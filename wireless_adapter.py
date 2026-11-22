#!/usr/bin/env python3
"""Read-only Linux wireless hardware and AP diagnostics.

This module never changes interface type, channel, power, or regulatory state.
It reports monitor-mode and AP/monitor concurrency only when iw reports enough
information to make that determination. Unknown is treated as unsupported for
automatic actions so an AP is never silently disrupted.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

SYS_NET = Path('/sys/class/net')
MAX_OUTPUT = 160_000


def _run(args: list[str], timeout: float = 4.0) -> tuple[int, str]:
    try:
        result = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, timeout=timeout, check=False,
            env={**os.environ, 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'},
        )
        return result.returncode, result.stdout[:MAX_OUTPUT]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def _read(path: Path) -> str | None:
    try:
        value = path.read_text(encoding='utf-8', errors='replace').strip()
        return value[:160] if value else None
    except OSError:
        return None


def _usb_parent(device: Path) -> Path | None:
    try:
        current = device.resolve(strict=True)
    except OSError:
        return None
    for parent in (current, *current.parents):
        if (parent / 'idVendor').is_file() and (parent / 'idProduct').is_file():
            return parent
    return None


def _interface_sysfs(name: str, root: Path = SYS_NET) -> dict[str, Any]:
    path = root / name
    result: dict[str, Any] = {'name': name, 'driver': None, 'phy': None,
                              'bus': 'unknown', 'usb_id': None, 'model': None}
    try:
        device = (path / 'device').resolve(strict=True)
    except OSError:
        device = None
    if device:
        driver_link = device / 'driver'
        try:
            result['driver'] = driver_link.resolve(strict=True).name
        except OSError:
            pass
        phy_link = path / 'phy80211'
        try:
            result['phy'] = phy_link.resolve(strict=True).name
        except OSError:
            pass
        usb = _usb_parent(device)
        if usb:
            vendor, product = _read(usb / 'idVendor'), _read(usb / 'idProduct')
            if vendor and product and re.fullmatch(r'[0-9a-fA-F]{4}', vendor) and re.fullmatch(r'[0-9a-fA-F]{4}', product):
                result['bus'] = 'USB'
                result['usb_id'] = f'{vendor.lower()}:{product.lower()}'
                manufacturer = _read(usb / 'manufacturer')
                product_name = _read(usb / 'product')
                result['model'] = ' '.join(x for x in (manufacturer, product_name) if x) or None
        elif 'platform' in str(device):
            result['bus'] = 'platform'
    return result


def _parse_modes(text: str) -> set[str]:
    match = re.search(r'Supported interface modes:\s*\n((?:\s+\*[^\n]*\n?)+)', text, re.I)
    if not match:
        return set()
    return {line.strip().lstrip('*').strip().lower() for line in match.group(1).splitlines() if line.strip()}


def _combo_ap_monitor(text: str) -> tuple[bool | None, bool | None, list[str]]:
    """Conservatively detect an AP+monitor combination from iw's combo lines."""
    lines = text.splitlines()
    combo_lines: list[str] = []
    in_combos = False
    for line in lines:
        if re.search(r'valid interface combinations:', line, re.I):
            in_combos = True
            continue
        if in_combos:
            if not line.strip():
                if combo_lines:
                    break
                continue
            if re.search(r'^[^\s]', line):
                break
            if '* #{' in line or combo_lines:
                combo_lines.append(line.strip())
    if not combo_lines:
        return None, None, []
    normalized = ' '.join(combo_lines)
    groups = re.findall(r'#\{([^}]+)\}\s*<=\s*(\d+)', normalized)
    total_match = re.search(r'total\s*<=\s*(\d+)', normalized)
    channel_match = re.search(r'#channels\s*<=\s*(\d+)', normalized)
    ap_capacity = 0
    monitor_capacity = 0
    separate_groups = False
    for group, maximum in groups:
        modes = {item.strip().lower() for item in group.split(',')}
        cap = int(maximum)
        if 'ap' in modes:
            ap_capacity += cap
        if 'monitor' in modes:
            monitor_capacity += cap
        if 'ap' in modes and 'monitor' not in modes:
            has_ap_group = True
        else:
            has_ap_group = False
        if 'monitor' in modes and 'ap' not in modes:
            has_monitor_group = True
        else:
            has_monitor_group = False
        if has_ap_group and monitor_capacity >= 0:
            separate_groups = True
        if has_monitor_group and ap_capacity >= 0:
            separate_groups = True
    total = int(total_match.group(1)) if total_match else 0
    possible = bool(ap_capacity and monitor_capacity and total >= 2 and separate_groups)
    channels = int(channel_match.group(1)) if channel_match else None
    return possible, (channels == 1 if channels is not None else None), combo_lines


def _parse_iface_blocks(text: str) -> list[dict[str, Any]]:
    radios: list[dict[str, Any]] = []
    current_phy: str | None = None
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.fullmatch(r'phy#(\d+)', line)
        if m:
            if current:
                radios.append(current)
                current = None
            current_phy = f'phy{m.group(1)}'
            continue
        if line.startswith('Interface '):
            if current:
                radios.append(current)
            current = {'phy': current_phy, 'interfaces': []}
            current['interfaces'].append(line.split(None, 1)[1])
            continue
        if current is not None:
            if line.startswith('type '):
                current['type'] = line.split(None, 1)[1]
            elif line.startswith('channel '):
                current['channel'] = line.split(None, 1)[1]
            elif line.startswith('addr '):
                current['mac'] = line.split(None, 1)[1].lower()
    if current:
        radios.append(current)
    merged: dict[str, dict[str, Any]] = {}
    for row in radios:
        phy = row.get('phy') or 'unknown'
        target = merged.setdefault(phy, {'phy': phy, 'interfaces': []})
        target['interfaces'].extend(row['interfaces'])
        for key in ('type', 'channel', 'mac'):
            if row.get(key):
                target[key] = row[key]
    return list(merged.values())


def _parse_station_dump(text: str) -> list[dict[str, Any]]:
    stations: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('Station '):
            if current:
                stations.append(current)
            match = re.match(r'Station\s+([0-9a-fA-F:]{17})', stripped)
            if not match:
                current = None
                continue
            current = {'mac': match.group(1).lower()}
        elif current and ':' in stripped:
            key, value = stripped.split(':', 1)
            key = key.strip().lower().replace(' ', '_')
            if key in {'inactive_time', 'signal', 'signal_avg', 'tx_bitrate', 'rx_bitrate',
                       'tx_packets', 'tx_retries', 'tx_failed', 'rx_packets', 'rx_bytes', 'tx_bytes'}:
                current[key] = value.strip()[:80]
    if current:
        stations.append(current)
    return stations[:128]


def _parse_survey(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('Survey data from '):
            if current:
                rows.append(current)
            current = {'interface': stripped.split()[-1]}
        elif current and stripped.startswith('frequency:'):
            current['frequency_mhz'] = stripped.split(':', 1)[1].strip()
        elif current and stripped.startswith('noise:'):
            current['noise_dbm'] = stripped.split(':', 1)[1].strip()
        elif current and stripped.startswith('channel busy time:'):
            current['busy_ms'] = stripped.split(':', 1)[1].strip()
        elif current and stripped.startswith('channel active time:'):
            current['active_ms'] = stripped.split(':', 1)[1].strip()
        elif current and stripped.startswith('channel transmit time:'):
            current['transmit_ms'] = stripped.split(':', 1)[1].strip()
        elif current and stripped.startswith('channel receive time:'):
            current['receive_ms'] = stripped.split(':', 1)[1].strip()
    if current:
        rows.append(current)
    return rows[:64]


def station_inventory(interfaces: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    """Read current associated stations without scanning or changing radio state."""
    if interfaces is None:
        import sbc_site
        interfaces = tuple(sbc_site.ap_interfaces(sbc_site.load()))
    iw = shutil.which('iw')
    if not iw:
        return []
    rows: list[dict[str, Any]] = []
    for interface in interfaces[:4]:
        rc, output = _run([iw, 'dev', interface, 'station', 'dump'], timeout=3.0)
        if rc != 0:
            continue
        for station in _parse_station_dump(output):
            rows.append({**station, 'radio': interface, 'associated': True,
                         'discovery_source': 'Wi-Fi station table'})
            if len(rows) >= 128:
                return rows
    return rows


def status() -> dict[str, Any]:
    iw = shutil.which('iw')
    if not iw:
        return {'ok': True, 'available': False, 'error': '`iw` is not installed; install the Debian package `iw` to inspect wireless capabilities.', 'adapters': []}
    rc, dev_text = _run([iw, 'dev'])
    if rc != 0:
        return {'ok': True, 'available': False, 'error': dev_text[:300], 'adapters': []}
    phy_rows = _parse_iface_blocks(dev_text)
    adapters = []
    for phy in phy_rows:
        phy_name = phy.get('phy') or 'unknown'
        phy_rc, phy_text = _run([iw, 'phy', phy_name, 'info'], timeout=5.0) if phy_name != 'unknown' else (1, '')
        supported_modes: list[str] = []
        combinations: list[str] = []
        bands: list[str] = []
        ap_monitor_concurrent, monitor_same_channel_only, _parsed_combinations = _combo_ap_monitor(phy_text) if phy_rc == 0 else (None, None, [])
        in_modes = in_combinations = in_bands = False
        for line in phy_text.splitlines():
            stripped = line.strip()
            if 'Supported interface modes:' in line:
                in_modes, in_combinations, in_bands = True, False, False
                continue
            if 'valid interface combinations:' in line:
                in_modes, in_combinations, in_bands = False, True, False
                continue
            if re.match(r'Band \d+:', stripped):
                in_modes, in_combinations, in_bands = False, False, True
                bands.append(stripped[:120])
                continue
            if in_modes:
                match = re.match(r'\*\s*(.+)', stripped)
                if match:
                    supported_modes.append(match.group(1)[:80])
                elif stripped and not stripped.startswith('*'):
                    in_modes = False
            if in_combinations and stripped:
                if len(combinations) < 12:
                    combinations.append(stripped[:240])
                if stripped.startswith('software interface modes'):
                    in_combinations = False
        for name in phy.get('interfaces', []):
            info = _interface_sysfs(name)
            _, iface_text = _run([iw, 'dev', name, 'info'])
            current = next((row for row in _parse_iface_blocks(dev_text) if name in row['interfaces']), {})
            _, station_text = _run([iw, 'dev', name, 'station', 'dump'], timeout=3.0)
            _, survey_text = _run([iw, 'dev', name, 'survey', 'dump'], timeout=3.0)
            stations = _parse_station_dump(station_text)
            survey = _parse_survey(survey_text)
            info.update({
                'name': name, 'phy': phy_name, 'type': current.get('type', 'unknown'),
                'channel': current.get('channel'), 'stations': stations,
                'survey': survey,
                'interface_info': iface_text[:4000],
                'monitor_mode_enabled': current.get('type') == 'monitor',
                'monitor_mode_supported': 'monitor' in [value.lower() for value in supported_modes],
                'ap_mode_supported': 'ap' in [value.lower() for value in supported_modes],
                'ap_monitor_concurrent': ap_monitor_concurrent,
                'monitor_same_channel_only': monitor_same_channel_only,
                'phy_capabilities': {
                    'supported_modes': supported_modes,
                    'interface_combinations': combinations,
                    'bands': bands[:8],
                    'monitor_mode_supported': 'monitor' in [value.lower() for value in supported_modes],
                    'ap_mode_supported': 'ap' in [value.lower() for value in supported_modes],
                    'ap_monitor_concurrent': ap_monitor_concurrent,
                    'monitor_same_channel_only': monitor_same_channel_only,
                    'phy_info_available': phy_rc == 0,
                },
                'capability_details': (_parsed_combinations or combinations)[:6],
                'monitor_mode_supported': 'monitor' in [value.lower() for value in supported_modes],
                'ap_mode_supported': 'ap' in [value.lower() for value in supported_modes],
                'ap_monitor_concurrent': ap_monitor_concurrent,
                'monitor_same_channel_only': monitor_same_channel_only,
            })
            adapters.append(info)
    return {'ok': True, 'available': True, 'adapters': adapters,
            'monitor_mode_note': 'Capability is reported only. No monitor interface or channel is activated; doing so can interrupt an AP.',
            'capture_note': 'AF_PACKET captures routed IP traffic on selected network interfaces. 802.11 management/control frames require radio monitor mode, which is reported but never enabled automatically.',
            'note': 'Read-only capability inspection. No monitor interface, channel, injection, or hostapd state was changed.'}

