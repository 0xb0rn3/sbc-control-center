#!/usr/bin/env python3
"""Bounded third-party discovery helpers for the board's own Wi-Fi LANs.

Continuous identification is supplied by hostapd/iw, DHCP, neighbour state,
passive packet observations and optional arpwatch. Active arp-scan and Nmap
probes are explicit, scoped operations; no arbitrary target or interface is
accepted from a caller.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any

import device_intelligence
import sbc_site


_SITE = sbc_site.load()
APPROVED_NETWORKS: dict[str, str] = {
    _SITE['ap2_interface']: _SITE['ap2_subnet'],
    _SITE['ap_interface']: _SITE['ap_subnet'],
}
NETWORK_LABELS = {
    _SITE['ap2_interface']: f"{_SITE['ap2_ssid']} · {_SITE['ap2_label']}",
    _SITE['ap_interface']: f"{_SITE['ap_ssid']} · {_SITE['ap_label']}",
}
AP_GATEWAYS = {_SITE['ap2_interface']: _SITE['ap2_ip'], _SITE['ap_interface']: _SITE['ap_ip']}
CACHE_TTL_SECONDS = 300
MAX_SCAN_RESULTS = 512
MAX_SCAN_OUTPUT = 128 * 1024
P0F_LOG_DIR = sbc_site.P0F_LOG_DIR
P0F_MAX_LOG_BYTES = 256 * 1024
TOOL_SPECS = {
    'arpwatch': {
        'package': 'arpwatch', 'purpose': 'Continuous passive MAC/IP change detection',
        'mode': 'passive/event-driven',
    },
    'arp-scan': {
        'package': 'arp-scan', 'purpose': 'Scoped local ARP host discovery',
        'mode': 'active/on-demand',
    },
    'nmap': {
        'package': 'nmap', 'purpose': 'On-demand device OS and service fingerprinting',
        'mode': 'active/on-demand',
    },
    'p0f': {
        'package': 'p0f', 'purpose': 'Passive TCP/IP operating-system fingerprinting from normal traffic',
        'mode': 'passive/continuous',
    },
    'avahi-browse': {
        'package': 'avahi-utils', 'purpose': 'Optional mDNS/DNS-SD service discovery',
        'mode': 'passive/service browse',
    },
}

_cache_lock = threading.RLock()
_scan_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def _binary(name: str) -> str | None:
    candidate = shutil.which(name, path='/usr/sbin:/usr/bin:/sbin:/bin')
    if candidate:
        return candidate
    for path in (f'/usr/sbin/{name}', f'/usr/bin/{name}', f'/sbin/{name}', f'/bin/{name}'):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def tool_inventory() -> dict[str, Any]:
    """Return tool availability only; never executes discovery during polling."""
    tools: list[dict[str, Any]] = []
    for name, spec in TOOL_SPECS.items():
        path = _binary(name)
        tools.append({
            'name': name,
            'package': spec['package'],
            'purpose': spec['purpose'],
            'mode': spec['mode'],
            'installed': bool(path),
            'path': path,
        })
    arpwatch_template_present = os.path.exists(f'/etc/systemd/system/{sbc_site.ARPWATCH_UNIT}@.service')
    p0f_template_present = os.path.exists(f'/etc/systemd/system/{sbc_site.P0F_UNIT}@.service')
    arpwatch_units = {iface: arpwatch_template_present for iface in APPROVED_NETWORKS}
    p0f_units = {iface: p0f_template_present for iface in APPROVED_NETWORKS}
    watcher_active: dict[str, bool] = {}
    p0f_active: dict[str, bool] = {}
    systemctl = _binary('systemctl')
    if systemctl:
        for iface in APPROVED_NETWORKS:
            for prefix, state in ((sbc_site.ARPWATCH_UNIT, watcher_active), (sbc_site.P0F_UNIT, p0f_active)):
                try:
                    check = subprocess.run([systemctl, 'is-active', '--quiet', f'{prefix}@{iface}.service'],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           timeout=1.5, check=False, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
                    state[iface] = check.returncode == 0
                except (OSError, subprocess.TimeoutExpired):
                    state[iface] = False
    with _cache_lock:
        scans = {iface: int(max(0, time.monotonic() - entry[0]))
                 for iface, entry in _scan_cache.items()}
    return {
        'tools': tools,
        'arpwatch_template_installed': arpwatch_template_present,
        'p0f_template_installed': p0f_template_present,
        'arpwatch_units_installed': arpwatch_units,
        'p0f_units_installed': p0f_units,
        'arpwatch_units_active': watcher_active,
        'p0f_units_active': p0f_active,
        'active_scan_cache_age_seconds': scans,
        'identity_policy': (
            'MAC vendor identifies the IEEE address-block assignee, not guaranteed '
            'finished-device manufacturer. Private/randomized MACs are not vendor-attributed.'
        ),
        'scan_policy': 'Only the two configured AP subnets are eligible for active ARP discovery.',
    }


def validate_scan_interfaces(interfaces: Any) -> list[str] | None:
    if not isinstance(interfaces, list) or not interfaces or len(interfaces) > len(APPROVED_NETWORKS):
        return None
    if any(not isinstance(item, str) or item not in APPROVED_NETWORKS for item in interfaces):
        return None
    if len(set(interfaces)) != len(interfaces):
        return None
    return sorted(interfaces)


def fingerprint_scope(address: Any) -> dict[str, str] | None:
    if not isinstance(address, str):
        return None
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if not isinstance(ip, ipaddress.IPv4Address):
        return None
    for interface, subnet in APPROVED_NETWORKS.items():
        network = ipaddress.ip_network(subnet)
        gateway = ipaddress.ip_address(AP_GATEWAYS[interface])
        if ip in network and ip not in {network.network_address, network.broadcast_address, gateway}:
            return {'ip': str(ip), 'interface': interface}
    return None


def _validate_interface(interface: str) -> ipaddress.IPv4Network:
    if interface not in APPROVED_NETWORKS:
        raise ValueError('Active discovery is restricted to the configured Wi-Fi AP interfaces.')
    network = ipaddress.ip_network(APPROVED_NETWORKS[interface], strict=True)
    return network  # type: ignore[return-value]


def _run(args: list[str], timeout: float, max_output: int = MAX_SCAN_OUTPUT) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace',
            timeout=timeout, check=False,
            env={**os.environ, 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                 'LC_ALL': 'C', 'LANG': 'C'},
        )
        output = completed.stdout or ''
        if len(output.encode('utf-8', errors='replace')) > max_output:
            raise RuntimeError('Discovery tool output exceeded the safety limit.')
        return completed.returncode, output
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'{args[0]} timed out after {timeout:g} seconds.') from exc
    except FileNotFoundError as exc:
        raise RuntimeError(f'Required tool is not installed: {args[0]}') from exc


def _parse_arp_scan(output: str, interface: str) -> list[dict[str, Any]]:
    network = _validate_interface(interface)
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in output.splitlines()[:MAX_SCAN_RESULTS * 3]:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        try:
            address = ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        if not isinstance(address, ipaddress.IPv4Address) or address not in network:
            continue
        mac = device_intelligence.normalize_mac(parts[1])
        if not mac or device_intelligence.mac_properties(mac).get('multicast'):
            continue
        key = (str(address), mac)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            'ip': str(address), 'mac': mac, 'associated': False,
            'radio': interface, 'network_label': NETWORK_LABELS[interface],
            'discovery_source': 'arp-scan active ARP discovery',
            'discovery_tool': 'arp-scan',
        })
        if len(results) >= MAX_SCAN_RESULTS:
            break
    return results


def scan_interface(interface: str, *, timeout: float = 12.0) -> dict[str, Any]:
    """Perform a single low-rate ARP sweep of one fixed AP's directly attached LAN."""
    if os.geteuid() != 0:
        raise PermissionError(f'Run with sudo: sudo {sbc_site.PREFIX}-admin devices scan')
    network = _validate_interface(interface)
    binary = _binary('arp-scan')
    if not binary:
        raise RuntimeError('arp-scan is not installed. Run: sudo apt-get install arp-scan')
    # --localnet derives the target range from the named interface. This module
    # separately verifies the expected interface/subnet pair before execution.
    command = [
        binary, '--interface', interface, '--localnet', '--retry=1',
        '--timeout=350', '--bandwidth=128000', '--quiet', '--plain',
    ]
    started = time.monotonic()
    returncode, output = _run(command, timeout=timeout)
    if returncode != 0:
        raise RuntimeError(f'arp-scan failed on {interface}: {output.strip()[:500]}')
    rows = _parse_arp_scan(output, interface)
    elapsed = time.monotonic() - started
    now = time.monotonic()
    with _cache_lock:
        _scan_cache[interface] = (now, rows)
    database = device_intelligence.load_vendor_database()
    enriched = [device_intelligence.enrich_client(row, database=database) for row in rows]
    return {
        'ok': True, 'interface': interface, 'subnet': str(network),
        'network_label': NETWORK_LABELS[interface], 'tool': 'arp-scan',
        'devices_found': len(enriched), 'devices': enriched,
        'duration_seconds': round(elapsed, 3),
        'note': 'Active ARP discovery is limited to this directly attached AP subnet. Sleeping devices may not respond.',
    }


def scan_configured_networks(interfaces: list[str] | None = None) -> dict[str, Any]:
    if interfaces is None:
        interfaces = list(APPROVED_NETWORKS)
    valid = validate_scan_interfaces(interfaces)
    if valid is None:
        raise ValueError('Active discovery is restricted to one or both configured AP interfaces.')
    interfaces = valid
    started = time.monotonic()
    networks = [scan_interface(interface) for interface in interfaces]
    merged: dict[str, dict[str, Any]] = {}
    for network in networks:
        for device in network['devices']:
            key = device.get('mac') or f"ip:{device.get('ip')}"
            merged.setdefault(key, {}).update(device)
    return {
        'ok': True, 'networks': networks, 'devices': list(merged.values()),
        'devices_found': len(merged),
        'duration_seconds': round(time.monotonic() - started, 3),
        'message': f"Local discovery finished: {len(merged)} unique device(s) found across {len(networks)} AP network(s).",
    }


def cached_scan_results(interface: str) -> list[dict[str, Any]]:
    _validate_interface(interface)
    with _cache_lock:
        cached = _scan_cache.get(interface)
        if not cached:
            return []
        age, rows = cached
        if time.monotonic() - age > CACHE_TTL_SECONDS:
            _scan_cache.pop(interface, None)
            return []
        return [dict(row) for row in rows]


def fingerprint_device(address: str) -> dict[str, Any]:
    """Run a single-host Nmap OS fingerprint only for a device on an AP LAN."""
    if os.geteuid() != 0:
        raise PermissionError(f'Run with sudo: sudo {sbc_site.PREFIX}-admin devices fingerprint IP')
    scope = fingerprint_scope(address)
    if not scope:
        raise ValueError('Nmap fingerprinting is restricted to IPv4 devices on the two configured Wi-Fi subnets.')
    ip = ipaddress.ip_address(scope['ip'])
    iface = scope['interface']
    binary = _binary('nmap')
    if not binary:
        raise RuntimeError('nmap is not installed. Run: sudo apt-get install nmap')
    command = [
        binary, '-n', '-O', '--osscan-limit', '--max-retries', '1',
        '--host-timeout', '15s', '-T2', '-e', iface, '-oX', '-', str(ip),
    ]
    returncode, output = _run(command, timeout=20.0, max_output=64 * 1024)
    if returncode not in (0, 1):
        raise RuntimeError(f'Nmap fingerprint failed: {output.strip()[:500]}')
    try:
        root = ET.fromstring(output)
    except ET.ParseError as exc:
        raise RuntimeError('Nmap returned invalid XML; no fingerprint was accepted.') from exc
    host = root.find('host')
    if host is None or host.find('status') is None or host.find('status').get('state') != 'up':
        return {'ok': True, 'ip': str(ip), 'interface': iface, 'identified': False,
                'matches': [], 'note': 'Host did not respond to Nmap OS fingerprint probes.'}
    matches: list[dict[str, Any]] = []
    os_node = host.find('os')
    if os_node is not None:
        for match in os_node.findall('osmatch')[:5]:
            accuracy = match.get('accuracy', '0')
            try:
                accuracy_value = max(0, min(100, int(accuracy)))
            except ValueError:
                accuracy_value = 0
            classes = []
            for cls in match.findall('osclass')[:4]:
                classes.append({
                    'vendor': cls.get('vendor'), 'os_family': cls.get('osfamily'),
                    'os_generation': cls.get('osgen'), 'device_type': cls.get('type'),
                })
            matches.append({'name': match.get('name', 'Unspecified'),
                            'accuracy_percent': accuracy_value, 'classes': classes})
    address_node = host.find("address[@addrtype='mac']")
    mac = device_intelligence.normalize_mac(address_node.get('addr')) if address_node is not None else None
    return {
        'ok': True, 'ip': str(ip), 'interface': iface, 'mac': mac,
        'identified': bool(matches), 'matches': matches,
        'tool': 'nmap',
        'note': 'Active OS fingerprint estimate, not a definitive identity. Firewalls, proxies, unusual TCP stacks and limited open/closed-port evidence can reduce accuracy.',
    }


def _parse_p0f_record(line: str, interface: str) -> dict[str, Any] | None:
    """Parse one p0f grep-friendly record without treating it as definitive identity."""
    match = re.match(r'^\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\]\s*(.*)$', line.strip())
    if not match:
        return None
    fields: dict[str, str] = {}
    for field in match.group(2).split('|'):
        if '=' in field:
            key, value = field.split('=', 1)
            if re.fullmatch(r'[a-z][a-z0-9_]{0,31}', key):
                fields[key] = value[:240]
    os_name = fields.get('os') or fields.get('os_name')
    if not os_name:
        return None
    # On the AP ingress interfaces, p0f's client endpoint is the device initiating
    # the connection. Never attribute a remote server's fingerprint to a LAN client.
    if fields.get('subj', 'cli') != 'cli':
        return None
    endpoint = fields.get('cli', '')
    address_text = endpoint.rsplit('/', 1)[0]
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address):
        return None
    network = ipaddress.ip_network(APPROVED_NETWORKS[interface])
    if address not in network or address.is_unspecified or address.is_multicast:
        return None
    try:
        observed = datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S').timestamp()
    except ValueError:
        observed = 0.0
    module = fields.get('mod', 'tcp')[:24]
    return {
        'ip': str(address), 'os': os_name[:120], 'interface': interface,
        'module': module, 'timestamp': int(observed),
        'confidence': 'medium', 'source': 'p0f passive TCP/IP fingerprint',
    }


def passive_os_fingerprints(log_paths: dict[str, Path] | None = None) -> dict[str, dict[str, Any]]:
    """Read bounded local p0f logs and return the newest OS evidence per AP client IP."""
    paths = log_paths or {iface: P0F_LOG_DIR / f'{iface}.log' for iface in APPROVED_NETWORKS}
    found: dict[str, dict[str, Any]] = {}
    for interface, path in paths.items():
        if interface not in APPROVED_NETWORKS:
            continue
        fd = -1
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                os.close(fd)
                continue
            with os.fdopen(fd, 'rb', closefd=True) as stream:
                fd = -1
                stream.seek(max(0, info.st_size - P0F_MAX_LOG_BYTES), os.SEEK_SET)
                content = stream.read(P0F_MAX_LOG_BYTES).decode('utf-8', errors='replace')
        except OSError:
            continue
        finally:
            if fd >= 0:
                os.close(fd)
        for line in content.splitlines()[-1000:]:
            item = _parse_p0f_record(line, interface)
            if item:
                previous = found.get(item['ip'])
                if not previous or item['timestamp'] >= previous.get('timestamp', 0):
                    found[item['ip']] = item
    return found


def recent_arpwatch_events(limit: int = 20) -> dict[str, Any]:
    """Read recent passive ARP-watch and p0f identity events from local state."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        raise ValueError('Event limit must be between 1 and 50.')
    journalctl = _binary('journalctl')
    events: list[dict[str, Any]] = []
    available = False
    if journalctl:
        units = [f'{sbc_site.ARPWATCH_UNIT}@{iface}.service' for iface in APPROVED_NETWORKS]
        command = [journalctl, '--no-pager', '--since=-24h', '-n', str(limit), '-o', 'json']
        for unit in units:
            command.extend(['-u', unit])
        code, output = _run(command, timeout=3.0, max_output=64 * 1024)
        if code == 0:
            available = True
            import json
            for line in output.splitlines()[-limit:]:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                message = row.get('MESSAGE')
                if isinstance(message, str) and message:
                    events.append({
                        'timestamp': row.get('__REALTIME_TIMESTAMP'),
                        'unit': str(row.get('_SYSTEMD_UNIT', ''))[:120],
                        'message': message[:400], 'source': 'arpwatch',
                    })
    fingerprints = passive_os_fingerprints()
    for item in sorted(fingerprints.values(), key=lambda row: row.get('timestamp', 0), reverse=True)[:limit]:
        events.append({
            'timestamp': int(item['timestamp'] * 1_000_000) if item.get('timestamp') else None,
            'unit': f"{sbc_site.P0F_UNIT}@{item['interface']}.service",
            'message': f"Passive TCP/IP fingerprint for {item['ip']}: {item['os']} ({item['module']})",
            'source': 'p0f', 'ip': item['ip'], 'os': item['os'],
        })
    events.sort(key=lambda row: int(row.get('timestamp') or 0), reverse=True)
    return {'ok': True, 'available': available or bool(fingerprints), 'events': events[:limit]}
