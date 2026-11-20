#!/usr/bin/env python3
"""Low-overhead Linux telemetry from /proc and /sys (no packet payload capture)."""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any

SYS_CLASS_NET = Path('/sys/class/net')
SYS_THERMAL = Path('/sys/class/thermal')
SYS_HWMON = Path('/sys/class/hwmon')
SYS_CLASS_BLOCK = Path('/sys/class/block')
SYS_CPU = Path('/sys/devices/system/cpu')
SYS_DEVFREQ = Path('/sys/class/devfreq')
SYS_DRM = Path('/sys/class/drm')
PROC_ROOT = Path('/proc')
PROC_PRESSURE = Path('/proc/pressure')
DEVICE_TREE_MODEL = Path('/proc/device-tree/model')

_previous_cpu: dict[str, tuple[int, int]] = {}
_previous_net: dict[str, tuple[float, dict[str, int]]] = {}
_previous_disk: tuple[float, dict[str, tuple[int, int]]] | None = None


def _read_cpu_times() -> dict[str, tuple[int, int]]:
    values: dict[str, tuple[int, int]] = {}
    try:
        for line in Path('/proc/stat').read_text().splitlines():
            match = re.match(r'^(cpu\d*)\s+(.+)$', line)
            if not match:
                continue
            fields = [int(x) for x in match.group(2).split()[:10]]
            if len(fields) < 4:
                continue
            # guest and guest_nice are already included in user/nice by the kernel.
            # Excluding fields 8-9 prevents double-counting virtualized CPU time.
            total = sum(fields[:8])
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
            values[match.group(1)] = (total, idle)
    except (OSError, ValueError):
        pass
    return values


def _cpu_usage() -> dict[str, Any]:
    global _previous_cpu
    current = _read_cpu_times()
    result: dict[str, float | None] = {}
    for name, (total, idle) in current.items():
        previous = _previous_cpu.get(name)
        if previous is None:
            result[name] = None
            continue
        total_delta = total - previous[0]
        idle_delta = idle - previous[1]
        result[name] = round(max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta)), 1) if total_delta > 0 else 0.0
    _previous_cpu = current
    return {'percent': result.get('cpu'), 'cores': [{'core': name, 'percent': value} for name, value in result.items() if name != 'cpu']}


def _read_int(path: Path) -> int:
    try:
        return max(0, int(path.read_text().strip()))
    except (OSError, ValueError):
        return 0


def _temperature_sensors() -> list[dict[str, Any]]:
    sensors: list[dict[str, Any]] = []
    seen: set[tuple[str, float]] = set()
    for zone in sorted(SYS_THERMAL.glob('thermal_zone*')):
        raw = _read_int(zone / 'temp')
        if not raw:
            continue
        celsius = raw / 1000.0 if raw > 1000 else float(raw)
        if not -10 <= celsius <= 150:
            continue
        try:
            label = (zone / 'type').read_text().strip()[:48] or zone.name
        except OSError:
            label = zone.name
        item = (label, round(celsius, 1))
        if item not in seen:
            seen.add(item)
            sensors.append({'label': label, 'temperature_c': item[1], 'source': 'thermal'})
    # Merge hwmon even when thermal zones exist: some boards expose CPU and
    # GPU/PMIC sensors through different kernel interfaces. Deduplicate identical
    # label/value pairs where drivers publish the same physical sensor twice.
    for hwmon in sorted(SYS_HWMON.glob('hwmon*')):
        try:
            driver = (hwmon / 'name').read_text().strip()[:48]
        except OSError:
            driver = hwmon.name
        for input_path in sorted(hwmon.glob('temp*_input')):
            raw = _read_int(input_path)
            if not raw:
                continue
            celsius = raw / 1000.0 if raw > 1000 else float(raw)
            if not -10 <= celsius <= 150:
                continue
            suffix = input_path.name.removesuffix('_input')
            try:
                label = (hwmon / f'{suffix}_label').read_text().strip()[:48] or f'{driver} {suffix}'
            except OSError:
                label = f'{driver} {suffix}'
            item = (label, round(celsius, 1))
            if item not in seen:
                seen.add(item)
                sensors.append({'label': label, 'temperature_c': item[1], 'source': 'hwmon'})
    return sensors[:16]


def _net_counters() -> dict[str, dict[str, int]]:
    counters: dict[str, dict[str, int]] = {}
    fields = ('rx_bytes', 'rx_packets', 'rx_errors', 'rx_dropped', 'tx_bytes', 'tx_packets', 'tx_errors', 'tx_dropped')
    try:
        interfaces = sorted(SYS_CLASS_NET.iterdir(), key=lambda p: p.name)
    except OSError:
        return counters
    for iface in interfaces[:64]:
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', iface.name):
            continue
        stats = iface / 'statistics'
        row = {field: _read_int(stats / field) for field in fields}
        try:
            state = (iface / 'operstate').read_text().strip()[:16]
        except OSError:
            state = 'unknown'
        # Ignore loopback and common software-only devices in aggregate traffic,
        # while still reporting their per-interface counters in the table.
        include = not (iface.name == 'lo' or iface.name.startswith(('br', 'docker', 'veth', 'virbr', 'tun', 'tap', 'wg', 'tailscale')))
        counters[iface.name] = {**row, '_include_total': int(include), '_state_up': int(state == 'up')}
    return counters


def _network_rates(now: float) -> dict[str, Any]:
    global _previous_net
    current = _net_counters()
    result = []
    totals = {'rx_bytes_per_sec': 0.0, 'tx_bytes_per_sec': 0.0, 'rx_packets_per_sec': 0.0, 'tx_packets_per_sec': 0.0}
    next_previous: dict[str, tuple[float, dict[str, int]]] = {}
    for name, counts in current.items():
        previous = _previous_net.get(name)
        elapsed = max(0.001, now - previous[0]) if previous else 0.0
        old = previous[1] if previous else {}
        row: dict[str, Any] = {'name': name, 'state': 'up' if counts.pop('_state_up') else 'down'}
        include = bool(counts.pop('_include_total'))
        for field, rate_name in (
            ('rx_bytes', 'rx_bytes_per_sec'), ('tx_bytes', 'tx_bytes_per_sec'),
            ('rx_packets', 'rx_packets_per_sec'), ('tx_packets', 'tx_packets_per_sec'),
        ):
            delta = max(0, counts[field] - old.get(field, counts[field]))
            rate = round(delta / elapsed, 1) if elapsed else 0.0
            row[rate_name] = rate
            if include:
                totals[rate_name] += rate
        for field in ('rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets', 'rx_errors', 'tx_errors', 'rx_dropped', 'tx_dropped'):
            row[field] = counts[field]
        row['included_in_total'] = include
        result.append(row)
        next_previous[name] = (now, counts)
    _previous_net = next_previous
    return {
        'interfaces': result,
        'totals': {key: round(value, 1) for key, value in totals.items()},
    }


def _disk_io(now: float) -> dict[str, Any]:
    global _previous_disk
    current: dict[str, tuple[int, int]] = {}
    try:
        for line in Path('/proc/diskstats').read_text().splitlines():
            fields = line.split()
            if len(fields) < 14:
                continue
            name = fields[2]
            if name.startswith(('loop', 'ram', 'zram')) or not re.fullmatch(r'[A-Za-z0-9_.!-]{1,64}', name):
                continue
            # Partition counters duplicate whole-device totals; report whole devices only.
            if (SYS_CLASS_BLOCK / name / 'partition').exists():
                continue
            # Sectors read/written are 512-byte sectors (kernel diskstats ABI).
            current[name] = (int(fields[5]) * 512, int(fields[9]) * 512)
    except (OSError, ValueError):
        pass
    read_rate = write_rate = 0.0
    if _previous_disk:
        elapsed = max(0.001, now - _previous_disk[0])
        old = _previous_disk[1]
        read_rate = sum(max(0, v[0] - old.get(k, v)[0]) for k, v in current.items()) / elapsed
        write_rate = sum(max(0, v[1] - old.get(k, v)[1]) for k, v in current.items()) / elapsed
    _previous_disk = (now, current)
    return {'read_bytes_per_sec': round(read_rate, 1), 'write_bytes_per_sec': round(write_rate, 1), 'devices': len(current)}


def _memory() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            name, rest = line.split(':', 1)
            if name in {'MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'}:
                values[name] = int(rest.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    total = values.get('MemTotal', 0)
    available = values.get('MemAvailable', 0)
    swap_total = values.get('SwapTotal', 0)
    swap_free = values.get('SwapFree', 0)
    return {
        'total': total, 'used': max(0, total - available), 'available': available,
        'swap_total': swap_total, 'swap_used': max(0, swap_total - swap_free),
    }



def _cpu_frequency() -> dict[str, Any]:
    """Read available CPU frequency policy values; unsupported governors are omitted."""
    rows: list[dict[str, Any]] = []
    for cpu in sorted(SYS_CPU.glob('cpu[0-9]*')):
        if not re.fullmatch(r'cpu[0-9]+', cpu.name):
            continue
        policy = cpu / 'cpufreq'
        current = _read_int(policy / 'scaling_cur_freq') or _read_int(policy / 'cpuinfo_cur_freq')
        maximum = _read_int(policy / 'scaling_max_freq') or _read_int(policy / 'cpuinfo_max_freq')
        minimum = _read_int(policy / 'scaling_min_freq') or _read_int(policy / 'cpuinfo_min_freq')
        if current or maximum:
            rows.append({
                'cpu': cpu.name,
                'current_mhz': round(current / 1000, 1) if current else None,
                'min_mhz': round(minimum / 1000, 1) if minimum else None,
                'max_mhz': round(maximum / 1000, 1) if maximum else None,
            })
    values = [row['current_mhz'] for row in rows if row['current_mhz'] is not None]
    return {'average_mhz': round(sum(values) / len(values), 1) if values else None, 'cpus': rows[:256]}


def _accelerator_metrics() -> list[dict[str, Any]]:
    """Best-effort GPU/devfreq utilization. Kernel interfaces vary by SoC and driver."""
    found: dict[str, dict[str, Any]] = {}
    try:
        devices = sorted(SYS_DEVFREQ.iterdir())
    except OSError:
        devices = []
    for device in devices[:64]:
        try:
            name = (device / 'name').read_text().strip()[:64] or device.name
        except OSError:
            name = device.name
        lower = f'{device.name} {name}'.lower()
        # devfreq also exposes CPU interconnects and memory controllers; only
        # report accelerators with an identifiable GPU/NPU/video/DSP name.
        if not re.search(r'(gpu|npu|vpu|mali|panfrost|adreno|vivante|rga|g2d|dsp|accelerator)', lower):
            continue
        current = _read_int(device / 'cur_freq')
        maximum = _read_int(device / 'max_freq')
        load = _read_int(device / 'load')
        utilization = load if 0 <= load <= 100 else None
        found[name] = {
            'name': name,
            'current_mhz': round(current / 1_000_000, 1) if current else None,
            'max_mhz': round(maximum / 1_000_000, 1) if maximum else None,
            'utilization_percent': utilization,
            'source': 'devfreq',
        }
    for busy_path in sorted(SYS_DRM.glob('card*/device/gpu_busy_percent')):
        value = _read_int(busy_path)
        if value <= 100:
            name = busy_path.parents[1].name + ' GPU'
            row = found.setdefault(name, {'name': name, 'current_mhz': None, 'max_mhz': None, 'source': 'drm'})
            row['utilization_percent'] = value
            row['source'] = 'drm'
    return list(found.values())[:16]


def _pressure() -> dict[str, Any]:
    """Parse Linux PSI pressure stall information when the kernel exposes it."""
    result: dict[str, Any] = {}
    for resource in ('cpu', 'memory', 'io'):
        rows: dict[str, dict[str, float | int]] = {}
        try:
            lines = (PROC_PRESSURE / resource).read_text().splitlines()
        except OSError:
            continue
        for line in lines[:2]:
            bits = line.split()
            if not bits or bits[0] not in {'some', 'full'}:
                continue
            values: dict[str, float | int] = {}
            for part in bits[1:]:
                if '=' not in part:
                    continue
                key, raw = part.split('=', 1)
                if key not in {'avg10', 'avg60', 'avg300', 'total'}:
                    continue
                try:
                    values[key] = int(raw) if key == 'total' else float(raw)
                except ValueError:
                    continue
            rows[bits[0]] = values
        if rows:
            result[resource] = rows
    return result


def _device_model() -> str | None:
    try:
        value = DEVICE_TREE_MODEL.read_bytes().replace(b'\x00', b' ').decode('utf-8', 'replace').strip()
        return value[:160] or None
    except OSError:
        return None


def _process_count() -> int | None:
    try:
        return sum(1 for item in PROC_ROOT.iterdir() if item.name.isdigit())
    except OSError:
        return None


def snapshot() -> dict[str, Any]:
    """Return a single sample. Call repeatedly (1–2s) to calculate rates."""
    now = time.monotonic()
    cpu = _cpu_usage()
    network = _network_rates(now)
    temperatures = _temperature_sensors()
    load: list[float] = []
    try:
        load = [round(float(x), 2) for x in Path('/proc/loadavg').read_text().split()[:3]]
    except (OSError, ValueError):
        pass
    temp = max((item['temperature_c'] for item in temperatures), default=None)
    try:
        uptime = max(0.0, float((PROC_ROOT / 'uptime').read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        uptime = None
    return {
        'timestamp': time.time(), 'uptime_seconds': round(uptime, 1) if uptime is not None else None,
        'device_model': _device_model(), 'process_count': _process_count(),
        'cpu': cpu, 'cpu_frequency': _cpu_frequency(), 'accelerators': _accelerator_metrics(),
        'memory': _memory(), 'pressure': _pressure(),
        'temperature_c': temp, 'temperatures': temperatures,
        'network': network, 'disk_io': _disk_io(now), 'load': load,
    }


def reset_for_tests() -> None:
    global _previous_cpu, _previous_net, _previous_disk
    _previous_cpu = {}
    _previous_net = {}
    _previous_disk = None
