#!/usr/bin/env python3
"""Server-owned, timestamped Linux telemetry sampler."""
from __future__ import annotations

import collections
import copy
import datetime as dt
import threading
import time
from pathlib import Path
from typing import Any, Callable

NETWORK_FIELDS = (
    'rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets',
    'rx_errors', 'tx_errors', 'rx_dropped', 'tx_dropped',
)
EXCLUDED_PREFIXES = (
    'lo', 'br', 'docker', 'veth', 'virbr', 'tun', 'tap', 'wg',
    'tailscale', 'zt', 'ifb', 'dummy',
)


def read_network_counters(sys_class_net: Path = Path('/sys/class/net')) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    try:
        interfaces = sorted(sys_class_net.iterdir(), key=lambda item: item.name)[:64]
    except OSError:
        return result
    for iface in interfaces:
        name = iface.name
        if not name or len(name) > 32 or any(ch not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-' for ch in name):
            continue
        values: dict[str, int] = {}
        for field in NETWORK_FIELDS:
            try:
                number = int((iface / 'statistics' / field).read_text(encoding='ascii').strip())
                if number < 0:
                    raise ValueError('negative counter')
                values[field] = number
            except (OSError, ValueError):
                values = {}
                break
        if not values:
            continue
        try:
            state = (iface / 'operstate').read_text(encoding='ascii').strip()[:16]
        except OSError:
            state = 'unknown'
        virtual = name == 'lo' or name.startswith(EXCLUDED_PREFIXES[1:])
        try:
            ifindex = int((iface / 'ifindex').read_text(encoding='ascii').strip())
            iflink = int((iface / 'iflink').read_text(encoding='ascii').strip())
        except (OSError, ValueError):
            ifindex = iflink = -1
        has_device = (iface / 'device').exists()
        has_master = (iface / 'master').exists()
        # A physical total excludes loopback, virtual devices, stacked VLANs,
        # bridges/bonds, tunnel links and lower devices enslaved to a master.
        physical = bool(has_device and ifindex > 0 and iflink == ifindex and not has_master and not virtual)
        result[name] = {
            **values, 'state': state, 'ifindex': ifindex, 'iflink': iflink,
            'has_device': has_device, 'has_master': has_master,
            'included_in_physical_total': physical,
            'source': 'linux-sysfs-interface-statistics',
        }
    return result


def _utc_iso(epoch_ns: int) -> str:
    value = dt.datetime.fromtimestamp(epoch_ns / 1_000_000_000, tz=dt.timezone.utc)
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


class RealtimeSampler:
    """One non-overlapping sampler with a bounded, sequence-addressable ring."""

    def __init__(
        self, snapshot_fn: Callable[[], dict[str, Any]],
        counter_reader: Callable[[], dict[str, dict[str, Any]]] = read_network_counters,
        *, interval_seconds: float = 1.0, capacity: int = 900,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        time_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if not 0.25 <= interval_seconds <= 10:
            raise ValueError('Sampling interval must be between 0.25 and 10 seconds.')
        if not 60 <= capacity <= 3600:
            raise ValueError('Sample ring capacity must be between 60 and 3600.')
        self._snapshot_fn, self._counter_reader = snapshot_fn, counter_reader
        self.interval_seconds, self._capacity = float(interval_seconds), int(capacity)
        self._monotonic_ns, self._time_ns = monotonic_ns, time_ns
        self._lock = threading.RLock()
        self._samples: collections.deque[dict[str, Any]] = collections.deque(maxlen=self._capacity)
        self._previous_rows: dict[str, dict[str, Any]] = {}
        self._previous_counter_mono_ns: int | None = None
        self._sequence = self._overwritten = self._missed_deadlines = 0
        self._last_error: str | None = None
        self._last_completed_mono_ns: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False

    def _network_sample(self, counters: dict[str, dict[str, Any]], mono_ns: int, epoch_ns: int) -> dict[str, Any]:
        previous_ns = self._previous_counter_mono_ns
        elapsed = (mono_ns - previous_ns) / 1_000_000_000 if previous_ns is not None else None
        interfaces: list[dict[str, Any]] = []
        totals: dict[str, Any] = {
            'rx_delta_bytes': 0, 'tx_delta_bytes': 0, 'rx_delta_packets': 0, 'tx_delta_packets': 0,
            'rx_bytes_per_second': 0.0, 'tx_bytes_per_second': 0.0,
            'rx_packets_per_second': 0.0, 'tx_packets_per_second': 0.0,
        }
        aggregate_valid = True
        current_physical: set[str] = set()
        for name, row in counters.items():
            previous = self._previous_rows.get(name)
            resets = [field for field in NETWORK_FIELDS if previous is not None and row[field] < previous.get(field, row[field])]
            valid = previous is not None and elapsed is not None and elapsed > 0 and not resets
            item: dict[str, Any] = {
                'name': name, 'state': row['state'], 'source': row['source'],
                'included_in_total': bool(row['included_in_physical_total']),
                'sample_valid': bool(valid), 'counter_reset': bool(resets), 'reset_fields': resets,
                'interval_seconds': elapsed if valid else None,
                'timestamp': _utc_iso(epoch_ns), 'timestamp_unix_ns': epoch_ns, 'monotonic_ns': mono_ns,
            }
            for field in NETWORK_FIELDS:
                item[field] = row[field]
            for raw, delta_key, rate_key in (
                ('rx_bytes', 'rx_delta_bytes', 'rx_bytes_per_second'),
                ('tx_bytes', 'tx_delta_bytes', 'tx_bytes_per_second'),
                ('rx_packets', 'rx_delta_packets', 'rx_packets_per_second'),
                ('tx_packets', 'tx_delta_packets', 'tx_packets_per_second'),
            ):
                delta = row[raw] - previous[raw] if valid and previous else None
                item[delta_key] = delta
                item[rate_key] = delta / elapsed if delta is not None and elapsed else None
                if row['included_in_physical_total']:
                    current_physical.add(name)
                    if delta is None:
                        aggregate_valid = False
                    else:
                        totals[delta_key] += delta
                        totals[rate_key] += delta / elapsed
            interfaces.append(item)
        # Counter reset or first sample: report unavailable, never manufacture zero traffic.
        if not interfaces or any(row['included_in_total'] and not row['sample_valid'] for row in interfaces):
            aggregate_valid = False
        self._previous_rows = copy.deepcopy(counters)
        self._previous_counter_mono_ns = mono_ns
        if not aggregate_valid:
            for key in ('rx_delta_bytes', 'tx_delta_bytes', 'rx_delta_packets', 'tx_delta_packets',
                        'rx_bytes_per_second', 'tx_bytes_per_second', 'rx_packets_per_second', 'tx_packets_per_second'):
                totals[key] = None
        return {
            'timestamp': _utc_iso(epoch_ns), 'timestamp_unix_ns': epoch_ns, 'monotonic_ns': mono_ns,
            'interval_seconds': elapsed, 'interfaces': interfaces, 'totals': totals,
            'aggregate_valid': aggregate_valid,
            'aggregate_scope': 'physical interfaces; excludes loopback and common virtual/tunnel interfaces',
            'counter_source': 'Linux /sys/class/net/*/statistics',
        }

    def collect_once(self) -> dict[str, Any]:
        start_mono, start_epoch = self._monotonic_ns(), self._time_ns()
        counters = self._counter_reader()
        network_mono, network_epoch = self._monotonic_ns(), self._time_ns()
        metrics = self._snapshot_fn()
        end_mono, end_epoch = self._monotonic_ns(), self._time_ns()
        with self._lock:
            self._sequence += 1
            if len(self._samples) == self._capacity:
                self._overwritten += 1
            sample = {
                **metrics, 'sequence': self._sequence, 'timestamp': _utc_iso(end_epoch),
                'timestamp_unix_ns': end_epoch, 'monotonic_ns': end_mono,
                'interval_seconds': (end_mono - self._last_completed_mono_ns) / 1e9 if self._last_completed_mono_ns else None,
                'collection_duration_ms': max(0, end_mono - start_mono) / 1e6,
                'network': self._network_sample(counters, network_mono, network_epoch),
                'sample_state': 'valid',
            }
            self._samples.append(sample)
            self._last_completed_mono_ns = end_mono
            self._last_error = None
            return copy.deepcopy(sample)

    def _run(self) -> None:
        period = int(self.interval_seconds * 1e9)
        deadline = self._monotonic_ns()
        while not self._stop.is_set():
            try:
                self.collect_once()
            except Exception as exc:
                with self._lock:
                    self._last_error = f'{type(exc).__name__}: {exc}'[:240]
            deadline += period
            now = self._monotonic_ns()
            if now > deadline:
                missed = (now - deadline) // period + 1
                with self._lock:
                    self._missed_deadlines += int(missed)
                deadline += missed * period
            self._stop.wait(max(0.0, (deadline - self._monotonic_ns()) / 1e9))
        with self._lock:
            self._running = False

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._stop.clear()
            self._running = True
            self._thread = threading.Thread(target=self._run, name='sbc-telemetry-sampler', daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def read(self, after_sequence: int = 0, limit: int | None = None) -> dict[str, Any]:
        if isinstance(after_sequence, bool) or not isinstance(after_sequence, int) or after_sequence < 0:
            raise ValueError('Invalid telemetry cursor.')
        limit = self._capacity if limit is None else limit
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= self._capacity:
            raise ValueError('Invalid telemetry history limit.')
        with self._lock:
            rows = [copy.deepcopy(row) for row in self._samples if row['sequence'] > after_sequence][-limit:]
            latest = copy.deepcopy(self._samples[-1]) if self._samples else None
            age_ms = ((self._monotonic_ns() - self._last_completed_mono_ns) / 1e6) if self._last_completed_mono_ns else None
            return {
                'latest': latest, 'samples': rows, 'cursor': latest['sequence'] if latest else 0,
                'history_capacity': self._capacity, 'history_size': len(self._samples),
                'overwritten_samples': self._overwritten, 'missed_deadlines': self._missed_deadlines,
                'sampler_running': self._running, 'sample_age_ms': age_ms,
                'sample_interval_seconds': self.interval_seconds, 'last_error': self._last_error,
            }

    def reset_for_tests(self) -> None:
        self.stop()
        with self._lock:
            self._samples.clear()
            self._previous_rows.clear()
            self._previous_counter_mono_ns = None
            self._sequence = self._overwritten = self._missed_deadlines = 0
            self._last_error = None
            self._last_completed_mono_ns = None
            self._running = False


__all__ = ['RealtimeSampler', 'read_network_counters']
