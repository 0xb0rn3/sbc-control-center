#!/usr/bin/env python3
"""Bounded per-flow byte-rate sampling using measured monotonic intervals."""
from __future__ import annotations

import collections
import datetime as dt
import hashlib
import re
import threading
import time
from typing import Any, Callable

FLOW_ID_RE = re.compile(r"^[0-9a-f]{24}$")
DEFAULT_MAX_FLOWS = 2048
DEFAULT_SERIES_FLOWS = 64
DEFAULT_SAMPLES_PER_FLOW = 60
DEFAULT_IDLE_SECONDS = 60.0


def _utc_iso(epoch_ns: int) -> str:
    value = dt.datetime.fromtimestamp(epoch_ns / 1_000_000_000, tz=dt.timezone.utc)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class FlowRateTracker:
    """Track flow counters and emit timestamped interval rates.

    Packet arrival updates counters only. A dedicated caller invokes
    sample_once() on a target one-second cadence. Every rate divides the byte
    or packet delta by the actual monotonic elapsed interval, not the target
    cadence or browser polling interval.
    """

    def __init__(
        self,
        *,
        max_flows: int = DEFAULT_MAX_FLOWS,
        max_series_flows: int = DEFAULT_SERIES_FLOWS,
        samples_per_flow: int = DEFAULT_SAMPLES_PER_FLOW,
        idle_seconds: float = DEFAULT_IDLE_SECONDS,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        time_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if isinstance(max_flows, bool) or not isinstance(max_flows, int) or not 1 <= max_flows <= 8192:
            raise ValueError("max_flows must be between 1 and 8192.")
        if isinstance(max_series_flows, bool) or not isinstance(max_series_flows, int) or not 1 <= max_series_flows <= 256:
            raise ValueError("max_series_flows must be between 1 and 256.")
        if isinstance(samples_per_flow, bool) or not isinstance(samples_per_flow, int) or not 2 <= samples_per_flow <= 900:
            raise ValueError("samples_per_flow must be between 2 and 900.")
        if not 1.0 <= float(idle_seconds) <= 3600.0:
            raise ValueError("idle_seconds must be between 1 and 3600.")
        self.max_flows = max_flows
        self.max_series_flows = max_series_flows
        self.samples_per_flow = samples_per_flow
        self.idle_ns = int(float(idle_seconds) * 1_000_000_000)
        self._monotonic_ns = monotonic_ns
        self._time_ns = time_ns
        self._lock = threading.RLock()
        self._flows: collections.OrderedDict[str, dict[str, Any]] = collections.OrderedDict()
        self._series: collections.OrderedDict[str, collections.deque[dict[str, Any]]] = collections.OrderedDict()
        self._sequence = 0
        self._flow_evictions = 0
        self._series_evictions = 0
        self._untracked_series = 0
        self._last_sample_epoch_ns: int | None = None
        self._last_sample_mono_ns: int | None = None
        self._sample_count = 0

    @staticmethod
    def make_flow_id(metadata: dict[str, Any]) -> str:
        fields = (
            "interface", "client_ip", "client_port", "remote_ip",
            "remote_port", "protocol",
        )
        canonical = "|".join(str(metadata.get(field) or "") for field in fields)
        return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()[:24]

    def record(
        self,
        *,
        packet_bytes: int,
        packet_timestamp_ns: int,
        direction: str,
        metadata: dict[str, Any],
    ) -> str:
        if isinstance(packet_bytes, bool) or not isinstance(packet_bytes, int) or not 0 <= packet_bytes <= 65535:
            raise ValueError("Invalid packet length.")
        if isinstance(packet_timestamp_ns, bool) or not isinstance(packet_timestamp_ns, int) or packet_timestamp_ns <= 0:
            raise ValueError("Invalid packet timestamp.")
        if direction not in {"upload", "download", "unknown"}:
            direction = "unknown"
        if not isinstance(metadata, dict):
            raise ValueError("Flow metadata must be an object.")

        clean: dict[str, Any] = {}
        for key in ("interface", "client_ip", "remote_ip", "protocol", "application"):
            value = metadata.get(key)
            clean[key] = str(value)[:64] if value is not None else None
        for key in ("client_port", "remote_port"):
            value = metadata.get(key)
            clean[key] = value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535 else None

        flow_id = self.make_flow_id(clean)
        mono_now = self._monotonic_ns()
        with self._lock:
            flow = self._flows.get(flow_id)
            if flow is None:
                flow = {
                    **clean,
                    "flow_id": flow_id,
                    "first_timestamp_ns": packet_timestamp_ns,
                    "last_timestamp_ns": packet_timestamp_ns,
                    "packets": 0,
                    "bytes": 0,
                    "upload_packets": 0,
                    "download_packets": 0,
                    "upload_bytes": 0,
                    "download_bytes": 0,
                    "bytes_per_second": None,
                    "packets_per_second": None,
                    "upload_bytes_per_second": None,
                    "download_bytes_per_second": None,
                    "sample_valid": False,
                    "sample_timestamp_unix_ns": None,
                    "sample_interval_seconds": None,
                    "_last_seen_mono_ns": mono_now,
                    "_sample_mono_ns": mono_now,
                    "_sampled_packets": 0,
                    "_sampled_bytes": 0,
                    "_sampled_upload_packets": 0,
                    "_sampled_download_packets": 0,
                    "_sampled_upload_bytes": 0,
                    "_sampled_download_bytes": 0,
                }
                self._flows[flow_id] = flow
                if len(self._series) < self.max_series_flows:
                    self._series[flow_id] = collections.deque(maxlen=self.samples_per_flow)
                else:
                    self._untracked_series += 1
            flow["last_timestamp_ns"] = max(flow["last_timestamp_ns"], packet_timestamp_ns)
            flow["_last_seen_mono_ns"] = mono_now
            flow["packets"] += 1
            flow["bytes"] += packet_bytes
            if direction == "upload":
                flow["upload_packets"] += 1
                flow["upload_bytes"] += packet_bytes
            elif direction == "download":
                flow["download_packets"] += 1
                flow["download_bytes"] += packet_bytes
            self._flows.move_to_end(flow_id)
            if flow_id in self._series:
                self._series.move_to_end(flow_id)
            while len(self._flows) > self.max_flows:
                evicted_id, _ = self._flows.popitem(last=False)
                self._flow_evictions += 1
                if evicted_id in self._series:
                    del self._series[evicted_id]
                    self._series_evictions += 1
            return flow_id

    def sample_once(self) -> dict[str, Any]:
        mono_now = self._monotonic_ns()
        epoch_now = self._time_ns()
        with self._lock:
            self._sequence += 1
            self._sample_count += 1
            expired = [
                flow_id for flow_id, flow in self._flows.items()
                if mono_now - flow["_last_seen_mono_ns"] > self.idle_ns
            ]
            for flow_id in expired:
                self._flows.pop(flow_id, None)
                if flow_id in self._series:
                    self._series.pop(flow_id, None)
                    self._series_evictions += 1

            sampled = 0
            for flow_id, flow in self._flows.items():
                elapsed = (mono_now - flow["_sample_mono_ns"]) / 1_000_000_000
                if elapsed <= 0:
                    continue
                deltas = {
                    "bytes_delta": flow["bytes"] - flow["_sampled_bytes"],
                    "packets_delta": flow["packets"] - flow["_sampled_packets"],
                    "upload_bytes_delta": flow["upload_bytes"] - flow["_sampled_upload_bytes"],
                    "download_bytes_delta": flow["download_bytes"] - flow["_sampled_download_bytes"],
                    "upload_packets_delta": flow["upload_packets"] - flow["_sampled_upload_packets"],
                    "download_packets_delta": flow["download_packets"] - flow["_sampled_download_packets"],
                }
                if any(value < 0 for value in deltas.values()):
                    # Defensive guard: counters are monotonic for a flow. If a
                    # future implementation resets one, suppress that interval.
                    flow["sample_valid"] = False
                    flow["bytes_per_second"] = None
                    flow["packets_per_second"] = None
                    flow["upload_bytes_per_second"] = None
                    flow["download_bytes_per_second"] = None
                    flow["_sample_mono_ns"] = mono_now
                    continue

                sample = {
                    "sequence": self._sequence,
                    "timestamp": _utc_iso(epoch_now),
                    "timestamp_unix_ns": epoch_now,
                    "timestamp_unix_ns_text": str(epoch_now),
                    "monotonic_ns": mono_now,
                    "interval_seconds": elapsed,
                    **deltas,
                    "bytes_per_second": deltas["bytes_delta"] / elapsed,
                    "packets_per_second": deltas["packets_delta"] / elapsed,
                    "upload_bytes_per_second": deltas["upload_bytes_delta"] / elapsed,
                    "download_bytes_per_second": deltas["download_bytes_delta"] / elapsed,
                    "sample_valid": True,
                    "source": "AF_PACKET per-flow byte and packet counters",
                }
                flow.update(
                    bytes_per_second=sample["bytes_per_second"],
                    packets_per_second=sample["packets_per_second"],
                    upload_bytes_per_second=sample["upload_bytes_per_second"],
                    download_bytes_per_second=sample["download_bytes_per_second"],
                    sample_valid=True,
                    sample_timestamp_unix_ns=epoch_now,
                    sample_interval_seconds=elapsed,
                )
                flow["_sample_mono_ns"] = mono_now
                for total_key, sampled_key in (
                    ("bytes", "_sampled_bytes"),
                    ("packets", "_sampled_packets"),
                    ("upload_bytes", "_sampled_upload_bytes"),
                    ("download_bytes", "_sampled_download_bytes"),
                    ("upload_packets", "_sampled_upload_packets"),
                    ("download_packets", "_sampled_download_packets"),
                ):
                    flow[sampled_key] = flow[total_key]
                history = self._series.get(flow_id)
                if history is not None:
                    history.append(sample)
                sampled += 1

            self._last_sample_epoch_ns = epoch_now
            self._last_sample_mono_ns = mono_now
            return {
                "ok": True,
                "timestamp": _utc_iso(epoch_now),
                "timestamp_unix_ns": epoch_now,
                "monotonic_ns": mono_now,
                "interval_target_seconds": 1.0,
                "flows_sampled": sampled,
                "active_flows": len(self._flows),
                "tracked_series": len(self._series),
                "untracked_series_flows": sum(1 for flow_id in self._flows if flow_id not in self._series),
                "untracked_series_created": self._untracked_series,
            }

    def summary(self, limit: int = 100) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 256:
            raise ValueError("Invalid flow summary limit.")
        with self._lock:
            rows = []
            for flow in reversed(self._flows.values()):
                row = {key: value for key, value in flow.items() if not key.startswith("_")}
                row["series_available"] = flow["flow_id"] in self._series
                age = max(0.0, (flow["last_timestamp_ns"] - flow["first_timestamp_ns"]) / 1_000_000_000)
                row["lifetime_average_bytes_per_second"] = flow["bytes"] / max(age, 0.001)
                row["sample_source"] = "AF_PACKET per-flow counters"
                rows.append(row)
                if len(rows) >= limit:
                    break
            return rows

    def series(self, flow_id: str, limit: int = DEFAULT_SAMPLES_PER_FLOW) -> dict[str, Any]:
        if not isinstance(flow_id, str) or not FLOW_ID_RE.fullmatch(flow_id):
            return {"ok": False, "error": "Invalid flow identifier."}
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= self.samples_per_flow:
            return {"ok": False, "error": "Invalid flow history limit."}
        with self._lock:
            history = self._series.get(flow_id)
            if history is None or flow_id not in self._flows:
                return {"ok": False, "error": "No sampled history is available for this flow."}
            flow = self._flows[flow_id]
            return {
                "ok": True,
                "flow_id": flow_id,
                "flow": {key: value for key, value in flow.items() if not key.startswith("_")},
                "samples": list(history)[-limit:],
                "sample_capacity": self.samples_per_flow,
                "sample_count": len(history),
                "last_sequence": history[-1]["sequence"] if history else 0,
                "interval_target_seconds": 1.0,
            }

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "interval_target_seconds": 1.0,
                "history_seconds_per_flow": self.samples_per_flow,
                "max_series_flows": self.max_series_flows,
                "tracked_series": len(self._series),
                "untracked_series_flows": self._untracked_series,
                "active_flows": len(self._flows),
                "max_active_flows": self.max_flows,
                "flow_evictions": self._flow_evictions,
                "series_evictions": self._series_evictions,
                "sample_count": self._sample_count,
                "last_sample_timestamp_unix_ns": self._last_sample_epoch_ns,
            }

    def reset(self) -> None:
        with self._lock:
            self._flows.clear()
            self._series.clear()
            self._sequence = self._flow_evictions = self._series_evictions = 0
            self._untracked_series = self._sample_count = 0
            self._last_sample_epoch_ns = self._last_sample_mono_ns = None


__all__ = ["FlowRateTracker", "FLOW_ID_RE"]
