#!/usr/bin/env python3
"""Bounded offline TShark analysis for application-owned PCAPNG captures."""
from __future__ import annotations

import collections
import csv
import io
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

CAPTURE_DIR = Path("/var/lib/sbc-control-center/captures")
MAX_PCAP_BYTES = 32 * 1024 * 1024
MAX_ANALYSED_PACKETS = 5000
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
ANALYSIS_TIMEOUT_SECONDS = 20

FIELDS = (
    "frame.number", "frame.time_epoch", "frame.time_relative",
    "frame.time_delta_displayed", "frame.len", "frame.cap_len",
    "frame.protocols", "eth.src", "eth.dst",
    "ip.src", "ip.dst", "ip.ttl", "ipv6.src", "ipv6.dst", "ipv6.hlim",
    "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.flags", "tcp.flags.str",
    "tcp.seq", "tcp.ack", "tcp.window_size_value", "tcp.len",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack", "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
    "udp.srcport", "udp.dstport", "udp.length",
    "dns.qry.name", "dns.qry.type", "dns.flags.rcode",
    "tls.handshake.extensions_server_name", "tls.handshake.version",
    "tls.record.version",
)
TCP_ANALYSIS_FIELDS = (
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack", "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
)


def tool_inventory() -> dict[str, Any]:
    names = {
        "tshark": "Offline protocol dissection and TCP analysis",
        "dumpcap": "Packet capture engine",
        "capinfos": "Capture metadata and format inspection",
        "tcpdump": "Packet inspection and capture filters",
        "zeek": "Connection and protocol metadata analysis",
        "suricata": "Network threat detection and protocol metadata",
    }
    return {
        "ok": True,
        "tools": [
            {"name": name, "purpose": purpose,
             "available": bool(shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin"))}
            for name, purpose in names.items()
        ],
        "engine": "AF_PACKET live metadata plus bounded offline TShark analysis",
    }


def _validated_capture(value: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("No capture selected.")
    base = CAPTURE_DIR.resolve(strict=True)
    candidate = Path(value)
    if candidate.is_symlink():
        raise ValueError("Capture symlink rejected.")
    path = candidate.resolve(strict=True)
    stat = path.stat()
    if (
        path.parent != base
        or path.suffix != ".pcapng"
        or not path.is_file()
        or stat.st_uid != 0
        or stat.st_mode & 0o077
        or not 0 < stat.st_size <= MAX_PCAP_BYTES
    ):
        raise ValueError("Capture must be root-owned, private and at most 32 MiB.")
    return path


def _as_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def _as_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _summarize_rows(rows: list[dict[str, str]]) -> dict[str, Any]:
    protocols: collections.Counter[str] = collections.Counter()
    endpoints: collections.Counter[str] = collections.Counter()
    dns_names: collections.Counter[str] = collections.Counter()
    tls_names: collections.Counter[str] = collections.Counter()
    tcp_analysis: collections.Counter[str] = collections.Counter()
    conversations: dict[tuple[str, str, str], dict[str, Any]] = {}
    times: list[float] = []
    deltas: list[float] = []

    for row in rows:
        length = _as_int(row.get("frame.len")) or 0
        protocol_stack = row.get("frame.protocols") or ""
        for layer in dict.fromkeys(x for x in protocol_stack.split(":") if x):
            protocols[layer] += 1

        source = row.get("ip.src") or row.get("ipv6.src") or ""
        destination = row.get("ip.dst") or row.get("ipv6.dst") or ""
        tcp_sport = row.get("tcp.srcport") or ""
        tcp_dport = row.get("tcp.dstport") or ""
        udp_sport = row.get("udp.srcport") or ""
        udp_dport = row.get("udp.dstport") or ""
        source_port = tcp_sport or udp_sport
        destination_port = tcp_dport or udp_dport
        transport = "TCP" if tcp_sport or tcp_dport else ("UDP" if udp_sport or udp_dport else "IP")

        if source:
            endpoints[source] += length
        if destination:
            endpoints[destination] += length
        if source and destination:
            left = f"{source}:{source_port}" if source_port else source
            right = f"{destination}:{destination_port}" if destination_port else destination
            key = (transport, *sorted((left, right)))
            item = conversations.setdefault(key, {
                "transport": transport, "endpoint_a": key[1], "endpoint_b": key[2],
                "packets": 0, "bytes": 0, "first_epoch": None, "last_epoch": None,
                "tcp_stream": row.get("tcp.stream") or None,
            })
            item["packets"] += 1
            item["bytes"] += length
            epoch = _as_float(row.get("frame.time_epoch"))
            if epoch is not None:
                item["first_epoch"] = epoch if item["first_epoch"] is None else min(item["first_epoch"], epoch)
                item["last_epoch"] = epoch if item["last_epoch"] is None else max(item["last_epoch"], epoch)

        epoch = _as_float(row.get("frame.time_epoch"))
        if epoch is not None:
            times.append(epoch)
        delta = _as_float(row.get("frame.time_delta_displayed"))
        if delta is not None and delta >= 0:
            deltas.append(delta)

        dns_name = (row.get("dns.qry.name") or "").strip().lower()
        if dns_name:
            dns_names[dns_name] += 1
        tls_name = (row.get("tls.handshake.extensions_server_name") or "").strip().lower()
        if tls_name:
            tls_names[tls_name] += 1
        for field in TCP_ANALYSIS_FIELDS:
            if row.get(field):
                tcp_analysis[field] += 1

    duration = max(times) - min(times) if len(times) > 1 else 0.0
    return {
        "protocol_layers": protocols.most_common(40),
        "top_endpoints_by_observed_bytes": [
            {"address": address, "observed_bytes": size}
            for address, size in endpoints.most_common(20)
        ],
        "top_conversations": sorted(
            conversations.values(), key=lambda item: item["bytes"], reverse=True
        )[:30],
        "dns_names": dns_names.most_common(100),
        "tls_server_names": tls_names.most_common(100),
        "tcp_analysis": {field: tcp_analysis.get(field, 0) for field in TCP_ANALYSIS_FIELDS},
        "capture_time": {
            "first_epoch": min(times) if times else None,
            "last_epoch": max(times) if times else None,
            "duration_seconds": duration,
            "mean_interpacket_delta_seconds": (sum(deltas) / len(deltas)) if deltas else None,
        },
    }


def analyse_capture(value: str) -> dict[str, Any]:
    if os.geteuid() != 0:
        return {"ok": False, "error": "TShark requires the privileged agent."}
    binary = shutil.which("tshark", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not binary:
        return {"ok": False, "error": "TShark is not installed."}
    try:
        path = _validated_capture(value)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}

    args = [
        binary, "-2", "-n", "-r", str(path),
        "-c", str(MAX_ANALYSED_PACKETS),
        "-T", "fields",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f",
    ]
    for field in FIELDS:
        args.extend(("-e", field))

    try:
        result = subprocess.run(
            args, stdin=subprocess.DEVNULL, capture_output=True,
            timeout=ANALYSIS_TIMEOUT_SECONDS,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"},
            check=False,
        )
        if len(result.stdout) > MAX_OUTPUT_BYTES:
            return {"ok": False, "error": "Analysis output exceeds 2 MiB."}
        if result.returncode:
            return {"ok": False, "error": result.stderr.decode(errors="replace")[:500]}

        text = result.stdout.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "frame.protocols" not in reader.fieldnames:
            return {"ok": False, "error": "TShark returned an unexpected fields table; CSV header is missing."}
        rows = list(reader)
        summary = _summarize_rows(rows)
        return {
            "ok": True,
            "capture": path.name,
            "packets_analysed": len(rows),
            "packet_limit": MAX_ANALYSED_PACKETS,
            "truncated_at_packet_limit": len(rows) >= MAX_ANALYSED_PACKETS,
            "summary": summary,
            "fields": rows[:500],
            "fields_available": list(FIELDS),
            "payloads_returned": False,
            "analysis_mode": "offline TShark two-pass fields; payloads excluded",
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"TShark exceeded {ANALYSIS_TIMEOUT_SECONDS}-second limit."}
    except (OSError, csv.Error) as exc:
        return {"ok": False, "error": str(exc)[:240]}


__all__ = ["analyse_capture", "tool_inventory", "_summarize_rows", "FIELDS"]
