#!/usr/bin/env python3
"""Bounded, on-demand TShark analysis for root-owned PCAPNG captures.

The AF_PACKET monitor remains the low-overhead live collector. TShark performs
an explicit, time- and packet-bounded second pass and returns protocol metadata,
conversation summaries, one-second capture buckets and TCP diagnostics only.
Raw packet payloads are never returned to the portal.
"""
from __future__ import annotations

import collections
import csv
import datetime as dt
import io
import os
import shutil
import subprocess
import time
from pathlib import Path

import sbc_site
from typing import Any

CAPTURE_DIR = sbc_site.STATE_DIR / 'captures'
MAX_PCAP_BYTES = 32 * 1024 * 1024
MAX_ANALYSED_PACKETS = 5000
ANALYSIS_TIMEOUT = 15
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_TIMELINE_BUCKETS = 301
TOOLS = {
    'tshark': 'Protocol dissection, conversations and expert fields',
    'dumpcap': 'Efficient packet capture and ring-buffer support',
    'capinfos': 'Capture-file metadata and integrity summary',
    'tcpdump': 'Lightweight packet inspection and capture',
    'zeek': 'Connection and protocol behaviour logs (optional)',
    'suricata': 'Signature and protocol metadata engine (optional)',
}


def _run(args: list[str], timeout: int = 3) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=timeout, check=False,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                 'HOME': '/nonexistent'}, close_fds=True,
        )
        output = (completed.stdout or '')[:1200]
        return completed.returncode, output
    except (OSError, subprocess.TimeoutExpired):
        return 127, ''


def tool_inventory() -> dict[str, Any]:
    rows = []
    for name, purpose in TOOLS.items():
        binary = shutil.which(name, path='/usr/sbin:/usr/bin:/sbin:/bin')
        version = None
        if binary:
            _, output = _run([binary, '--version'], timeout=2)
            version = next((line.strip() for line in output.splitlines() if line.strip()), None)
        rows.append({'name': name, 'available': bool(binary), 'version': version,
                     'purpose': purpose, 'required': name == 'tshark'})
    return {'ok': True, 'tools': rows,
            'engine': 'native AF_PACKET live metadata + on-demand TShark PCAPNG dissection',
            'live_capture_engine': 'packet_monitor.py / Linux AF_PACKET',
            'deep_analysis': 'TShark runs only when explicitly requested against the last saved PCAPNG.'}


def _validated_capture(path_value: str | None) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise ValueError('No saved PCAPNG is available. Enable “Save full PCAPNG” for a bounded capture first.')
    base = CAPTURE_DIR.resolve(strict=True)
    candidate = Path(path_value)
    if candidate.is_symlink():
        raise ValueError('Capture file must not be a symbolic link.')
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError('Saved capture file is unavailable.') from exc
    if resolved.parent != base or resolved.suffix.lower() != '.pcapng':
        raise ValueError('Capture path is outside the approved PCAPNG directory.')
    info = resolved.stat()
    if not resolved.is_file() or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('Capture file is not a root-owned, private regular file.')
    if not 0 < info.st_size <= MAX_PCAP_BYTES:
        raise ValueError('Capture file is empty or exceeds the 32 MiB analysis limit.')
    return resolved


def _field_set(value: str) -> bool:
    return bool(value and value.strip() not in ('0', '0x0000', 'False', 'false'))


def _utc(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def analyse_capture(path_value: str | None) -> dict[str, Any]:
    """Return aggregate protocol, conversation, timeline and TCP metadata."""
    if os.geteuid() != 0:
        return {'ok': False, 'error': 'TShark analysis requires the root control agent.'}
    binary = shutil.which('tshark', path='/usr/sbin:/usr/bin:/sbin:/bin')
    if not binary:
        return {'ok': False, 'error': 'TShark is not installed. Install the tshark package, then retry.'}
    try:
        capture = _validated_capture(path_value)
    except (OSError, ValueError) as exc:
        return {'ok': False, 'error': str(exc)}

    # Keep this list explicit. We request only decoded header and expert fields,
    # never Follow TCP Stream, reassembled application bodies or raw bytes.
    fields = [
        'frame.number', 'frame.protocols', 'frame.time_epoch',
        'ip.src', 'ipv6.src', 'ip.dst', 'ipv6.dst',
        'tcp.srcport', 'udp.srcport', 'tcp.dstport', 'udp.dstport',
        'dns.qry.name', 'dns.flags.response', 'dns.flags.rcode',
        'tls.handshake.extensions_server_name', 'http.host', 'frame.len',
        'tcp.analysis.retransmission', 'tcp.analysis.fast_retransmission',
        'tcp.analysis.spurious_retransmission', 'tcp.analysis.duplicate_ack',
        'tcp.analysis.out_of_order', 'tcp.analysis.zero_window',
        'tcp.analysis.ack_rtt', 'tcp.flags.syn', 'tcp.flags.reset',
        'tcp.flags.fin', 'tcp.window_size_value',
        'udp.length', 'icmp.type', 'icmpv6.type',
        '_ws.expert.severity', '_ws.expert.message',
    ]
    args = [binary, '-n', '-r', str(capture), '-c', str(MAX_ANALYSED_PACKETS),
            '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=f', '-E', 'quote=n']
    for field in fields:
        args.extend(['-e', field])
    started = time.monotonic()
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=ANALYSIS_TIMEOUT,
                                check=False, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                                  'LC_ALL': 'C', 'HOME': '/nonexistent'},
                                close_fds=True)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'TShark analysis reached its 15-second safety limit. Try a shorter or smaller capture.'}
    except OSError as exc:
        return {'ok': False, 'error': f'Could not start TShark: {exc}'}
    if len(result.stdout) > MAX_OUTPUT_BYTES:
        return {'ok': False, 'error': 'TShark output exceeded the bounded analysis limit.'}
    if result.returncode != 0:
        error = result.stderr.decode('utf-8', 'replace')[:500]
        return {'ok': False, 'error': 'TShark could not dissect this capture: ' + (error or f'exit {result.returncode}')}

    protocols: collections.Counter[str] = collections.Counter()
    endpoints: collections.Counter[str] = collections.Counter()
    domains: collections.Counter[str] = collections.Counter()
    tls_hosts: collections.Counter[str] = collections.Counter()
    http_hosts: collections.Counter[str] = collections.Counter()
    expert: collections.Counter[str] = collections.Counter()
    dns_rcodes: collections.Counter[str] = collections.Counter()
    conversations: dict[tuple[str, str], dict[str, Any]] = {}
    timeline: dict[int, dict[str, int]] = {}
    tcp_counts: collections.Counter[str] = collections.Counter()
    icmp_types: collections.Counter[str] = collections.Counter()
    rtt_values: list[float] = []
    frames = 0
    total_bytes = 0
    first_epoch: float | None = None
    last_epoch: float | None = None

    tcp_flags = {
        17: 'retransmissions',
        18: 'fast_retransmissions',
        19: 'spurious_retransmissions',
        20: 'duplicate_acks',
        21: 'out_of_order',
        22: 'zero_window',
        24: 'syn_packets',
        25: 'reset_packets',
        26: 'fin_packets',
    }

    for row in csv.reader(io.StringIO(result.stdout.decode('utf-8', 'replace')), delimiter='\t'):
        if not row or not any(row):
            continue
        if len(row) < len(fields):
            row += [''] * (len(fields) - len(row))
        frames += 1
        for protocol in row[1].split(':'):
            if protocol:
                protocols[protocol.split('.')[-1].upper()] += 1

        try:
            epoch = float(row[2]) if row[2] else None
        except ValueError:
            epoch = None
        if epoch is not None:
            first_epoch = epoch if first_epoch is None else min(first_epoch, epoch)
            last_epoch = epoch if last_epoch is None else max(last_epoch, epoch)
            bucket = int(epoch)
            if bucket not in timeline and len(timeline) < MAX_TIMELINE_BUCKETS:
                timeline[bucket] = {'packets': 0, 'bytes': 0}
            if bucket in timeline:
                timeline[bucket]['packets'] += 1

        src = row[3] or row[4]
        dst = row[5] or row[6]
        sport = row[7] or row[8]
        dport = row[9] or row[10]
        src_endpoint = f'{src}:{sport}' if src and sport else src
        dst_endpoint = f'{dst}:{dport}' if dst and dport else dst
        if src_endpoint:
            endpoints[src_endpoint] += 1
        if dst_endpoint:
            endpoints[dst_endpoint] += 1

        try:
            frame_bytes = max(0, int(row[16] or 0))
        except ValueError:
            frame_bytes = 0
        total_bytes += frame_bytes
        if epoch is not None and int(epoch) in timeline:
            timeline[int(epoch)]['bytes'] += frame_bytes

        if src_endpoint and dst_endpoint:
            pair = tuple(sorted((src_endpoint, dst_endpoint)))
            conversation = conversations.setdefault(pair, {
                'endpoint_a': pair[0], 'endpoint_b': pair[1], 'frames': 0, 'bytes': 0,
            })
            conversation['frames'] += 1
            conversation['bytes'] += frame_bytes

        if row[11]:
            domains[row[11].lower().rstrip('.')] += 1
        if row[12] == '1' and row[13]:
            rcode = row[13].strip()
            rcode_names = {'0': 'NOERROR', '1': 'FORMERR', '2': 'SERVFAIL',
                           '3': 'NXDOMAIN', '4': 'NOTIMP', '5': 'REFUSED'}
            dns_rcodes[rcode_names.get(rcode, f'RCODE {rcode}')] += 1
        if row[14]:
            tls_hosts[row[14].lower().rstrip('.')] += 1
        if row[15]:
            http_hosts[row[15].lower().rstrip('.')] += 1

        for field_index, label in tcp_flags.items():
            if _field_set(row[field_index]):
                tcp_counts[label] += 1
        try:
            if row[23]:
                rtt_values.append(float(row[23]) * 1000.0)
        except ValueError:
            pass
        if row[29]:
            icmp_types['ICMP type ' + row[29]] += 1
        if row[30]:
            icmp_types['ICMPv6 type ' + row[30]] += 1
        if row[31] or row[32]:
            severity = row[31].strip().upper() or 'NOTE'
            message = row[32].strip()[:160] or 'Expert diagnostic'
            expert[f'{severity}: {message}'] += 1

        if row[27]:
            try:
                # A zero TCP window is a useful back-pressure indicator. Do not
                # confuse it with the unrelated UDP length field at index 28.
                window = int(row[27], 0)
                tcp_counts['zero_window_advertisements'] += int(window == 0)
            except ValueError:
                pass
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    timeline_rows = [
        {'timestamp': float(second), 'timestamp_utc': _utc(float(second)),
         'packets': values['packets'], 'bytes': values['bytes'],
         'bytes_per_second': values['bytes'], 'packets_per_second': values['packets']}
        for second, values in sorted(timeline.items())
    ]
    sorted_conversations = sorted(conversations.values(), key=lambda row: (row['bytes'], row['frames']), reverse=True)
    rtt_summary = {
        'samples': len(rtt_values),
        'average_ms': round(sum(rtt_values) / len(rtt_values), 3) if rtt_values else None,
        'maximum_ms': round(max(rtt_values), 3) if rtt_values else None,
    }
    return {
        'ok': True,
        'capture': {
            'name': capture.name, 'bytes': capture.stat().st_size,
            'analysed_packets': frames, 'packet_limit': MAX_ANALYSED_PACKETS,
            'truncated_to_packet_limit': frames >= MAX_ANALYSED_PACKETS,
            'first_packet_utc': _utc(first_epoch) if first_epoch is not None else None,
            'last_packet_utc': _utc(last_epoch) if last_epoch is not None else None,
            'observed_window_seconds': round(max(0.0, last_epoch - first_epoch), 3)
            if first_epoch is not None and last_epoch is not None else 0.0,
        },
        'duration_ms': elapsed_ms,
        'protocols': [{'name': key, 'frames': value} for key, value in protocols.most_common(24)],
        'endpoints': [{'endpoint': key, 'frames': value} for key, value in endpoints.most_common(24)],
        'conversations': [
            {'conversation': f"{row['endpoint_a']} ↔ {row['endpoint_b']}",
             'frames': row['frames'], 'bytes': row['bytes'],
             'endpoint_a': row['endpoint_a'], 'endpoint_b': row['endpoint_b']}
            for row in sorted_conversations[:24]
        ],
        'dns_queries': [{'name': key, 'count': value} for key, value in domains.most_common(30)],
        'dns_rcodes': [{'name': key, 'count': value} for key, value in dns_rcodes.most_common(12)],
        'tls_hosts': [{'name': key, 'count': value} for key, value in tls_hosts.most_common(30)],
        'http_hosts': [{'name': key, 'count': value} for key, value in http_hosts.most_common(20)],
        'expert': [{'message': key, 'count': value} for key, value in expert.most_common(24)],
        'tcp_analysis': [{'name': key.replace('_', ' ').title(), 'count': value}
                         for key, value in tcp_counts.most_common(20)],
        'tcp_rtt': rtt_summary,
        'icmp_types': [{'name': key, 'count': value} for key, value in icmp_types.most_common(16)],
        'timeline': timeline_rows,
        'total_frame_bytes': total_bytes,
        'timeline_bucket_seconds': 1,
        'privacy': 'Aggregate decoded metadata only. Packet payloads, stream contents and raw frame bytes are never returned to the portal.',
        'analysis_limits': {'packet_limit': MAX_ANALYSED_PACKETS,
                            'timeout_seconds': ANALYSIS_TIMEOUT,
                            'output_limit_bytes': MAX_OUTPUT_BYTES,
                            'timeline_bucket_limit': MAX_TIMELINE_BUCKETS},
    }
