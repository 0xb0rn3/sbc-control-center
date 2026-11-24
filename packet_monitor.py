#!/usr/bin/env python3
"""Bounded live network inspection for the router interfaces.

Default mode retains only packet metadata in memory. Optional, explicit PCAPNG
capture writes full packet bytes to a root-only, size/time-limited file for
Wireshark. No capture payload is exposed through the web API.
"""
from __future__ import annotations

import collections
import datetime as dt
import ipaddress
import os
import re
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import device_intelligence
import sbc_site
import wireless_adapter

PACKET_OUTGOING = getattr(socket, 'PACKET_OUTGOING', 4)
ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
SOL_PACKET = 263
PACKET_STATISTICS = 6
MAX_EVENTS = 2500
MAX_FLOWS = 2048
FLOW_IDLE_SECONDS = 180.0
FLOW_SAMPLE_SECONDS = 1.0
MAX_FLOW_SERIES = 96
FLOW_SERIES_SAMPLES = 60
MAX_CAPTURE_SECONDS = 600
MIN_CAPTURE_SECONDS = 10
MAX_CONNTRACK_ROWS = 12000
SOCKET_RCVBUF = 4 * 1024 * 1024
MAX_PCAP_BYTES = 32 * 1024 * 1024
CAPTURE_DIR = sbc_site.STATE_DIR / 'captures'
LEASE_FILE = Path('/var/lib/misc/dnsmasq.leases')
CONNTRACK_FILE = Path('/proc/net/nf_conntrack')

# Deployment-specific interface allowlist. Names are verified against sysfs
# before opening a capture socket; no arbitrary interface name is accepted.
_SITE = sbc_site.load()
VPN_ROLE = _SITE['vpn_label']
DEFAULT_INTERFACES: dict[str, str] = {
    _SITE['ap2_interface']: f"AP · {_SITE['ap2_label']}",
    _SITE['ap_interface']: f"AP · {_SITE['ap_label']}",
    _SITE['vpn_interface']: f"{VPN_ROLE} · inner traffic",
    _SITE['uplink_interface']: 'Physical uplink · WireGuard outer transport',
}
DEFAULT_SUBNETS = (_SITE['ap2_subnet'], _SITE['ap_subnet'])
AP_NETWORKS = ((_SITE['ap2_interface'], _SITE['ap2_subnet']), (_SITE['ap_interface'], _SITE['ap_subnet']))


def _watched_endpoint() -> tuple[str, int] | None:
    """The one TV cloud endpoint dns-filter.json names, if any (flagged, never blocked here)."""
    try:
        import dns_filter
        cfg = dns_filter._load_dns_config()
        return (cfg['vidaa_endpoint_ip'], cfg['vidaa_endpoint_port']) if cfg.get('vidaa_endpoint_ip') else None
    except Exception:
        return None


WATCHED_ENDPOINT = _watched_endpoint()


def _port_pair(payload: bytes, offset: int = 0) -> tuple[int | None, int | None]:
    if len(payload) < offset + 4:
        return None, None
    return struct.unpack_from('!HH', payload, offset)


def _dns_name(packet: bytes, offset: int) -> tuple[str | None, int]:
    """Decode one DNS name, safely following compression pointers."""
    labels: list[str] = []
    cursor = offset
    consumed: int | None = None
    seen: set[int] = set()
    for _ in range(128):
        if cursor >= len(packet):
            return None, offset
        length = packet[cursor]
        if length == 0:
            if consumed is None:
                consumed = cursor + 1
            name = '.'.join(labels).lower().rstrip('.')
            return (name[:253] if name and len(name) <= 253 else None), consumed
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                return None, offset
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet) or pointer in seen:
                return None, offset
            seen.add(pointer)
            if consumed is None:
                consumed = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0 or length > 63 or cursor + 1 + length > len(packet):
            return None, offset
        try:
            label = packet[cursor + 1:cursor + 1 + length].decode('ascii')
        except UnicodeDecodeError:
            return None, offset
        if not label or any(ord(ch) < 33 or ord(ch) > 126 for ch in label):
            return None, offset
        labels.append(label)
        cursor += length + 1
    return None, offset


def _dns_question(payload: bytes) -> tuple[str | None, int | None, int | None, bool | None, list[str], bool]:
    """Return question, qtype, response code, QR flag, A/AAAA answers, blocked hint."""
    if len(payload) < 12:
        return None, None, None, None, [], False
    flags, qdcount, ancount = struct.unpack_from('!HHH', payload, 2)
    qr = bool(flags & 0x8000)
    rcode = flags & 0x000F
    if qdcount < 1:
        return None, None, rcode, qr, [], rcode in (2, 3, 5)
    name, cursor = _dns_name(payload, 12)
    if not name or cursor + 4 > len(payload):
        return None, None, rcode, qr, [], False
    qtype = struct.unpack_from('!H', payload, cursor)[0]
    cursor += 4  # QTYPE + QCLASS
    answers: list[str] = []
    if qr:
        # Skip authority/additional records; parse at most 16 answer records.
        for _ in range(min(ancount, 16)):
            answer_name, next_cursor = _dns_name(payload, cursor)
            if answer_name is None or next_cursor + 10 > len(payload):
                break
            atype, aclass, ttl, rdlength = struct.unpack_from('!HHIH', payload, next_cursor)
            rdata_start = next_cursor + 10
            rdata_end = rdata_start + rdlength
            if rdata_end > len(payload):
                break
            try:
                if aclass == 1 and atype == 1 and rdlength == 4:
                    answers.append(socket.inet_ntop(socket.AF_INET, payload[rdata_start:rdata_end]))
                elif aclass == 1 and atype == 28 and rdlength == 16:
                    answers.append(socket.inet_ntop(socket.AF_INET6, payload[rdata_start:rdata_end]))
            except OSError:
                pass
            cursor = rdata_end
    sinkholes = {'0.0.0.0', '127.0.0.1', '::', '::1'}
    blocked = rcode in (2, 3, 5) or any(answer in sinkholes for answer in answers)
    return name, qtype, rcode, qr, answers[:8], blocked


def _tls_sni(payload: bytes) -> str | None:
    """Extract visible SNI from a single, unfragmented TLS ClientHello record."""
    try:
        if len(payload) < 9 or payload[0] != 22:
            return None
        record_len = struct.unpack_from('!H', payload, 3)[0]
        if record_len + 5 > len(payload) or payload[5] != 1:
            return None
        hello = payload[9:5 + record_len]
        pos = 34
        sid_len = hello[pos]
        pos += 1 + sid_len
        cipher_len = struct.unpack_from('!H', hello, pos)[0]
        pos += 2 + cipher_len
        comp_len = hello[pos]
        pos += 1 + comp_len
        ext_len = struct.unpack_from('!H', hello, pos)[0]
        pos += 2
        end = min(len(hello), pos + ext_len)
        while pos + 4 <= end:
            ext_type, ext_size = struct.unpack_from('!HH', hello, pos)
            pos += 4
            ext_end = min(end, pos + ext_size)
            if ext_type == 0 and pos + 5 <= ext_end:
                list_len = struct.unpack_from('!H', hello, pos)[0]
                cursor = pos + 2
                list_end = min(ext_end, cursor + list_len)
                while cursor + 3 <= list_end:
                    name_type = hello[cursor]
                    name_len = struct.unpack_from('!H', hello, cursor + 1)[0]
                    cursor += 3
                    if cursor + name_len > list_end:
                        return None
                    if name_type == 0:
                        value = hello[cursor:cursor + name_len].decode('ascii')
                        if re.fullmatch(r'[A-Za-z0-9.-]{1,253}', value):
                            return value.lower().rstrip('.')
                    cursor += name_len
                return None
            pos = ext_end
    except (IndexError, struct.error, UnicodeDecodeError, ValueError):
        return None
    return None



def _safe_text(data: bytes, limit: int = 180) -> str | None:
    try:
        value = data.decode('utf-8', errors='replace')
    except Exception:
        return None
    value = re.sub(r'[^\x20-\x7e]', ' ', value)
    value = re.sub(r'\s+', ' ', value).strip()
    return value[:limit] or None


def _dhcp_metadata(payload: bytes) -> dict[str, Any]:
    """Extract only bounded, non-secret DHCP identity hints from BOOTP options."""
    if len(payload) < 240 or payload[236:240] != b'\x63\x82\x53\x63':
        return {}
    hlen = min(payload[2], 16)
    client_mac = ':'.join(f'{byte:02x}' for byte in payload[28:28 + min(hlen, 6)]) if hlen >= 6 else None
    requested_ip = None
    try:
        requested_ip = socket.inet_ntop(socket.AF_INET, payload[16:20])
        if requested_ip == '0.0.0.0':
            requested_ip = None
    except OSError:
        pass
    ciaddr = socket.inet_ntop(socket.AF_INET, payload[12:16])
    if ciaddr == '0.0.0.0':
        ciaddr = None
    hostname = vendor_class = message_type = None
    parameter_request = []
    cursor = 240
    option_count = 0
    while cursor < len(payload) and option_count < 128:
        option = payload[cursor]
        cursor += 1
        if option == 255:
            break
        if option == 0:
            continue
        if cursor >= len(payload):
            break
        size = payload[cursor]
        cursor += 1
        if size > len(payload) - cursor:
            break
        value = payload[cursor:cursor + size]
        cursor += size
        option_count += 1
        if option == 12:
            hostname = _safe_text(value, 63)
        elif option == 60:
            vendor_class = _safe_text(value, 96)
        elif option == 50 and size == 4:
            requested_ip = socket.inet_ntop(socket.AF_INET, value)
        elif option == 53 and size == 1:
            message_type = {1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline',
                            5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform'}.get(value[0], 'Other')
        elif option == 55:
            parameter_request = [str(item) for item in value[:32]]
    return {
        'dhcp_client_mac': client_mac,
        'dhcp_requested_ip': requested_ip,
        'dhcp_client_ip': ciaddr,
        'dhcp_hostname': hostname,
        'dhcp_vendor_class': vendor_class,
        'dhcp_message_type': message_type,
        'dhcp_parameter_request': parameter_request,
    }


def _ssdp_metadata(payload: bytes) -> dict[str, Any]:
    if len(payload) > 4096:
        payload = payload[:4096]
    text = _safe_text(payload, 4096)
    if not text or not (text.startswith('M-SEARCH') or text.startswith('NOTIFY') or text.startswith('HTTP/1.') or text.startswith('SUBSCRIBE')):
        return {}
    fields: dict[str, str] = {}
    for line in payload.decode('utf-8', errors='replace').splitlines()[:40]:
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip().lower()
        if key in {'server', 'st', 'usn', 'nt', 'nls'}:
            safe = _safe_text(value.encode('utf-8', errors='replace'), 180)
            if safe:
                fields[key] = safe
    return {
        'ssdp_server': fields.get('server'),
        'ssdp_service_type': fields.get('st') or fields.get('nt'),
        'ssdp_unique_name': fields.get('usn'),
        'ssdp_hint': ' '.join(value for value in (fields.get('server'), fields.get('st'), fields.get('nt')) if value)[:240] or None,
    }


def _arp_metadata(payload: bytes) -> dict[str, Any]:
    if len(payload) < 28:
        return {}
    try:
        htype, ptype, hlen, plen, opcode = struct.unpack_from('!HHBBH', payload, 0)
        if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4 or opcode not in (1, 2):
            return {}
        sender_mac = ':'.join(f'{value:02x}' for value in payload[8:14])
        sender_ip = socket.inet_ntop(socket.AF_INET, payload[14:18])
        target_mac = ':'.join(f'{value:02x}' for value in payload[18:24])
        target_ip = socket.inet_ntop(socket.AF_INET, payload[24:28])
        return {'arp_operation': 'request' if opcode == 1 else 'reply',
                'arp_sender_mac': sender_mac, 'arp_sender_ip': sender_ip,
                'arp_target_mac': target_mac, 'arp_target_ip': target_ip}
    except (OSError, struct.error):
        return {}


def decode_packet(data: bytes, packet_type: int = 0, link_protocol: int | None = None) -> dict[str, Any]:
    """Decode IP headers and selected cleartext metadata; never return payload bytes."""
    event: dict[str, Any] = {
        'timestamp': time.time(),
        'direction': 'outbound' if packet_type == PACKET_OUTGOING else 'inbound',
        'bytes': len(data), 'source_ip': None, 'destination_ip': None,
        'source_port': None, 'destination_port': None, 'protocol': 'OTHER',
        'application': 'Other', 'tcp_flags': '', 'dns_query': None,
        'dns_qtype': None, 'dns_rcode': None, 'dns_response': None,
        'dns_answers': [], 'dns_blocked_answer': False, 'tls_sni': None,
        'mdns_name': None, 'ssdp_server': None, 'ssdp_service_type': None,
        'ssdp_unique_name': None, 'ssdp_hint': None, 'dhcp_client_mac': None,
        'dhcp_requested_ip': None, 'dhcp_client_ip': None, 'dhcp_hostname': None,
        'dhcp_vendor_class': None, 'dhcp_message_type': None, 'dhcp_parameter_request': [],
        'arp_operation': None, 'arp_sender_mac': None, 'arp_sender_ip': None,
        'arp_target_mac': None, 'arp_target_ip': None,
        'ip_version': None, 'ip_ttl': None, 'ip_dscp': None, 'ip_total_length': None,
    }
    if not data:
        return event
    version = data[0] >> 4
    payload = b''
    transport = 0
    if version == 4 and len(data) >= 20:
        event['ip_version'] = 4
        event['ip_ttl'] = data[8]
        event['ip_dscp'] = data[1] >> 2
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or ihl > len(data):
            event['protocol'] = 'IPv4 malformed'
            return event
        total_len = struct.unpack_from('!H', data, 2)[0]
        event['ip_total_length'] = total_len or len(data)
        if total_len and total_len < ihl:
            event['protocol'] = 'IPv4 malformed'
            return event
        fragment = struct.unpack_from('!H', data, 6)[0] & 0x1FFF
        event['source_ip'] = socket.inet_ntop(socket.AF_INET, data[12:16])
        event['destination_ip'] = socket.inet_ntop(socket.AF_INET, data[16:20])
        transport = data[9]
        payload = data[ihl:min(len(data), total_len or len(data))]
        if fragment:
            event['protocol'] = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(transport, f'IP-{transport}') + ' fragment'
            return event
    elif version == 6 and len(data) >= 40:
        event['ip_version'] = 6
        event['ip_ttl'] = data[7]
        event['ip_dscp'] = ((data[0] & 0x0F) << 2) | (data[1] >> 6)
        event['source_ip'] = socket.inet_ntop(socket.AF_INET6, data[8:24])
        event['destination_ip'] = socket.inet_ntop(socket.AF_INET6, data[24:40])
        payload_len = struct.unpack_from('!H', data, 4)[0]
        event['ip_total_length'] = 40 + payload_len
        payload = data[40:min(len(data), 40 + payload_len)]
        transport = data[6]
        offset = 0
        for _ in range(8):
            if transport in (0, 43, 60):
                if offset + 2 > len(payload):
                    break
                next_header = payload[offset]
                ext_len = (payload[offset + 1] + 1) * 8
            elif transport == 44:
                if offset + 8 > len(payload):
                    break
                next_header = payload[offset]
                fragment = struct.unpack_from('!H', payload, offset + 2)[0] >> 3
                if fragment:
                    event['protocol'] = 'IPv6 fragment'
                    return event
                ext_len = 8
            elif transport == 51:
                if offset + 2 > len(payload):
                    break
                next_header = payload[offset]
                ext_len = (payload[offset + 1] + 2) * 4
            else:
                break
            if ext_len < 8 or offset + ext_len > len(payload):
                event['protocol'] = 'IPv6 extension'
                return event
            transport = next_header
            offset += ext_len
        payload = payload[offset:]
    else:
        proto = link_protocol
        if proto in (ETH_P_ARP, socket.htons(ETH_P_ARP)):
            event['protocol'] = 'ARP'
            event['application'] = 'Address resolution'
            event.update(_arp_metadata(data))
        else:
            event['protocol'] = 'Non-IP'
        return event

    if transport == 6:
        event['protocol'] = 'TCP'
        event['source_port'], event['destination_port'] = _port_pair(payload)
        app_payload = b''
        if len(payload) >= 20:
            tcp_header_len = ((payload[12] >> 4) & 0x0F) * 4
            if 20 <= tcp_header_len <= len(payload):
                flags = payload[13]
                event['tcp_flags'] = ','.join(name for bit, name in ((2, 'SYN'), (16, 'ACK'), (1, 'FIN'), (4, 'RST'), (8, 'PSH'), (32, 'URG')) if flags & bit)
                app_payload = payload[tcp_header_len:]
        sport, dport = event['source_port'], event['destination_port']
        if sport == 53 or dport == 53:
            event['application'] = 'DNS'
            if len(app_payload) >= 2:
                length = struct.unpack_from('!H', app_payload, 0)[0]
                dns_info = _dns_question(app_payload[2:2 + length])
                (event['dns_query'], event['dns_qtype'], event['dns_rcode'],
                 event['dns_response'], event['dns_answers'], event['dns_blocked_answer']) = dns_info
        elif sport in (80, 8080) or dport in (80, 8080):
            event['application'] = 'HTTP'
        elif sport in (443, 8443) or dport in (443, 8443):
            event['application'] = 'TLS'
            event['tls_sni'] = _tls_sni(app_payload)
        elif sport == 22 or dport == 22:
            event['application'] = 'SSH'
    elif transport == 17:
        event['protocol'] = 'UDP'
        event['source_port'], event['destination_port'] = _port_pair(payload)
        app_payload = payload[8:] if len(payload) >= 8 else b''
        sport, dport = event['source_port'], event['destination_port']
        if sport == 53 or dport == 53:
            event['application'] = 'DNS'
            dns_info = _dns_question(app_payload)
            (event['dns_query'], event['dns_qtype'], event['dns_rcode'],
             event['dns_response'], event['dns_answers'], event['dns_blocked_answer']) = dns_info
        elif sport in (443, 784, 8853) or dport in (443, 784, 8853):
            event['application'] = 'QUIC / encrypted transport'
        elif sport == 123 or dport == 123:
            event['application'] = 'NTP'
        elif sport in (67, 68) or dport in (67, 68):
            event['application'] = 'DHCP'
            event.update(_dhcp_metadata(app_payload))
        elif sport == 5353 or dport == 5353:
            event['application'] = 'mDNS'
            event['mdns_name'] = _dns_question(app_payload)[0]
        elif sport == 1900 or dport == 1900:
            event['application'] = 'SSDP / UPnP'
            event.update(_ssdp_metadata(app_payload))
    elif transport in (1, 58):
        event['protocol'] = 'ICMP' if transport == 1 else 'ICMPv6'
        event['application'] = 'Network control'
    else:
        event['protocol'] = f'IP-{transport}'
    return event


def _load_leases(path: Path = LEASE_FILE) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    try:
        with path.open('r', encoding='utf-8', errors='replace') as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 4 and re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', parts[2]):
                    try:
                        ipaddress.ip_address(parts[2])
                    except ValueError:
                        continue
                    result[parts[2]] = {'mac': parts[1].lower(), 'hostname': parts[3] if parts[3] != '*' else ''}
    except OSError:
        pass
    return result


def _conntrack_keys(path: Path, subnets: tuple[str, ...]) -> dict[tuple[str, int, str, int, str], tuple[str, str]]:
    """Map NATed tunnel tuples back to the original AP client and remote address."""
    networks = [ipaddress.ip_network(value, strict=False) for value in subnets]
    result: dict[tuple[str, int, str, int, str], tuple[str, str]] = {}
    try:
        handle = path.open('r', encoding='ascii', errors='ignore')
    except OSError:
        return result
    with handle:
        for row_no, line in enumerate(handle):
            if row_no >= MAX_CONNTRACK_ROWS:
                break
            parts = line.split()
            if len(parts) < 4 or parts[2] not in ('tcp', 'udp'):
                continue
            proto = parts[2].upper()
            attrs = re.findall(r'\b(src|dst|sport|dport)=([^\s]+)', line)
            if len(attrs) < 8:
                continue
            try:
                original = dict(attrs[:4])
                reply = dict(attrs[4:8])
                client = str(ipaddress.ip_address(original['src']))
                remote = str(ipaddress.ip_address(original['dst']))
                rep_src = str(ipaddress.ip_address(reply['src']))
                rep_dst = str(ipaddress.ip_address(reply['dst']))
                rep_sport, rep_dport = int(reply['sport']), int(reply['dport'])
                if not any(ipaddress.ip_address(client) in network for network in networks):
                    continue
                result[(rep_src, rep_sport, rep_dst, rep_dport, proto)] = (client, remote)
                result[(rep_dst, rep_dport, rep_src, rep_sport, proto)] = (client, remote)
            except (KeyError, ValueError):
                continue
    return result


class PcapngWriter:
    """Minimal PCAPNG writer using DLT_RAW (IP packets, no link-layer payload)."""
    def __init__(self, interfaces: list[str], directory: Path = CAPTURE_DIR, max_bytes: int = MAX_PCAP_BYTES):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        self.path = directory / f'{sbc_site.PREFIX}-{stamp}-{os.getpid()}.pcapng'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(self.path, flags, 0o600)
        self._stream = os.fdopen(fd, 'wb', buffering=0)
        self._lock = threading.Lock()
        self._max_bytes = max_bytes
        self._written = 0
        self._full = False
        self._if_indexes = {name: index for index, name in enumerate(interfaces)}
        # Section Header Block, little-endian, version 1.0, unknown section length.
        self._write_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for name in interfaces:
            encoded = name.encode('utf-8')[:64]
            padding = b'\0' * ((-len(encoded)) % 4)
            options = struct.pack('<HH', 2, len(encoded)) + encoded + padding + struct.pack('<HH', 0, 0)
            body = struct.pack('<HHI', 101, 0, 65535) + options
            self._write_block(1, body)

    def _write_block(self, block_type: int, body: bytes) -> bool:
        total = 12 + len(body)
        self._stream.write(struct.pack('<II', block_type, total) + body + struct.pack('<I', total))
        self._written += total
        return True

    def write_packet(self, interface: str, packet: bytes, timestamp: float) -> bool:
        # PCAPNG interface link type 101 (DLT_RAW) contains only valid raw
        # IPv4/IPv6 packets. AF_PACKET SOCK_DGRAM can also deliver ARP/non-IP.
        if not packet:
            return False
        version = packet[0] >> 4
        if version == 4:
            if len(packet) < 20:
                return False
            header_length = (packet[0] & 0x0F) * 4
            total_length = struct.unpack_from('!H', packet, 2)[0]
            if header_length < 20 or header_length > len(packet) or total_length < header_length:
                return False
        elif version == 6:
            if len(packet) < 40 or 40 + struct.unpack_from('!H', packet, 4)[0] > len(packet):
                return False
        else:
            return False
        with self._lock:
            if self._full or self._stream.closed:
                return False
            index = self._if_indexes.get(interface)
            if index is None:
                return False
            caplen = min(len(packet), 65535)
            packet = packet[:caplen]
            padding = b'\0' * ((-caplen) % 4)
            micros = int(timestamp * 1_000_000)
            body = struct.pack('<IIIII', index, micros >> 32, micros & 0xFFFFFFFF, caplen, len(packet)) + packet + padding
            projected = self._written + 12 + len(body)
            if projected > self._max_bytes:
                self._full = True
                return False
            self._write_block(6, body)
            return True

    def close(self) -> None:
        with self._lock:
            if not self._stream.closed:
                self._stream.flush()
                os.fsync(self._stream.fileno())
                self._stream.close()

    @property
    def size(self) -> int:
        return self._written

    @property
    def full(self) -> bool:
        return self._full


class PacketMonitor:
    def __init__(self, ring_size: int = MAX_EVENTS,
                 conntrack_path: Path = CONNTRACK_FILE,
                 lease_path: Path = LEASE_FILE):
        self._lock = threading.RLock()
        self._events: collections.deque[dict[str, Any]] = collections.deque(maxlen=ring_size)
        self._flows: collections.OrderedDict[str, dict[str, Any]] = collections.OrderedDict()
        # A small, bounded set of per-flow histories keeps the live graph cheap
        # on the SBC while retaining one timestamped sample per actual interval.
        self._flow_series: collections.OrderedDict[str, collections.deque[dict[str, Any]]] = collections.OrderedDict()
        self._rate_sample_sequence = 0
        self._flow_sequence = 0
        self._conntrack_path = conntrack_path
        self._lease_path = lease_path
        self._conntrack: dict[tuple[str, int, str, int, str], tuple[str, str]] = {}
        self._leases: dict[str, dict[str, str]] = {}
        self._identity_by_ip: dict[str, dict[str, Any]] = {}
        # Client-scoped DNS answer cache lets later TLS/QUIC flows inherit the
        # hostname resolved moments earlier, without retaining packet payloads.
        self._dns_ip_names: collections.OrderedDict[tuple[str, str], tuple[str, float]] = collections.OrderedDict()
        self._last_conntrack_refresh = 0.0
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self._writer: PcapngWriter | None = None
        self._active = False
        self._started_at: float | None = None
        self._stop_at: float | None = None
        self._duration = 0
        self._interfaces: list[str] = []
        self._allowed_interfaces: dict[str, str] = {}
        self._subnets: tuple[str, ...] = DEFAULT_SUBNETS
        self._next_id = 0
        self._counts: dict[str, dict[str, int]] = {}
        self._errors: list[str] = []
        self._overwritten = 0
        self._last_packet_at: float | None = None
        self._last_pcap_path: str | None = None
        self._last_pcap_bytes = 0

    def _refresh_maps(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_conntrack_refresh < 3.0:
            return
        conntrack = _conntrack_keys(self._conntrack_path, self._subnets)
        leases = _load_leases(self._lease_path)
        neighbours: list[dict[str, Any]] = []
        for iface, subnet in AP_NETWORKS:
            neighbours.extend(device_intelligence.discover_neighbours(iface, subnet))
        stations = wireless_adapter.station_inventory(tuple(i for i, _ in AP_NETWORKS))
        by_mac = {row.get('mac'): row for row in neighbours if row.get('mac')}
        for mac, lease in ((row.get('mac'), row) for row in leases.values()):
            if mac:
                by_mac.setdefault(mac.lower(), {}).update({k: v for k, v in lease.items() if v})
        rows: list[dict[str, Any]] = []
        for ip, lease in leases.items():
            rows.append({'ip': ip, 'mac': lease.get('mac'), 'hostname': lease.get('hostname'),
                         'associated': False, 'discovery_source': 'dnsmasq DHCP lease'})
        rows.extend(neighbours)
        for station in stations:
            mac = station.get('mac')
            lease = by_mac.get(mac, {}) if mac else {}
            rows.append({**lease, **station, 'mac': mac or lease.get('mac'),
                         'ip': lease.get('ip'), 'hostname': lease.get('hostname'),
                         'associated': True, 'discovery_source': 'Wi-Fi station table'})
        identities = {row.get('ip'): row for row in device_intelligence.enrich_clients(rows) if row.get('ip')}
        with self._lock:
            self._conntrack = conntrack
            self._leases = leases
            self._identity_by_ip = identities
            self._last_conntrack_refresh = now

    def _conntrack_worker(self) -> None:
        while not self._stop.wait(2.0):
            self._refresh_maps(force=True)

    def _event_for(self, iface: str, packet_type: int, link_protocol: int | None, data: bytes) -> dict[str, Any]:
        event = decode_packet(data, packet_type, link_protocol)
        role = self._allowed_interfaces.get(iface, 'other')
        event['interface'] = iface
        event['path'] = role
        event['client_ip'] = None
        event['client_name'] = None
        event['client_mac'] = None
        event['remote_ip'] = None
        source, destination = event.get('source_ip'), event.get('destination_ip')
        source_port, destination_port = event.get('source_port'), event.get('destination_port')
        proto = event.get('protocol', '')
        packet_key = (source, source_port, destination, destination_port, proto) if source and destination and source_port is not None and destination_port is not None else None
        with self._lock:
            conntrack = self._conntrack
            leases = self._leases
            identities = self._identity_by_ip
        client_ip = remote_ip = None
        if role.startswith('AP'):
            # Attribute by the AP subnet, not PACKET_OUTGOING. This remains correct
            # when the driver reports direction differently or VLAN/NAT paths vary.
            networks = [ipaddress.ip_network(value, strict=False) for value in self._subnets]
            source_is_client = False
            destination_is_client = False
            for candidate, target in ((source, 'source'), (destination, 'destination')):
                if not candidate:
                    continue
                try:
                    if any(ipaddress.ip_address(candidate) in network for network in networks):
                        if target == 'source':
                            source_is_client = True
                        else:
                            destination_is_client = True
                except ValueError:
                    continue
            if source_is_client:
                client_ip, remote_ip = source, destination
                event['flow_direction'] = 'client-to-network'
            elif destination_is_client:
                client_ip, remote_ip = destination, source
                event['flow_direction'] = 'network-to-client'
            # DHCP may identify a client before it has an assigned address.
            if event.get('application') == 'DHCP':
                client_ip = event.get('dhcp_requested_ip') or event.get('dhcp_client_ip') or client_ip
                if event.get('dhcp_client_mac'):
                    event['client_mac'] = event['dhcp_client_mac']
                hints = [event.get('dhcp_hostname'), event.get('dhcp_vendor_class')]
                if event.get('dhcp_parameter_request'):
                    hints.append('DHCP option 55 PRL ' + ','.join(event['dhcp_parameter_request'][:16]))
                hint = ' | '.join(x for x in hints if x)
                if hint:
                    device_intelligence.remember_observation(
                        ip=client_ip, mac=event.get('client_mac'), hint=hint, source='DHCP fingerprint')
            if event.get('application') == 'Address resolution':
                arp_ip = event.get('arp_sender_ip')
                arp_mac = event.get('arp_sender_mac')
                if arp_ip and arp_mac and arp_ip != '0.0.0.0':
                    client_ip = arp_ip
                    event['client_mac'] = arp_mac
                    device_intelligence.remember_observation(
                        ip=arp_ip, mac=arp_mac, hint='ARP address resolution', source='ARP')
            event['client_ip'] = client_ip
            event['remote_ip'] = remote_ip
            if client_ip and client_ip in leases:
                event['client_name'] = leases[client_ip].get('hostname') or None
                event['client_mac'] = event.get('client_mac') or leases[client_ip].get('mac')
        elif role.startswith(VPN_ROLE):
            mapping = conntrack.get(packet_key) if packet_key else None
            if mapping:
                client_ip, remote_ip = mapping
            else:
                for candidate, remote in ((source, destination), (destination, source)):
                    if candidate:
                        try:
                            if any(ipaddress.ip_address(candidate) in network for network in (ipaddress.ip_network(x, strict=False) for x in self._subnets)):
                                client_ip, remote_ip = candidate, remote
                                break
                        except ValueError:
                            pass
            if client_ip and remote_ip:
                if source == client_ip and destination == remote_ip:
                    event['flow_direction'] = 'client-to-network'
                elif source == remote_ip and destination == client_ip:
                    event['flow_direction'] = 'network-to-client'
            event['client_ip'], event['remote_ip'] = client_ip, remote_ip
        identity = identities.get(event.get('client_ip')) if event.get('client_ip') else None
        if role.startswith('AP') and event.get('client_ip'):
            passive_hint = event.get('mdns_name') or event.get('ssdp_hint')
            if passive_hint:
                source_name = 'mDNS service advertisement/query' if event.get('mdns_name') else 'SSDP/UPnP advertisement'
                device_intelligence.remember_observation(
                    ip=event.get('client_ip'), mac=event.get('client_mac'),
                    hint=passive_hint, source=source_name)
        if identity:
            event['client_mac'] = event.get('client_mac') or identity.get('mac')
            event['device_label'] = identity.get('identity_label')
            event['device_type'] = identity.get('device_type')
            event['device_type_confidence'] = identity.get('device_type_confidence')
            event['device_vendor'] = identity.get('mac_vendor')
            event['device_vendor_registry'] = identity.get('mac_vendor_registry')
            event['device_identity_confidence'] = identity.get('identity_confidence')
            event['device_identity_evidence'] = identity.get('identity_evidence', [])
            event['device_mac_kind'] = identity.get('mac_kind')
            event['device_signal'] = identity.get('signal')
            event['device_radio'] = identity.get('radio')
        event['client_label'] = (identity or {}).get('identity_label') or event.get('client_name') or event.get('client_ip') or 'Unattributed'
        event['remote_port'] = (destination_port if remote_ip == destination else
                                source_port if remote_ip == source else None)
        event['client_port'] = (source_port if client_ip == source else
                                destination_port if client_ip == destination else None)
        domain = event.get('tls_sni') or event.get('dns_query')
        # Correlate DNS answers with subsequent client flows. This improves
        # visibility for QUIC and TLS where SNI is unavailable, while keeping
        # cache entries client-specific and short-lived.
        if role.startswith('AP') and client_ip and event.get('application') == 'DNS' and event.get('dns_response') and domain:
            now_mono = time.monotonic()
            with self._lock:
                for answer in event.get('dns_answers') or []:
                    try:
                        answer_ip = str(ipaddress.ip_address(answer))
                    except ValueError:
                        continue
                    cache_key = (client_ip, answer_ip)
                    self._dns_ip_names[cache_key] = (str(domain), now_mono + 300.0)
                    self._dns_ip_names.move_to_end(cache_key)
                while self._dns_ip_names and len(self._dns_ip_names) > 4096:
                    self._dns_ip_names.popitem(last=False)
        if not domain and client_ip and remote_ip:
            cache_key = (client_ip, remote_ip)
            now_mono = time.monotonic()
            with self._lock:
                cached = self._dns_ip_names.get(cache_key)
                if cached and cached[1] >= now_mono:
                    domain = cached[0]
                    self._dns_ip_names.move_to_end(cache_key)
                elif cached:
                    self._dns_ip_names.pop(cache_key, None)
        event['domain'] = domain
        # Stable bidirectional flow identity. Client/remote attribution is preferred;
        # otherwise canonicalise the packet's endpoint tuple for host/uplink traffic.
        import hashlib
        if event.get('client_ip') and event.get('remote_ip'):
            flow = '|'.join(str(value or '') for value in (
                event.get('client_ip'), event.get('client_port'),
                event.get('remote_ip'), event.get('remote_port'), proto))
        elif source and destination:
            endpoints = sorted(((source, source_port or 0), (destination, destination_port or 0)))
            flow = '|'.join(str(value or '') for value in (*endpoints[0], *endpoints[1], proto))
        else:
            flow = None
        event['flow_id'] = hashlib.sha256(flow.encode('utf-8')).hexdigest()[:16] if flow else None
        event['signal'] = None
        if event.get('dns_blocked_answer'):
            event['signal'] = 'DNS response looks blocked (NXDOMAIN or sinkhole answer)'
        elif WATCHED_ENDPOINT and (event.get('remote_ip'), event.get('remote_port')) == WATCHED_ENDPOINT:
            event['signal'] = 'VIDAA/Tencent cloud endpoint candidate; verify client attribution before blocking'
        elif event.get('remote_port') in (4444, 5555, 6667, 31337, 12345):
            event['signal'] = 'Uncommon remote service port; review the device'
        if role.startswith('Physical uplink'):
            event['note'] = 'WireGuard outer transport and host uplink traffic; tunneled payload is encrypted.'
        elif role.startswith(VPN_ROLE) and not event.get('client_ip'):
            event['note'] = 'NAT attribution unavailable for this flow; AP-side capture still identifies the client.'
        return event

    def _update_flow_locked(self, event: dict[str, Any]) -> bool:
        """Update bounded flow counters and decide whether to emit an event sample.

        Called with self._lock held. Every packet updates a flow, but repeated
        QUIC/TLS packets are emitted at most once per second per interface/flow.
        DNS, identity, and review events are emitted immediately.
        """
        flow_id = event.get('flow_id')
        if not flow_id:
            return True
        now = float(event.get('timestamp') or time.time())
        key = f"{event.get('interface', 'unknown')}:{flow_id}"
        flow = self._flows.get(key)
        new_flow = flow is None
        if flow is None:
            flow = {
                'flow_id': flow_id,
                'flow_seq': 0,
                'interface': event.get('interface'),
                'path': event.get('path'),
                'client_ip': event.get('client_ip'),
                'client_mac': event.get('client_mac'),
                'client_label': event.get('client_label') or event.get('client_ip') or 'Unattributed',
                'remote_ip': event.get('remote_ip') or event.get('destination_ip'),
                'remote_port': event.get('remote_port') or event.get('destination_port') or event.get('source_port'),
                'client_port': event.get('client_port'),
                'protocol': event.get('protocol', 'OTHER'),
                'application': event.get('application', 'Other'),
                'domain': event.get('domain') or event.get('dns_query') or event.get('tls_sni'),
                'packets': 0,
                'bytes': 0,
                'upload_bytes': 0,
                'download_bytes': 0,
                'unknown_direction_bytes': 0,
                'upload_packets': 0,
                'download_packets': 0,
                'first_seen': now,
                'last_seen': now,
                'packets_per_second': 0.0,
                'bits_per_second': 0.0,
                'bytes_per_second': 0.0,
                'upload_bytes_per_second': 0.0,
                'download_bytes_per_second': 0.0,
                'unknown_direction_bytes_per_second': 0.0,
                'upload_packets_per_second': 0.0,
                'download_packets_per_second': 0.0,
                'rate_sampled_at': None,
                'rate_sampled_at_utc': None,
                'rate_interval_ms': None,
                '_sample_mono': time.monotonic(),
                '_interval_packets': 0,
                '_interval_bytes': 0,
                '_interval_upload_bytes': 0,
                '_interval_download_bytes': 0,
                '_interval_unknown_bytes': 0,
                '_interval_upload_packets': 0,
                '_interval_download_packets': 0,
                '_last_emit': 0.0,
                'signal': event.get('signal'),
                'note': event.get('note'),
                'flow_direction': event.get('flow_direction'),
            }
            self._flows[key] = flow
        else:
            # Refresh attribution as DHCP/ARP/Wi-Fi evidence becomes available.
            for field in ('client_ip', 'client_mac', 'client_label', 'remote_ip',
                          'remote_port', 'client_port', 'domain', 'signal', 'note'):
                value = event.get(field)
                if value not in (None, '', '—', 'Unattributed'):
                    flow[field] = value
            if event.get('application') and event.get('application') != 'Other':
                flow['application'] = event['application']
            if event.get('protocol'):
                flow['protocol'] = event['protocol']
            if event.get('flow_direction'):
                flow['flow_direction'] = event['flow_direction']
            self._flows.move_to_end(key)
        packet_bytes = max(0, int(event.get('bytes') or 0))
        flow['packets'] += 1
        flow['bytes'] += packet_bytes
        flow['_interval_packets'] += 1
        flow['_interval_bytes'] += packet_bytes
        direction = event.get('flow_direction')
        if direction == 'client-to-network':
            flow['upload_bytes'] += packet_bytes
            flow['upload_packets'] += 1
            flow['_interval_upload_bytes'] += packet_bytes
            flow['_interval_upload_packets'] += 1
        elif direction == 'network-to-client':
            flow['download_bytes'] += packet_bytes
            flow['download_packets'] += 1
            flow['_interval_download_bytes'] += packet_bytes
            flow['_interval_download_packets'] += 1
        else:
            flow['unknown_direction_bytes'] += packet_bytes
            flow['_interval_unknown_bytes'] += packet_bytes
        flow['last_seen'] = now
        self._flow_sequence += 1
        flow['flow_seq'] = self._flow_sequence

        # Retain short histories for the most recently active client-attributed
        # flows only. The counters above still cover every retained flow.
        if flow.get('client_ip') and flow.get('remote_ip'):
            if key not in self._flow_series:
                if len(self._flow_series) >= MAX_FLOW_SERIES:
                    evicted_key, _ = self._flow_series.popitem(last=False)
                    evicted_flow = self._flows.get(evicted_key)
                    if evicted_flow is not None:
                        evicted_flow.pop('series_id', None)
                self._flow_series[key] = collections.deque(maxlen=FLOW_SERIES_SAMPLES)
                flow['_sample_mono'] = time.monotonic()
            else:
                self._flow_series.move_to_end(key)
            flow['series_id'] = key
        else:
            flow.pop('series_id', None)

        # Keep the flow table bounded and expire silent flows without a timer thread.
        cutoff = now - FLOW_IDLE_SECONDS
        while self._flows:
            oldest_key = next(iter(self._flows))
            oldest = self._flows[oldest_key]
            if len(self._flows) <= MAX_FLOWS and float(oldest.get('last_seen') or 0) >= cutoff:
                break
            expired_key, _ = self._flows.popitem(last=False)
            self._flow_series.pop(expired_key, None)
        flow['flow_packets'] = flow['packets']
        flow['flow_bytes'] = flow['bytes']
        flow['flow_packets_per_second'] = flow['packets_per_second']
        flow['flow_bits_per_second'] = flow['bits_per_second']
        event['flow_packets'] = flow['packets']
        event['flow_bytes'] = flow['bytes']
        event['flow_packets_per_second'] = flow['packets_per_second']
        event['flow_bits_per_second'] = flow['bits_per_second']
        event['flow_seq'] = flow['flow_seq']
        event['client_label'] = flow.get('client_label') or event.get('client_ip') or 'Unattributed'

        high_value = event.get('application') in ('DNS', 'DHCP', 'ARP', 'mDNS', 'SSDP / UPnP')
        alert_sample = bool(event.get('signal')) and (now - float(flow.get('_last_emit') or 0.0) >= FLOW_SAMPLE_SECONDS)
        should_emit = new_flow or high_value or alert_sample or (now - float(flow.get('_last_emit') or 0.0) >= FLOW_SAMPLE_SECONDS)
        if should_emit:
            flow['_last_emit'] = now
        return should_emit

    def _sample_rates_locked(self, monotonic_now: float, timestamp_ns: int) -> None:
        """Take one measured interval sample for every retained flow.

        Kept separate from the worker so interval maths can be tested without
        starting capture sockets. Idle intervals are recorded as zero, preventing
        stale throughput values from remaining on screen.
        """
        utc = dt.datetime.fromtimestamp(timestamp_ns / 1_000_000_000, tz=dt.timezone.utc)
        epoch = timestamp_ns / 1_000_000_000
        utc_text = utc.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        for key, flow in list(self._flows.items()):
            previous = float(flow.get('_sample_mono') or monotonic_now)
            elapsed = monotonic_now - previous
            if elapsed <= 0:
                continue
            packets = int(flow.get('_interval_packets', 0))
            byte_count = int(flow.get('_interval_bytes', 0))
            upload_bytes = int(flow.get('_interval_upload_bytes', 0))
            download_bytes = int(flow.get('_interval_download_bytes', 0))
            unknown_bytes = int(flow.get('_interval_unknown_bytes', 0))
            upload_packets = int(flow.get('_interval_upload_packets', 0))
            download_packets = int(flow.get('_interval_download_packets', 0))
            flow['_sample_mono'] = monotonic_now
            flow['_interval_packets'] = 0
            flow['_interval_bytes'] = 0
            flow['_interval_upload_bytes'] = 0
            flow['_interval_download_bytes'] = 0
            flow['_interval_unknown_bytes'] = 0
            flow['_interval_upload_packets'] = 0
            flow['_interval_download_packets'] = 0

            flow['packets_per_second'] = round(packets / elapsed, 2)
            flow['bytes_per_second'] = round(byte_count / elapsed, 2)
            flow['bits_per_second'] = round(byte_count * 8 / elapsed, 1)
            flow['upload_bytes_per_second'] = round(upload_bytes / elapsed, 2)
            flow['download_bytes_per_second'] = round(download_bytes / elapsed, 2)
            flow['unknown_direction_bytes_per_second'] = round(unknown_bytes / elapsed, 2)
            flow['upload_packets_per_second'] = round(upload_packets / elapsed, 2)
            flow['download_packets_per_second'] = round(download_packets / elapsed, 2)
            flow['rate_sampled_at'] = epoch
            flow['rate_sampled_at_utc'] = utc_text
            flow['rate_interval_ms'] = round(elapsed * 1000, 2)

            history = self._flow_series.get(key)
            if history is not None:
                self._rate_sample_sequence += 1
                history.append({
                    'sequence': self._rate_sample_sequence,
                    'timestamp': epoch,
                    'timestamp_ns': timestamp_ns,
                    'timestamp_utc': utc_text,
                    'elapsed_seconds': round(elapsed, 6),
                    'elapsed_ms': round(elapsed * 1000, 2),
                    'packets': packets,
                    'bytes': byte_count,
                    'upload_bytes': upload_bytes,
                    'download_bytes': download_bytes,
                    'unknown_direction_bytes': unknown_bytes,
                    'upload_packets': upload_packets,
                    'download_packets': download_packets,
                    'packets_per_second': round(packets / elapsed, 2),
                    'bytes_per_second': round(byte_count / elapsed, 2),
                    'upload_bytes_per_second': round(upload_bytes / elapsed, 2),
                    'download_bytes_per_second': round(download_bytes / elapsed, 2),
                    'unknown_direction_bytes_per_second': round(unknown_bytes / elapsed, 2),
                    'upload_packets_per_second': round(upload_packets / elapsed, 2),
                    'download_packets_per_second': round(download_packets / elapsed, 2),
                    'direction_known': bool(flow.get('client_ip') and flow.get('remote_ip')),
                })

    def _rate_sampler_worker(self) -> None:
        """Sample counters once per second using actual monotonic elapsed time."""
        next_tick = time.monotonic() + FLOW_SAMPLE_SECONDS
        while not self._stop.is_set():
            if self._stop.wait(max(0.0, next_tick - time.monotonic())):
                return
            monotonic_now = time.monotonic()
            timestamp_ns = time.time_ns()
            with self._lock:
                self._sample_rates_locked(monotonic_now, timestamp_ns)
            next_tick += FLOW_SAMPLE_SECONDS
            if next_tick < monotonic_now:
                next_tick = monotonic_now + FLOW_SAMPLE_SECONDS

    def _capture_worker(self, iface: str, packet_socket: socket.socket) -> None:
        next_stats = time.monotonic() + 2.0
        try:
            while not self._stop.is_set():
                try:
                    data, address = packet_socket.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if not self._stop.is_set():
                        with self._lock:
                            self._errors.append(f'{iface}: capture socket failed: {exc}')
                    break
                packet_type = 0
                link_protocol = None
                if isinstance(address, tuple):
                    if len(address) > 2 and isinstance(address[2], int):
                        packet_type = address[2]
                    if len(address) > 1 and isinstance(address[1], int):
                        link_protocol = address[1]
                event = self._event_for(iface, packet_type, link_protocol, data)
                timestamp = event['timestamp']
                with self._lock:
                    emit_event = self._update_flow_locked(event)
                    if emit_event:
                        self._next_id += 1
                        event['id'] = self._next_id
                        if len(self._events) == self._events.maxlen:
                            self._overwritten += 1
                        self._events.append(event)
                    row = self._counts.setdefault(iface, {'packets': 0, 'bytes': 0, 'kernel_packets': 0, 'socket_drops': 0, 'socket_rcvbuf_bytes': 0})
                    row['packets'] += 1
                    row['bytes'] += len(data)
                    self._last_packet_at = timestamp
                    writer = self._writer
                if writer is not None:
                    writer.write_packet(iface, data, timestamp)
                if time.monotonic() >= next_stats:
                    self._collect_socket_stats(iface, packet_socket)
                    next_stats = time.monotonic() + 2.0
        finally:
            self._collect_socket_stats(iface, packet_socket)
            try:
                packet_socket.close()
            except OSError:
                pass

    def _collect_socket_stats(self, iface: str, packet_socket: socket.socket) -> None:
        try:
            stats = packet_socket.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            if len(stats) >= 8:
                received, dropped = struct.unpack('=II', stats[:8])
                with self._lock:
                    row = self._counts.setdefault(iface, {'packets': 0, 'bytes': 0, 'kernel_packets': 0, 'socket_drops': 0})
                    row['kernel_packets'] += received
                    row['socket_drops'] += dropped
        except OSError:
            pass

    def start(self, duration_seconds: int, interfaces: list[str],
              allowed_interfaces: dict[str, str] | None = None,
              subnets: tuple[str, ...] = DEFAULT_SUBNETS,
              save_pcap: bool = False) -> dict[str, Any]:
        if os.geteuid() != 0:
            raise PermissionError(f'Packet capture requires root privileges. Run: sudo {sbc_site.PREFIX}-admin capture start')
        if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, int) or not MIN_CAPTURE_SECONDS <= duration_seconds <= MAX_CAPTURE_SECONDS:
            raise ValueError(f'Capture duration must be between {MIN_CAPTURE_SECONDS} and {MAX_CAPTURE_SECONDS} seconds.')
        allowed_interfaces = allowed_interfaces or DEFAULT_INTERFACES
        allowed = {name for name in allowed_interfaces if re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', name)}
        if not isinstance(interfaces, list) or not interfaces or len(interfaces) > 4 or len(set(interfaces)) != len(interfaces):
            raise ValueError('Select one to four unique capture interfaces.')
        if any(not isinstance(name, str) or name not in allowed for name in interfaces):
            raise ValueError('A requested interface is not in the configured capture allowlist.')
        for name in interfaces:
            if not Path('/sys/class/net', name).exists():
                raise ValueError(f'Capture interface is not present: {name}')
        if save_pcap and duration_seconds > 300:
            raise ValueError('Full PCAPNG capture is limited to 300 seconds per session.')
        self.stop()
        if not hasattr(socket, 'AF_PACKET'):
            raise RuntimeError('Linux AF_PACKET capture is unavailable on this platform.')
        opened: list[tuple[str, socket.socket]] = []
        writer = None
        try:
            for iface in interfaces:
                packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
                packet_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_RCVBUF)
                packet_socket.settimeout(0.25)
                packet_socket.bind((iface, 0))
                opened.append((iface, packet_socket))
            if save_pcap:
                writer = PcapngWriter(interfaces)
        except OSError as exc:
            for _, packet_socket in opened:
                packet_socket.close()
            raise RuntimeError(f'Could not initialise packet capture on {iface}: {exc}') from exc
        with self._lock:
            self._events.clear()
            self._flows.clear()
            self._flow_series.clear()
            self._rate_sample_sequence = 0
            self._flow_sequence = 0
            self._next_id = 0
            self._counts = {name: {'packets': 0, 'bytes': 0, 'kernel_packets': 0, 'socket_drops': 0,
                                   'socket_rcvbuf_bytes': int(packet_socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))}
                            for name, packet_socket in opened}
            self._errors = []
            self._overwritten = 0
            self._last_packet_at = None
            self._stop = threading.Event()
            self._started_at = time.time()
            self._duration = duration_seconds
            self._stop_at = self._started_at + duration_seconds
            self._interfaces = list(interfaces)
            self._allowed_interfaces = dict(allowed_interfaces)
            self._subnets = tuple(subnets)
            self._writer = writer
            self._last_pcap_path = str(writer.path) if writer is not None else None
            self._last_pcap_bytes = 0
            self._sockets = [packet_socket for _, packet_socket in opened]
            self._active = True
        self._refresh_maps(force=True)
        self._threads = []
        for iface, packet_socket in opened:
            thread = threading.Thread(target=self._capture_worker, args=(iface, packet_socket), daemon=True, name=f'packet-{iface}')
            thread.start()
            self._threads.append(thread)
        self._threads.append(threading.Thread(target=self._conntrack_worker, daemon=True, name='packet-conntrack-refresh'))
        self._threads[-1].start()
        self._threads.append(threading.Thread(target=self._rate_sampler_worker, daemon=True, name='packet-flow-rate-sampler'))
        self._threads[-1].start()
        timer = threading.Thread(target=self._auto_stop_worker, daemon=True, name='packet-capture-expiry')
        timer.start()
        self._threads.append(timer)
        return self.snapshot(after=0, limit=0)

    def _auto_stop_worker(self) -> None:
        while not self._stop.is_set():
            remaining = (self._stop_at or 0) - time.time()
            if remaining <= 0:
                self.stop()
                return
            if self._stop.wait(min(remaining, 1.0)):
                return

    def stop(self) -> dict[str, Any]:
        with self._lock:
            was_active = self._active
            self._active = False
            self._stop.set()
            sockets = list(self._sockets)
            threads = list(self._threads)
            self._sockets.clear()
            writer = self._writer
            self._writer = None
        for packet_socket in sockets:
            try:
                packet_socket.close()
            except OSError:
                pass
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=0.5)
        if was_active:
            with self._lock:
                self._sample_rates_locked(time.monotonic(), time.time_ns())
        if writer is not None:
            writer.close()
            with self._lock:
                self._last_pcap_bytes = writer.size
        return {'ok': True, 'stopped': was_active, 'capture': self.snapshot(after=0, limit=0)['capture']}

    def snapshot(self, after: int = 0, limit: int = 200,
                 series_id: str | None = None) -> dict[str, Any]:
        if isinstance(after, bool) or not isinstance(after, int) or after < 0:
            after = 0
        if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= 250:
            limit = 200
        with self._lock:
            events = [dict(row) for row in self._events if row['id'] > after][:limit] if limit else []
            flows = []
            for row in reversed(self._flows.values()):
                clean = {key: value for key, value in row.items() if not key.startswith('_')}
                flows.append(clean)
                if len(flows) >= 100:
                    break
            series_options = []
            for key in reversed(self._flow_series):
                flow = self._flows.get(key)
                if not flow:
                    continue
                series_options.append({
                    'series_id': key,
                    'client_label': flow.get('client_label') or flow.get('client_ip') or 'Unattributed',
                    'client_ip': flow.get('client_ip'),
                    'remote_ip': flow.get('remote_ip'),
                    'remote_port': flow.get('remote_port'),
                    'domain': flow.get('domain'),
                    'protocol': flow.get('protocol'),
                    'interface': flow.get('interface'),
                    'last_seen': flow.get('last_seen'),
                })
            selected_series = None
            if isinstance(series_id, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', series_id):
                history = self._flow_series.get(series_id)
                if history is not None:
                    selected_series = {
                        'series_id': series_id,
                        'samples': [dict(sample) for sample in history],
                        'sample_count': len(history),
                        'capacity': FLOW_SERIES_SAMPLES,
                        'sample_interval_seconds': FLOW_SAMPLE_SECONDS,
                        'measurement_clock': 'monotonic elapsed interval; wall-clock UTC timestamp',
                    }
            writer = self._writer
            capture = {
                'active': self._active,
                'started_at': self._started_at,
                'stop_at': self._stop_at,
                'duration_seconds': self._duration,
                'interfaces': list(self._interfaces),
                'counts': {key: dict(value) for key, value in self._counts.items()},
                'errors': list(self._errors[-8:]),
                'ring_capacity': self._events.maxlen,
                'ring_size': len(self._events),
                'overwritten_events': self._overwritten,
                'last_packet_at': self._last_packet_at,
                'last_event_id': self._next_id,
                'flow_count': len(self._flows),
                'flow_sequence': self._flow_sequence,
                'flow_series_count': len(self._flow_series),
                'flow_series_capacity': MAX_FLOW_SERIES,
                'rate_sample_sequence': self._rate_sample_sequence,
                'mode': 'flow-aggregated metadata+optional-pcapng',
                'payload_retained_in_memory': False,
                'pcapng_enabled': writer is not None,
                'pcapng_path': str(writer.path) if writer is not None else self._last_pcap_path,
                'pcapng_bytes': writer.size if writer is not None else self._last_pcap_bytes,
                'pcapng_limit_reached': writer.full if writer is not None else False,
                'conntrack_available': self._conntrack_path.exists(),
            }
            return {'ok': True, 'capture': capture, 'events': events, 'flows': flows,
                    'flow_series_options': series_options, 'flow_series': selected_series}


def _run_readonly(args: list[str], timeout: int = 5) -> str:
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=timeout, check=False,
                                env={**os.environ, 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        return result.stdout[:24000] if result.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def adapter_inventory(interfaces: dict[str, str] | None = None) -> dict[str, Any]:
    """Read driver, link, Wi-Fi PHY and offload capabilities without changing them."""
    interfaces = interfaces or DEFAULT_INTERFACES
    wireless_raw = _run_readonly(['/usr/sbin/iw', 'dev']) or _run_readonly(['/usr/bin/iw', 'dev'])
    wireless: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for line in wireless_raw.splitlines():
        match = re.match(r'\s*Interface\s+(\S+)', line)
        if match:
            current = match.group(1)
            wireless[current] = {'phy': None, 'type': None, 'channel': None, 'tx_power_dbm': None}
        if current:
            if match := re.search(r'\bwiphy\s+(\d+)', line):
                wireless[current]['phy'] = f'phy{match.group(1)}'
            if match := re.search(r'\btype\s+(\S+)', line):
                wireless[current]['type'] = match.group(1)
            if match := re.search(r'channel\s+(\d+)\s+\((\d+)\s+MHz\)', line):
                wireless[current]['channel'] = {'number': int(match.group(1)), 'mhz': int(match.group(2))}
            if match := re.search(r'txpower\s+([0-9.]+)\s+dBm', line):
                wireless[current]['tx_power_dbm'] = float(match.group(1))
    phys: dict[str, dict[str, Any]] = {}
    for phy in sorted({item.get('phy') for item in wireless.values()} - {None}):
        raw = _run_readonly(['/usr/sbin/iw', 'phy', phy, 'info']) or _run_readonly(['/usr/bin/iw', 'phy', phy, 'info'])
        supported: list[str] = []
        in_modes = False
        combinations = []
        in_combinations = False
        for line in raw.splitlines():
            stripped = line.strip()
            if 'Supported interface modes:' in line:
                in_modes = True
                in_combinations = False
                continue
            if 'valid interface combinations:' in line:
                in_modes = False
                in_combinations = True
                continue
            if in_modes:
                mode = re.search(r'\*\s*(.+)', stripped)
                if mode:
                    supported.append(mode.group(1))
                elif stripped and not stripped.startswith('*'):
                    in_modes = False
            if in_combinations and stripped:
                combinations.append(stripped[:240])
                if len(combinations) >= 12:
                    in_combinations = False
        phys[phy] = {
            'supported_modes': supported,
            'monitor_mode_supported': 'monitor' in [x.lower() for x in supported],
            'ap_mode_supported': 'AP' in supported,
            'interface_combinations': combinations,
            'phy_info_available': bool(raw),
        }
    rows = []
    for name, label in interfaces.items():
        if not Path('/sys/class/net', name).exists():
            rows.append({'interface': name, 'label': label, 'present': False})
            continue
        driver_link = Path('/sys/class/net', name, 'device/driver')
        try:
            driver = driver_link.resolve().name
        except OSError:
            driver = None
        try:
            address = Path('/sys/class/net', name, 'address').read_text().strip().lower()
        except OSError:
            address = None
        try:
            operstate = Path('/sys/class/net', name, 'operstate').read_text().strip()
        except OSError:
            operstate = 'unknown'
        info: dict[str, Any] = {
            'interface': name, 'label': label, 'present': True,
            'driver': driver, 'mac': address, 'state': operstate,
        }
        if name in wireless:
            info['wireless'] = wireless[name]
            phy = wireless[name].get('phy')
            if phy in phys:
                info['phy_capabilities'] = phys[phy]
                info['monitor_concurrent_with_ap'] = any(
                    'monitor' in text.lower() and re.search(r'\bAP\b', text) for text in phys[phy]['interface_combinations']
                )
        driver_info = _run_readonly(['/usr/sbin/ethtool', '-i', name]) or _run_readonly(['/usr/bin/ethtool', '-i', name])
        if driver_info:
            info['ethtool_driver'] = {k: v for k, v in (line.split(':', 1) for line in driver_info.splitlines() if ':' in line)}
        features = _run_readonly(['/usr/sbin/ethtool', '-k', name]) or _run_readonly(['/usr/bin/ethtool', '-k', name])
        if features:
            info['offload_features'] = [line.strip() for line in features.splitlines()[1:80] if line.strip()]
        statistics = _run_readonly(['/usr/sbin/ethtool', '-S', name]) or _run_readonly(['/usr/bin/ethtool', '-S', name])
        if statistics:
            info['hardware_statistics'] = [line.strip() for line in statistics.splitlines()[1:61] if line.strip()]
        rows.append(info)
    return {
        'ok': True,
        'interfaces': rows,
        'wireless_phy_count': len(phys),
        'monitor_mode_note': 'Monitor-mode capability is reported only; no radio is switched. Concurrent monitor+AP operation depends on the PHY interface-combination rules and driver stability.',
        'capture_note': 'Routed IP capture works without monitor mode. Radio monitor mode sees 802.11 management/control frames and may disrupt an AP; encrypted Wi-Fi payloads are not automatically decrypted.',
    }


capture_manager = PacketMonitor()
