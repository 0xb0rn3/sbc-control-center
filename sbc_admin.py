#!/usr/bin/env python3
"""Direct, allow-listed administration over SSH or a local TTY (installed as <prefix>-admin)."""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

import dns_filter
import device_intelligence
import network_discovery
import sbc_site


VERSION_FILE = sbc_site.APP_DIR / 'VERSION'
AGENT_SOCKET = sbc_site.SOCKET_PATH
_SITE = sbc_site.load()
AP_IFACES = tuple(sbc_site.ap_interfaces(_SITE))
CAPTURE_IFACES = (*AP_IFACES, _SITE['vpn_interface'], _SITE['uplink_interface'])
DEFAULT_CAPTURE_INTERFACES = ','.join(CAPTURE_IFACES)
PROG = f'{sbc_site.PREFIX}-admin'


def _agent_request(payload: dict[str, Any], timeout: float = 20.0) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise PermissionError(f'Run this command with sudo: sudo {PROG} ...')
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(AGENT_SOCKET))
        client.sendall((json.dumps(payload, separators=(',', ':')) + '\n').encode('utf-8'))
        chunks = bytearray()
        while b'\n' not in chunks and len(chunks) < 1_900_000:
            part = client.recv(65536)
            if not part:
                break
            chunks.extend(part)
        if not chunks:
            raise RuntimeError('Control agent returned no response.')
        result = json.loads(bytes(chunks).split(b'\n', 1)[0].decode('utf-8'))
        if not isinstance(result, dict):
            raise RuntimeError('Control agent returned an invalid response.')
        return result
    finally:
        client.close()


def _print_result(result: dict[str, Any]) -> int:
    if not result.get('ok'):
        print(result.get('error') or result.get('message') or 'Operation failed.', file=sys.stderr)
        return 1
    if result.get('capture'):
        capture = result['capture']
        print(f"Capture active: {'yes' if capture.get('active') else 'no'}")
        print(f"Interfaces: {', '.join(capture.get('interfaces') or []) or 'none'}")
        print(f"Duration: {capture.get('duration_seconds', 0)} seconds")
        print(f"PCAPNG: {capture.get('pcapng_path') or 'metadata-only'}")
        print(f"Events retained: {capture.get('ring_size', 0)} / {capture.get('ring_capacity', 0)}")
        print(f"Active flows: {capture.get('flow_count', 0)} · flow samples: {capture.get('flow_sequence', 0)}")
        for interface, counts in (capture.get('counts') or {}).items():
            drops = int(counts.get('socket_drops', 0) or 0)
            packets = int(counts.get('packets', 0) or 0)
            drop_pct = 100.0 * drops / max(1, packets + drops)
            print(f"  {interface}: {packets:,} packets, {int(counts.get('bytes', 0) or 0):,} bytes, socket drops {drops:,} ({drop_pct:.2f}%), receive buffer {int(counts.get('socket_rcvbuf_bytes', 0) or 0):,} bytes")
    elif 'wireless' in result:
        wireless = result.get('wireless') or {}
        print(f"Wireless inspection available: {'yes' if wireless.get('available') else 'no'}")
        interface_rows = (result.get('interfaces') or {}).get('interfaces', [])
        interface_by_name = {item.get('interface'): item for item in interface_rows if item.get('interface')}
        for row in wireless.get('adapters', []):
            name = row.get('name')
            extra = interface_by_name.get(name, {})
            print(f"\n{name} · {row.get('model') or row.get('usb_id') or 'unknown adapter'}")
            print(f"  Driver: {row.get('driver') or extra.get('driver') or 'unknown'} · PHY: {row.get('phy') or 'unknown'} · State: {row.get('state') or extra.get('state') or 'unknown'}")
            caps = row.get('phy_capabilities') or {}
            print(f"  Monitor mode: {caps.get('monitor_mode_supported', row.get('monitor_mode_supported', 'unknown'))}")
            print(f"  AP+monitor concurrent: {row.get('ap_monitor_concurrent', 'unknown')} · Same-channel-only: {row.get('monitor_same_channel_only', 'unknown')}")
            print(f"  Channel: {row.get('channel') or 'unknown'} · Radio stations: {len(row.get('stations') or [])}")
            for station in (row.get('stations') or [])[:24]:
                print(f"    {station.get('mac', 'unknown MAC')}  signal={station.get('signal', 'n/a')} dBm  tx={station.get('tx_bitrate', 'n/a')}  rx={station.get('rx_bitrate', 'n/a')}")
            for survey in (row.get('survey') or [])[:4]:
                print(f"  Survey: frequency={survey.get('frequency_mhz', 'n/a')} MHz  noise={survey.get('noise_dbm', 'n/a')} dBm  active={survey.get('active_ms', 'n/a')} ms  busy={survey.get('busy_ms', 'n/a')} ms")
            phy = extra.get('phy_capabilities') or {}
            if phy:
                print(f"  Supported modes: {', '.join(phy.get('supported_modes') or []) or 'not reported'}")
                print(f"  Interface combinations: {'; '.join(phy.get('interface_combinations') or []) or 'not reported'}")
        for row in interface_rows:
            if not row.get('present'):
                print(f"\n{row.get('interface')}: not present")
                continue
            print(f"\n{row.get('interface')} · {row.get('label') or 'network interface'} · {row.get('driver') or 'driver unknown'} · {row.get('state') or 'unknown'}")
            features = row.get('offload_features') or []
            stats = row.get('hardware_statistics') or []
            driver_info = row.get('ethtool_driver') or {}
            if driver_info:
                print('  ethtool driver: ' + ', '.join(f'{key}={value}' for key, value in list(driver_info.items())[:8]))
            print(f"  Offload capabilities: {len(features)} reported; hardware counters: {len(stats)} reported")
            for feature in features[:16]:
                print(f"    {feature}")
            for counter in stats[:12]:
                print(f"    {counter}")
        print('\n' + str(wireless.get('note') or ''))
        print(str((result.get('interfaces') or {}).get('capture_note') or ''))
    elif result.get('data'):
        data = result['data']
        for ap in data.get('aps', []):
            for device in ap.get('clients', []):
                print(f"{device.get('identity_label') or device.get('hostname') or 'Unknown'}\t{device.get('ip') or '-'}\t{device.get('mac') or '-'}\t{device.get('mac_vendor') or 'Vendor unknown'}\t{device.get('device_type') or 'Unknown type'}\t{device.get('identity_confidence') or 'low'}")
                evidence = ', '.join(device.get('identity_evidence') or [])
                if device.get('radio') or device.get('signal'):
                    print(f"  radio={device.get('radio') or '-'} signal={device.get('signal') or '-'} tx={device.get('tx_bitrate') or '-'} rx={device.get('rx_bitrate') or '-'}")
                if device.get('passive_os'):
                    print(f"  passive TCP/IP OS: {device.get('passive_os')} · confidence={device.get('passive_os_confidence', 'medium')} · source=p0f")
                if evidence:
                    print(f"  evidence: {evidence}")
                if device.get('mac_vendor_status'):
                    print(f"  vendor lookup: {device.get('mac_vendor_status')}")
    else:
        print(result.get('message') or json.dumps(result, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=PROG, description='Safe, allow-listed administration over SSH or local TTY.')
    parser.add_argument('--version', action='version', version=PROG + ' ' + (VERSION_FILE.read_text().strip() if VERSION_FILE.exists() else 'source-tree'))
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('help', help='Show this command reference')
    sub.add_parser('status', help='Show DNS filtering status (requires sudo)')
    dns = sub.add_parser('dns', help='Manage DNS protection')
    dns_sub = dns.add_subparsers(dest='dns_command', required=True)
    dns_sub.add_parser('status', help='Show AdGuard Home and active profile state')
    dns_sub.add_parser('profiles', help='List available filtering profiles')
    profile = dns_sub.add_parser('profile', help='Apply a filtering profile (requires sudo)')
    profile.add_argument('name', choices=sorted(dns_filter.PROFILES))
    dns_sub.add_parser('validate', help='Run read-only configuration preflight')
    dns_sub.add_parser('rollback', help='Restore the latest DNS configuration backup (requires sudo)')

    capture = sub.add_parser('capture', help='Live packet inspection')
    capture_sub = capture.add_subparsers(dest='capture_command', required=True)
    capture_sub.add_parser('status', help='Show current capture state')
    events = capture_sub.add_parser('events', help='Print recent DNS, identity and review events')
    events.add_argument('--after', type=int, default=0, help='Return events with an ID greater than this value')
    events.add_argument('--limit', type=int, default=100, help='Maximum events to print (1–250)')
    flows = capture_sub.add_parser('flows', help='Show aggregated live flow counters by device and interface')
    flows.add_argument('--limit', type=int, default=50, help='Maximum flow rows to print (1–100)')
    flows.add_argument('--interface', choices=('all', *CAPTURE_IFACES), default='all')
    watch = capture_sub.add_parser('watch', help='Stream sampled flow changes and high-value packet events to this SSH/TTY terminal')
    watch.add_argument('--interval', type=float, default=1.0, help='Polling interval in seconds (0.5–5)')
    start = capture_sub.add_parser('start', help='Start a bounded capture (requires sudo)')
    start.add_argument('--seconds', type=int, default=60, help='Capture duration, 10-600 seconds')
    start.add_argument('--interfaces', default=DEFAULT_CAPTURE_INTERFACES, help='Comma-separated approved interfaces')
    start.add_argument('--pcap', action='store_true', help='Save full packets to a root-only, size-limited PCAPNG file')
    capture_sub.add_parser('stop', help='Stop active capture')
    capture_sub.add_parser('tools', help='Show packet-analysis tool availability')
    capture_sub.add_parser('analyze', help='Run bounded TShark analysis on the last saved PCAPNG')

    adapters = sub.add_parser('adapters', help='Inspect wireless adapter capabilities')
    adapters_sub = adapters.add_subparsers(dest='adapters_command', required=True)
    adapters_sub.add_parser('status', help='Show chipset, driver, PHY, monitor/AP combinations and station stats')

    oui = sub.add_parser('oui', help='Local IEEE MAC vendor registry')
    oui_sub = oui.add_subparsers(dest='oui_command', required=True)
    oui_sub.add_parser('update', help='Download official IEEE MA-L/MA-M/MA-S registries (no client MAC upload)')

    devices = sub.add_parser('devices', help='Device discovery and manual identity labels')
    devices_sub = devices.add_subparsers(dest='devices_command', required=True)
    devices_sub.add_parser('list', help='List discovered devices and identity evidence')
    devices_sub.add_parser('tools', help='Show optional third-party discovery tool availability')
    device_watch = devices_sub.add_parser('watch', help='Stream new passive ARP and p0f identity events to this SSH/TTY terminal')
    device_watch.add_argument('--interval', type=float, default=1.0, help='Polling interval in seconds (0.5–5)')
    device_events = devices_sub.add_parser('events', help='Show recent passive ARP and TCP/IP fingerprint events')
    device_events.add_argument('--limit', type=int, default=20, help='Maximum events to show (1–50)')
    scan = devices_sub.add_parser('scan', help='Run a rate-limited ARP discovery sweep on a configured AP (requires sudo)')
    scan.add_argument('--interface', choices=('both', *AP_IFACES), default='both')
    fingerprint = devices_sub.add_parser('fingerprint', help='Estimate one device OS on a configured AP (requires sudo)')
    fingerprint.add_argument('ip')
    label = devices_sub.add_parser('label', help='Set a trusted manual device label (requires sudo)')
    label.add_argument('mac')
    label.add_argument('name')
    unlabel = devices_sub.add_parser('unlabel', help='Remove a manual device label (requires sudo)')
    unlabel.add_argument('mac')

    args = parser.parse_args(argv)
    if args.command == 'help':
        parser.print_help()
        print('\nExamples:')
        print(f'  sudo {PROG} dns status')
        print(f'  sudo {PROG} dns profile aggressive')
        print(f'  sudo {PROG} capture start --seconds 60')
        print(f'  sudo {PROG} capture start --seconds 30 --pcap')
        print(f'  sudo {PROG} capture status')
        print(f'  sudo {PROG} capture events --limit 100')
        print(f'  sudo {PROG} capture flows --limit 50')
        print(f'  sudo {PROG} capture watch --interval 0.5')
        print(f'  sudo {PROG} capture stop')
        print(f'  sudo {PROG} adapters status')
        print(f'  sudo {PROG} dns validate')
        print(f'  sudo {PROG} devices list')
        print(f'  sudo {PROG} devices tools')
        print(f'  sudo {PROG} devices events --limit 20')
        print(f'  sudo {PROG} devices scan')
        print(f'  sudo {PROG} devices scan --interface wlan0')
        print(f'  sudo {PROG} devices fingerprint ' + str(__import__("ipaddress").ip_network(_SITE["ap2_subnet"])[25]))
        print(f'  sudo {PROG} oui update')
        print(f'  sudo {PROG} devices label aa:bb:cc:dd:ee:ff "Living room TV"')
        print('\nPCAPNG contains packet payload bytes. Treat it as sensitive data and copy it securely.')
        return 0

    if args.command == 'dns':
        if args.dns_command == 'profiles':
            for item in dns_filter.available_profiles():
                print(f"{item['id']:<12} {item['title']}: {item['description']}")
            return 0
        if os.geteuid() != 0:
            print(f'Run this command with sudo: sudo {PROG} dns ' + args.dns_command + ((' ' + args.name) if args.dns_command == 'profile' else ''), file=sys.stderr)
            return 2
        if args.dns_command == 'status':
            result = dns_filter.status()
        elif args.dns_command == 'validate':
            result = dns_filter.validate()
        elif args.dns_command == 'profile':
            result = dns_filter.apply_profile(args.name)
        elif args.dns_command == 'rollback':
            result = dns_filter.rollback()
        else:
            parser.error('Unsupported DNS command')
        dns_state = result.get('dns') if isinstance(result, dict) else None
        if isinstance(dns_state, dict):
            print(f"AdGuard installed: {'yes' if dns_state.get('installed') else 'no'}")
            print(f"Service: {dns_state.get('service_state', 'unknown')}")
            print(f"Profile: {dns_state.get('profile', 'not configured')}")
            print(f"DNS listeners: {', '.join(dns_state.get('dns_listeners', []))}")
            print(f"Upstream: {dns_state.get('upstream', 'unknown')}")
        else:
            print(result.get('message') or result.get('error') or result)
        return 0 if result.get('ok') else 1

    if args.command == 'oui':
        if os.geteuid() != 0:
            print(f'Run this command with sudo: sudo {PROG} oui update', file=sys.stderr)
            return 2
        result = device_intelligence.update_vendor_database()
        print(result.get('message') or json.dumps(result, indent=2))
        for registry, count in (result.get('registries') or {}).items():
            print(f'  {registry}: {count:,} assignments')
        return 0 if result.get('ok') else 1

    if args.command == 'status':
        return _print_result(_agent_request({'action': 'dns_status'}))
    if args.command == 'capture':
        if args.capture_command == 'tools':
            result = _agent_request({'action': 'packet_tools'}, timeout=8)
            for item in result.get('tools', []):
                print(f"{'[+] ' if item.get('available') else '[-] '}{item.get('name')}: {item.get('version') or 'not installed'} · {item.get('purpose')}")
            return 0 if result.get('ok') else 1
        if args.capture_command == 'analyze':
            result = _agent_request({'action': 'packet_analysis'}, timeout=22)
            if not result.get('ok'):
                print(result.get('error') or 'TShark analysis failed.', file=sys.stderr)
                return 1
            capture = result.get('capture', {})
            print(f"TShark analysed {capture.get('analysed_packets', 0):,} packets from {capture.get('name')} in {result.get('duration_ms')} ms")
            print('Protocols:')
            for row in result.get('protocols', []): print(f"  {row['name']}: {row['frames']:,}")
            print('Top endpoints:')
            for row in result.get('endpoints', [])[:12]: print(f"  {row['endpoint']}: {row['frames']:,}")
            print('DNS:')
            for row in result.get('dns_queries', [])[:15]: print(f"  {row['name']}: {row['count']:,}")
            print('TLS SNI:')
            for row in result.get('tls_hosts', [])[:15]: print(f"  {row['name']}: {row['count']:,}")
            print('Expert diagnostics:')
            for row in result.get('expert', [])[:15]: print(f"  {row['message']}: {row['count']:,}")
            print(result.get('privacy', ''))
            return 0
        if args.capture_command == 'status':
            return _print_result(_agent_request({'action': 'packet_snapshot', 'after': 0, 'limit': 0}))
        if args.capture_command == 'events':
            if args.after < 0 or not 1 <= args.limit <= 250:
                parser.error('capture events requires --after >= 0 and --limit between 1 and 250')
            result = _agent_request({'action': 'packet_snapshot', 'after': args.after, 'limit': args.limit})
            if not result.get('ok'):
                print(result.get('error') or 'Could not retrieve packet events.', file=sys.stderr)
                return 1
            for event in result.get('events', []):
                stamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event.get('timestamp', 0)))
                client = event.get('client_label') or 'Unattributed'
                client_ip = event.get('client_ip') or '?'
                client_mac = event.get('client_mac') or '?'
                remote = event.get('remote_ip') or event.get('destination_ip') or '—'
                port = event.get('remote_port') or event.get('destination_port') or event.get('source_port')
                domain = event.get('domain') or event.get('dns_query') or event.get('tls_sni') or '—'
                point = event.get('interface') or event.get('path') or 'unknown'
                signal = f" | REVIEW: {event['signal']}" if event.get('signal') else ''
                totals = f" | flow={int(event.get('flow_packets') or 1):,}pkt/{int(event.get('flow_bytes') or event.get('bytes') or 0):,}B"
                print(f"{stamp} | {client} [{client_ip} {client_mac}] | {remote}{':' + str(port) if port else ''} | {event.get('protocol', 'OTHER')} {event.get('application', '')} | {domain} | {point}{totals}{signal}")
            return 0
        if args.capture_command == 'flows':
            if not 1 <= args.limit <= 100:
                parser.error('capture flows --limit must be between 1 and 100')
            result = _agent_request({'action': 'packet_snapshot', 'after': 0, 'limit': 0}, timeout=8)
            if not result.get('ok'):
                print(result.get('error') or 'Could not retrieve packet flows.', file=sys.stderr)
                return 1
            rows = [row for row in result.get('flows', []) if args.interface == 'all' or row.get('interface') == args.interface]
            rows.sort(key=lambda row: (int(row.get('packets') or 0), float(row.get('last_seen') or 0)), reverse=True)
            print('DEVICE / CLIENT | REMOTE | PROTOCOL | DOMAIN | PACKETS / BYTES | RATE | INTERFACE')
            for row in rows[:args.limit]:
                client = row.get('client_label') or 'Unattributed'
                client_ip = row.get('client_ip') or '?'
                client_mac = row.get('client_mac') or '?'
                remote = row.get('remote_ip') or '?'
                port = row.get('remote_port')
                domain = row.get('domain') or '—'
                packets = int(row.get('packets') or 0)
                size = int(row.get('bytes') or 0)
                pps = float(row.get('packets_per_second') or 0)
                mbps = float(row.get('bits_per_second') or 0) / 1_000_000
                print(f"{client} [{client_ip} {client_mac}] | {remote}{':' + str(port) if port else ''} | {row.get('protocol', '?')} {row.get('application', '')} | {domain} | {packets:,} / {size:,} B | {pps:.1f} pkt/s {mbps:.3f} Mbit/s | {row.get('interface', '?')}")
                if row.get('signal'):
                    print(f"  REVIEW: {row['signal']}")
            print(f"\nShowing {min(len(rows), args.limit)} of {len(rows)} retained flows.")
            return 0
        if args.capture_command == 'watch':
            if not 0.5 <= args.interval <= 5.0:
                parser.error('capture watch --interval must be between 0.5 and 5 seconds')
            cursor = 0
            print('Watching packet metadata. Press Ctrl-C to stop viewing; the bounded capture continues until its timer expires or you run capture stop.')
            try:
                while True:
                    result = _agent_request({'action': 'packet_snapshot', 'after': cursor, 'limit': 250}, timeout=8)
                    if not result.get('ok'):
                        print(result.get('error') or 'Packet monitor unavailable.', file=sys.stderr)
                        return 1
                    for event in result.get('events', []):
                        cursor = max(cursor, int(event.get('id') or 0))
                        stamp = time.strftime('%H:%M:%S', time.localtime(event.get('timestamp', 0)))
                        client = event.get('client_label') or 'Unattributed'
                        client_ip = event.get('client_ip') or '?'
                        client_mac = event.get('client_mac') or '?'
                        remote = event.get('remote_ip') or event.get('destination_ip') or '—'
                        port = event.get('remote_port') or event.get('destination_port') or event.get('source_port')
                        domain = event.get('domain') or event.get('dns_query') or event.get('tls_sni') or '—'
                        point = event.get('interface') or event.get('path') or 'unknown'
                        packets = int(event.get('flow_packets') or 1)
                        size = int(event.get('flow_bytes') or event.get('bytes') or 0)
                        pps = float(event.get('flow_packets_per_second') or 0)
                        mbps = float(event.get('flow_bits_per_second') or 0) / 1_000_000
                        signal = f" | REVIEW: {event['signal']}" if event.get('signal') else ''
                        print(f"{stamp} | {client} [{client_ip} {client_mac}] | {remote}{':' + str(port) if port else ''} | {event.get('protocol', 'OTHER')} {event.get('application', '')} | {domain} | {packets:,} pkt / {size:,} B · {pps:.1f} pkt/s · {mbps:.3f} Mbit/s | {point}{signal}", flush=True)
                    if not result.get('capture', {}).get('active'):
                        print('Capture is no longer active.')
                        break
                    time.sleep(args.interval)
            except KeyboardInterrupt:
                print('Stopped viewing. The packet capture remains active until its configured timeout or an explicit stop.')
            return 0
        if args.capture_command == 'stop':
            return _print_result(_agent_request({'action': 'packet_stop'}))
        interfaces = [item.strip() for item in args.interfaces.split(',') if item.strip()]
        request = {'action': 'packet_start', 'interfaces': interfaces,
                   'duration_seconds': args.seconds, 'save_pcap': bool(args.pcap)}
        return _print_result(_agent_request(request, timeout=30))
    if args.command == 'adapters':
        return _print_result(_agent_request({'action': 'adapter_status'}, timeout=20))
    if args.command == 'devices':
        if args.devices_command == 'list':
            return _print_result(_agent_request({'action': 'status'}, timeout=30))
        if args.devices_command == 'watch':
            if not 0.5 <= args.interval <= 5.0:
                parser.error('devices watch --interval must be between 0.5 and 5 seconds')
            initial = _agent_request({'action': 'device_discovery_events', 'limit': 50}, timeout=5)
            if not initial.get('ok'):
                print(initial.get('error') or 'Could not start passive device watch.', file=sys.stderr)
                return 1
            seen = {(str(event.get('timestamp') or ''), str(event.get('unit') or ''), str(event.get('message') or ''))
                    for event in initial.get('events', [])}
            print('Watching passive device identity events. Press Ctrl-C to stop.')
            try:
                while True:
                    time.sleep(args.interval)
                    result = _agent_request({'action': 'device_discovery_events', 'limit': 50}, timeout=5)
                    if not result.get('ok'):
                        print(result.get('error') or 'Passive device event query failed.', file=sys.stderr)
                        return 1
                    fresh = []
                    for event in result.get('events', []):
                        key = (str(event.get('timestamp') or ''), str(event.get('unit') or ''), str(event.get('message') or ''))
                        if key not in seen:
                            seen.add(key)
                            fresh.append(event)
                    if len(seen) > 512:
                        seen = set(list(seen)[-256:])
                    for event in reversed(fresh):
                        stamp = event.get('timestamp') or ''
                        unit = event.get('unit') or 'passive watcher'
                        print(f"{stamp} | {unit} | {event.get('message', '')}", flush=True)
            except KeyboardInterrupt:
                print('Stopped passive device watch.')
            return 0
        if args.devices_command == 'tools':
            inventory = network_discovery.tool_inventory()
            for tool in inventory.get('tools', []):
                state = 'installed' if tool.get('installed') else 'not installed'
                print(f"{tool['name']:<14} {state:<14} {tool.get('mode', '')} · {tool.get('purpose', '')}")
            for interface, installed in (inventory.get('arpwatch_units_installed') or {}).items():
                active = (inventory.get('arpwatch_units_active') or {}).get(interface, False)
                print(f"arpwatch {interface}: {'active' if active else 'unit installed' if installed else 'not installed'}")
            for interface, installed in (inventory.get('p0f_units_installed') or {}).items():
                active = (inventory.get('p0f_units_active') or {}).get(interface, False)
                print(f"p0f {interface}: {'active' if active else 'unit installed' if installed else 'not installed'}")
            print(inventory.get('identity_policy', ''))
            return 0
        if args.devices_command == 'events':
            if not 1 <= args.limit <= 50:
                parser.error('devices events --limit must be between 1 and 50')
            result = _agent_request({'action': 'device_discovery_events', 'limit': args.limit}, timeout=5)
            if not result.get('ok'):
                print(result.get('error') or 'Could not retrieve discovery events.', file=sys.stderr)
                return 1
            events = result.get('events') or []
            if not events:
                print('No recent passive device events. Confirm the optional arpwatch and p0f units are installed and running.')
            for event in events:
                stamp = event.get('timestamp') or ''
                unit = event.get('unit') or 'arpwatch'
                print(f"{stamp} | {unit} | {event.get('message', '')}")
            return 0
        if args.devices_command == 'scan':
            if os.geteuid() != 0:
                print(f'Run this command with sudo: sudo {PROG} devices scan', file=sys.stderr)
                return 2
            interfaces = list(AP_IFACES) if args.interface == 'both' else [args.interface]
            result = _agent_request({'action': 'device_scan', 'interfaces': interfaces}, timeout=45)
            if not result.get('ok'):
                print(result.get('error') or 'Device scan failed.', file=sys.stderr)
                return 1
            print(result.get('message') or f"Found {result.get('devices_found', 0)} device(s).")
            for network in result.get('networks', []):
                print(f"\n{network.get('network_label')} · {network.get('subnet')} · {network.get('duration_seconds')}s")
                for device in network.get('devices', []):
                    print(f"  {device.get('ip', '-'):16} {device.get('mac', '-'):17} {device.get('identity_label') or device.get('hostname') or 'Unknown'} · {device.get('mac_vendor') or 'vendor unknown'} · {device.get('device_type') or 'unknown type'}")
            print('Note: sleeping devices may not respond; MAC vendor means IEEE address-block owner, not confirmed device maker.')
            return 0
        if args.devices_command == 'fingerprint':
            if os.geteuid() != 0:
                print(f'Run this command with sudo: sudo {PROG} devices fingerprint {args.ip}', file=sys.stderr)
                return 2
            result = _agent_request({'action': 'device_fingerprint', 'ip': args.ip}, timeout=25)
            if not result.get('ok'):
                print(result.get('error') or 'Device fingerprint failed.', file=sys.stderr)
                return 1
            print(f"Target: {result.get('ip')} · Interface: {result.get('interface')} · Tool: {result.get('tool', 'nmap')}")
            if not result.get('matches'):
                print(result.get('note') or 'No OS match returned.')
            for match in result.get('matches', []):
                print(f"  {match.get('name')} · Nmap match confidence {match.get('accuracy_percent')}%")
                for cls in match.get('classes', []):
                    print(f"    {cls.get('vendor') or 'vendor unknown'} / {cls.get('os_family') or 'OS unknown'} / {cls.get('os_generation') or 'generation unknown'} / {cls.get('device_type') or 'type unknown'}")
            print(result.get('note') or '')
            return 0
        if args.devices_command == 'label':
            return _print_result(_agent_request({'action': 'device_label', 'mac': args.mac, 'label': args.name}))
        if args.devices_command == 'unlabel':
            return _print_result(_agent_request({'action': 'device_unlabel', 'mac': args.mac}))
    parser.error('Unsupported command')
    return 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (PermissionError, RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'{PROG}: {exc}', file=sys.stderr)
        raise SystemExit(1)
