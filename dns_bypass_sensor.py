#!/usr/bin/env python3
"""Passive DNS-bypass indicators from packet metadata, never packet verdicts."""
from __future__ import annotations

import datetime as dt
import ipaddress
import time
from typing import Any

DOH_HOSTS = frozenset({
    'dns.google', 'cloudflare-dns.com', 'mozilla.cloudflare-dns.com',
    'security.cloudflare-dns.com', 'family.cloudflare-dns.com', 'dns.quad9.net',
    'dns10.quad9.net', 'dns.adguard-dns.com', 'family.adguard-dns.com',
    'dns.nextdns.io', 'doh.mullvad.net', 'dns.mullvad.net',
    'doh.opendns.com', 'doh.cleanbrowsing.org', 'dns0.eu',
    'doh.dns.apple.com', 'doh-dns-apple-com.v.aaplimg.com',
})
DOH_DISCOVERY_HOSTS = frozenset({'doh.dns.apple.com', 'doh-dns-apple-com.v.aaplimg.com'})


def _address(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def classify_event(
    packet: dict[str, Any], *,
    local_dns_addresses: set[str] | frozenset[str] = frozenset(),
    configured_upstreams: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any] | None:
    """Return an attempt/indicator event; enforcement outcome is always unknown."""
    if not isinstance(packet, dict) or not str(packet.get('path') or '').startswith('AP'):
        return None
    client_ip, destination = _address(packet.get('client_ip')), _address(packet.get('destination_ip'))
    if not client_ip or not destination:
        return None
    try:
        port = int(packet.get('destination_port'))
    except (TypeError, ValueError):
        return None
    proto = str(packet.get('protocol') or '').upper()
    transport = 'tcp' if proto == 'TCP' else 'udp' if proto == 'UDP' else None
    query = str(packet.get('dns_query') or '').strip().lower().rstrip('.')[:253]
    sni = str(packet.get('tls_sni') or '').strip().lower().rstrip('.')[:253]
    local = {_address(item) for item in local_dns_addresses}
    upstreams = {_address(item) for item in configured_upstreams}
    indicators = ['known_doh_endpoint_dns_lookup'] if query in DOH_DISCOVERY_HOSTS else []
    kind = evidence = None
    confidence = 'medium'
    explanation = ''
    if port == 53 and transport and destination not in local:
        kind = 'configured_upstream_direct_dns_attempt' if destination in upstreams else 'external_dns53_attempt'
        confidence = 'medium' if destination in upstreams else 'high'
        evidence = query or f'{transport.upper()}/53'
        explanation = (
            'Client addressed a configured upstream directly. AP prerouting DNAT is expected to redirect it; '
            'this observation does not establish successful bypass.'
            if destination in upstreams else
            'Client addressed a non-local DNS resolver. AP prerouting DNAT is expected to redirect it; '
            'capture alone does not establish that the external resolver was reached.'
        )
    elif transport == 'tcp' and port == 853:
        kind, evidence = 'dot_attempt', 'TCP/853'
        explanation = 'DoT-like port attempt observed; firewall verdict and resolver reachability are unverified.'
    elif transport == 'udp' and port in (784, 853):
        kind, evidence = 'doq_attempt', f'UDP/{port}'
        explanation = 'DoQ-like port attempt observed; firewall verdict and resolver reachability are unverified.'
    elif transport == 'tcp' and port == 443 and sni and any(sni == host or sni.endswith('.' + host) for host in DOH_HOSTS):
        kind, evidence = 'known_doh_endpoint_sni', sni
        explanation = 'TLS SNI matches a known resolver endpoint; SNI alone does not prove DNS-over-HTTPS.'
    if not kind:
        return None
    try:
        epoch = float(packet.get('timestamp'))
    except (TypeError, ValueError):
        epoch = time.time()
    return {
        'timestamp': dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
        'timestamp_unix_ns': int(epoch * 1_000_000_000),
        'type': kind, 'confidence': confidence,
        'interface': str(packet.get('interface') or '')[:32],
        'client': {'ip': client_ip, 'mac': str(packet.get('client_mac') or '')[:17] or None,
                   'label': str(packet.get('client_label') or '')[:100] or None},
        'destination': {'ip': destination, 'port': port, 'transport': transport},
        'evidence': evidence, 'indicators': indicators, 'expected_policy': explanation,
        'packet_payload_saved': False, 'enforcement_outcome': 'unknown',
    }


__all__ = ['DOH_HOSTS', 'DOH_DISCOVERY_HOSTS', 'classify_event']
