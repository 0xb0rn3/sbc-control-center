#!/usr/bin/env python3
"""Evidence-first threat map and incident API.

Consumes bounded local DNS-bypass sensor JSONL records and a locally cached
reputation snapshot. GeoIP is optional and local-only. No packet payloads are
retained here and no firewall actions are performed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import time
import threading
from functools import lru_cache
from pathlib import Path
import sbc_site

from typing import Any

EVENT_PATHS = (
    sbc_site.DNS_BYPASS_STATE / 'events.jsonl',
    sbc_site.DNS_BYPASS_STATE / 'events.jsonl.1',
)
FEED_PATH = sbc_site.STATE_DIR / 'threat-intel' / 'reputation.json'
GEOIP_PATH = Path('/usr/share/GeoIP/GeoLite2-City.mmdb')
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_EVENTS_PER_FILE = 500
MAX_EVENTS_RESPONSE = 250
EVIDENCE_FIELDS = (
    'schema', 'timestamp', 'type', 'confidence', 'interface', 'source',
    'destination', 'evidence', 'indicators', 'expected_policy',
    'packet_payload_saved',
)
_geo_reader = None
_geo_reader_mtime_ns = None
_geo_lock = threading.Lock()


def _load_feed() -> tuple[list[ipaddress._BaseNetwork], set[str], str | None]:
    try:
        if FEED_PATH.stat().st_size > MAX_FILE_BYTES:
            return [], set(), 'feed_too_large'
        raw = json.loads(FEED_PATH.read_text(encoding='utf-8'))
        if not isinstance(raw, dict):
            return [], set(), 'feed_invalid'
        nets = []
        for value in raw.get('cidrs', [])[:20000]:
            try:
                nets.append(ipaddress.ip_network(value, strict=False))
            except (ValueError, TypeError):
                continue
        domains = {str(x).lower().rstrip('.') for x in raw.get('domains', [])[:50000]
                   if isinstance(x, str) and x.strip()}
        return nets, domains, None
    except FileNotFoundError:
        return [], set(), 'feed_not_installed'
    except Exception:
        return [], set(), 'feed_invalid'


def _external(value: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
        # is_global excludes private, documentation, benchmarking, and other
        # special-use ranges that must not be plotted as public geography.
        return ip.is_global
    except ValueError:
        return False


@lru_cache(maxsize=2048)
def _geo(value: str) -> dict[str, Any] | None:
    """Return approximate coordinates from an optional local GeoLite2 DB."""
    global _geo_reader, _geo_reader_mtime_ns
    try:
        stat = GEOIP_PATH.stat()
        with _geo_lock:
            if _geo_reader is None or _geo_reader_mtime_ns != stat.st_mtime_ns:
                if _geo_reader is not None:
                    try:
                        _geo_reader.close()
                    except Exception:
                        pass
                import geoip2.database  # type: ignore
                _geo_reader = geoip2.database.Reader(str(GEOIP_PATH))
                _geo_reader_mtime_ns = stat.st_mtime_ns
            result = _geo_reader.city(value)
        latitude, longitude = result.location.latitude, result.location.longitude
        if latitude is None or longitude is None:
            return None
        return {
            'country': result.country.name,
            'country_code': result.country.iso_code,
            'city': result.city.name,
            'latitude': float(latitude),
            'longitude': float(longitude),
            'accuracy_radius_km': result.location.accuracy_radius,
            'precision': 'approximate_ip_geolocation',
        }
    except Exception:
        return None


def _read_sensor_records() -> list[tuple[Path, int, str, dict[str, Any]]]:
    records: list[tuple[Path, int, str, dict[str, Any]]] = []
    for path in EVENT_PATHS:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError:
            continue
        start = max(0, len(lines) - MAX_EVENTS_PER_FILE)
        for line_number, line in enumerate(lines[start:], start=start + 1):
            if not line or len(line) > 65536:
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(record, dict):
                records.append((path, line_number, line, record))
    return records


def _event_id(path: Path, line_number: int, line: str) -> str:
    digest = hashlib.sha256(f'{path.name}\0{line_number}\0{line}'.encode('utf-8', 'replace')).hexdigest()
    return 'ev_' + digest[:24]


def collect_events(limit: int = 150) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    networks, domains, _feed_state = _load_feed()
    for path, line_number, line, source_record in _read_sensor_records():
        source = source_record.get('source') if isinstance(source_record.get('source'), dict) else {}
        destination = source_record.get('destination') if isinstance(source_record.get('destination'), dict) else {}
        source_ip = str(source.get('ip') or source_record.get('src_ip') or source_record.get('source_ip') or '')
        destination_ip = str(destination.get('ip') or source_record.get('dst_ip') or source_record.get('destination_ip') or '')
        if not _external(destination_ip):
            continue
        domain = str(source_record.get('qname') or source_record.get('domain') or '')
        event_type = str(source_record.get('type') or source_record.get('event_type') or source_record.get('classification') or 'network_observation')[:80]
        evidence_text = str(source_record.get('evidence') or '')[:512]
        domain = (domain or (evidence_text if '.' in evidence_text and ' ' not in evidence_text else '')).lower().rstrip('.')[:253]
        try:
            destination_obj = ipaddress.ip_address(destination_ip)
            ip_match = any(destination_obj in network for network in networks)
        except ValueError:
            ip_match = False
        domain_match = bool(domain and domain in domains)
        feed_match = ip_match or domain_match
        severity = 'high' if feed_match else ('low' if any(token in event_type.lower() for token in ('dns', 'dot', 'doq', 'doh')) else 'info')
        sensor_confidence = str(source_record.get('confidence') or 'unknown')[:32]
        output.append({
            'event_id': _event_id(path, line_number, line),
            'timestamp': source_record.get('timestamp') or source_record.get('ts') or None,
            'source_ip': source_ip[:64],
            'source_mac': str(source.get('mac') or '')[:32],
            'source_hostname': str(source.get('hostname') or '')[:128],
            'destination_ip': destination_ip,
            'destination_port': destination.get('port'),
            'protocol': str(destination.get('transport') or source_record.get('protocol') or '')[:16],
            'interface': str(source_record.get('interface') or '')[:32],
            'domain': domain,
            'event_type': event_type,
            'severity': severity,
            'confidence': 'feed_match' if feed_match else 'observed_attempt',
            'sensor_confidence': sensor_confidence,
            'feed_match': feed_match,
            'evidence': 'dns_bypass_sensor',
            'evidence_summary': evidence_text,
            'packet_payload_saved': bool(source_record.get('packet_payload_saved', False)),
            'geo': _geo(destination_ip),
        })
    output.sort(key=lambda event: str(event.get('timestamp') or ''), reverse=True)
    return output[:max(1, min(int(limit), MAX_EVENTS_RESPONSE))]


def get_event_evidence(event_id: str) -> dict[str, Any] | None:
    """Resolve one opaque event ID to its original, bounded sensor metadata."""
    if not isinstance(event_id, str) or len(event_id) != 27 or not event_id.startswith('ev_'):
        return None
    for path, line_number, line, record in _read_sensor_records():
        if _event_id(path, line_number, line) != event_id:
            continue
        source = record.get('source') if isinstance(record.get('source'), dict) else {}
        destination = record.get('destination') if isinstance(record.get('destination'), dict) else {}
        evidence = {key: record.get(key) for key in EVIDENCE_FIELDS if key in record}
        return {
            'ok': True,
            'event_id': event_id,
            'source_file': path.name,
            'line_number': line_number,
            'sensor_record': evidence,
            'packet_metadata': {
                'source_ip': str(source.get('ip') or '')[:64],
                'source_mac': str(source.get('mac') or '')[:32],
                'source_hostname': str(source.get('hostname') or '')[:128],
                'destination_ip': str(destination.get('ip') or '')[:64],
                'destination_port': destination.get('port'),
                'transport': str(destination.get('transport') or '')[:16],
                'interface': str(record.get('interface') or '')[:32],
                'packet_payload_saved': bool(record.get('packet_payload_saved', False)),
                'evidence': str(record.get('evidence') or '')[:512],
                'expected_policy': str(record.get('expected_policy') or '')[:1024],
                'indicators': [str(value)[:128] for value in record.get('indicators', [])[:32]
                               if isinstance(value, (str, int, float))],
            },
            'limitations': [
                'This is the original TShark-derived sensor metadata record, not a retained packet payload.',
                'DNS direct-upstream observations are attempts; they do not prove that firewall redirection failed.',
            ],
        }
    return None


def snapshot() -> dict[str, Any]:
    networks, domains, feed_state = _load_feed()
    events = collect_events()
    by_severity = {key: sum(1 for event in events if event['severity'] == key)
                   for key in ('high', 'medium', 'low', 'info')}
    geolocated = [event for event in events if event.get('geo')]
    return {
        'ok': True,
        'generated_at': time.time(),
        'events': events,
        'summary': {
            'events': len(events),
            'severity': by_severity,
            'geolocated': len(geolocated),
            'unmapped': len(events) - len(geolocated),
            'feed_cidrs': len(networks),
            'feed_domains': len(domains),
        },
        'feed_state': feed_state,
        'map': {
            'projection': 'equirectangular',
            'coordinates': 'approximate destination-IP geolocation from local GeoLite2 City database',
            'cluster_on_client': True,
            'external_only': True,
        },
        'limitations': [
            'Direct DNS, DoT, DoQ and known-DoH endpoint observations are attempts or indicators, not proof of successful bypass or compromise.',
            'Geolocation is approximate and requires a locally installed GeoLite2 City database and geoip2 Python package.',
            'A mapped point represents an IP geolocation estimate, not a verified physical attacker location.',
            'Packet payloads are not stored by the DNS bypass sensor; drill-down exposes the original packet metadata record.',
            'Feed matches are indicators, not proof of compromise. This module is read-only and does not modify firewall rules.',
        ],
    }
