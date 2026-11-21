"""Evidence-first SOC event normalization for the SBC packet inspector.

This module enriches already captured packet metadata. It performs no packet
capture itself, no remote GeoIP/reputation lookups, and no firewall actions.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

FEED_PATH = Path("/var/lib/sbc-control-center/threat-intel/reputation.json")
GEOIP_PATH = Path("/usr/share/GeoIP/GeoLite2-City.mmdb")
MAX_FEED_BYTES = 8 * 1024 * 1024
_geo_lock = threading.Lock()
_geo_reader = None
_geo_mtime_ns = None


def is_public_ip(value: Any) -> bool:
    try:
        return ipaddress.ip_address(str(value)).is_global
    except ValueError:
        return False


def _load_feed() -> tuple[list[ipaddress._BaseNetwork], set[str], str | None]:
    try:
        if FEED_PATH.stat().st_size > MAX_FEED_BYTES:
            return [], set(), "feed_too_large"
        data = json.loads(FEED_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return [], set(), "feed_invalid"
        networks = []
        for item in data.get("cidrs", [])[:20000]:
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except (ValueError, TypeError):
                continue
        domains = {str(item).lower().rstrip(".") for item in data.get("domains", [])[:50000]
                   if isinstance(item, str) and item.strip()}
        return networks, domains, None
    except FileNotFoundError:
        return [], set(), "feed_not_installed"
    except Exception:
        return [], set(), "feed_invalid"


@lru_cache(maxsize=2048)
def _geo(ip_value: str) -> dict[str, Any] | None:
    global _geo_reader, _geo_mtime_ns
    try:
        stat = GEOIP_PATH.stat()
        with _geo_lock:
            if _geo_reader is None or _geo_mtime_ns != stat.st_mtime_ns:
                if _geo_reader is not None:
                    try:
                        _geo_reader.close()
                    except Exception:
                        pass
                import geoip2.database  # type: ignore
                _geo_reader = geoip2.database.Reader(str(GEOIP_PATH))
                _geo_mtime_ns = stat.st_mtime_ns
            result = _geo_reader.city(ip_value)
        lat, lon = result.location.latitude, result.location.longitude
        if lat is None or lon is None:
            return None
        return {
            "country": result.country.name,
            "country_code": result.country.iso_code,
            "city": result.city.name,
            "latitude": float(lat),
            "longitude": float(lon),
            "accuracy_radius_km": result.location.accuracy_radius,
            "precision": "approximate_ip_geolocation",
        }
    except Exception:
        return None


def _event_id(source: dict[str, Any]) -> str:
    canonical = json.dumps(source, sort_keys=True, separators=(",", ":"), default=str)
    return "ev_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _timestamp(value: Any) -> str | None:
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return None
    return None


def enrich_events(events: Iterable[dict[str, Any]], cidrs: Iterable[str] = (),
                  domains: Iterable[str] = ()) -> list[dict[str, Any]]:
    networks = []
    for value in cidrs:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except (ValueError, TypeError):
            continue
    domain_set = {str(value).lower().rstrip(".") for value in domains}
    output = []
    for source in events:
        if not isinstance(source, dict):
            continue
        event = dict(source)
        remote = str(event.get("remote_ip") or "")
        if not is_public_ip(remote):
            remote = next((str(value) for value in (event.get("destination_ip"), event.get("source_ip"))
                           if is_public_ip(value)), "")
        if not remote:
            continue
        domain = str(event.get("dns_query") or event.get("tls_sni") or event.get("domain") or "").lower().rstrip(".")
        try:
            address = ipaddress.ip_address(remote)
            ip_match = any(address in network for network in networks)
        except ValueError:
            ip_match = False
        domain_match = bool(domain and domain in domain_set)
        feed_match = ip_match or domain_match
        bypass = event.get("dns_bypass_indicator")
        if not isinstance(bypass, dict):
            bypass = {}
        event.update({
            "event_id": _event_id(source),
            "timestamp": _timestamp(event.get("timestamp")),
            "remote_ip": remote,
            "destination_ip": str(event.get("destination_ip") or ""),
            "source_ip": str(event.get("source_ip") or ""),
            "domain": domain,
            "event_type": str(bypass.get("type") or event.get("application") or event.get("protocol") or "packet_observation")[:80],
            "severity": "high" if feed_match else ("medium" if bypass else "info"),
            "confidence": "feed_match" if feed_match else ("sensor_indicator" if bypass else "observed"),
            "feed_match": feed_match,
            "geo": _geo(remote),
            "evidence_source": "live_packet_capture_ring",
            "packet_payload_saved": False,
            "automatic_action": "none",
        })
        output.append(event)
    output.sort(key=lambda row: row.get("timestamp") or "", reverse=True)
    return output[:250]


def snapshot_from_capture(capture_result: dict[str, Any]) -> dict[str, Any]:
    raw_events = capture_result.get("events", [])
    if not isinstance(raw_events, list):
        raw_events = []
    networks, domains, feed_state = _load_feed()
    events = enrich_events(raw_events, [str(x) for x in networks], domains)
    severity = {key: sum(1 for event in events if event["severity"] == key)
                for key in ("high", "medium", "low", "info")}
    geo_count = sum(1 for event in events if event.get("geo"))
    capture = capture_result.get("capture") if isinstance(capture_result.get("capture"), dict) else {}
    last_packet = capture.get("last_packet_at")
    freshness = None
    try:
        freshness = max(0.0, time.time() - float(last_packet)) if last_packet else None
    except (TypeError, ValueError):
        pass
    return {
        "ok": True, "generated_at": time.time(), "events": events,
        "summary": {"events": len(events), "severity": severity,
                    "geolocated": geo_count, "unmapped": len(events) - geo_count,
                    "feed_cidrs": len(networks), "feed_domains": len(domains)},
        "capture": {
            "active": bool(capture.get("active")), "last_packet_at": last_packet,
            "last_packet_age_seconds": freshness, "ring_size": capture.get("ring_size", len(raw_events)),
            "ring_capacity": capture.get("ring_capacity"),
            "overwritten_events": capture.get("overwritten_events", 0),
            "payload_retained_in_memory": bool(capture.get("payload_retained_in_memory", False)),
        },
        "feed_state": feed_state,
        "limitations": [
            "The map shows approximate IP geography for externally routed endpoints, not a person's physical location.",
            "A point is an observed remote endpoint. It is not automatically an incoming attack.",
            "GeoIP is local-only and requires GeoLite2 City plus geoip2; no remote lookup is made.",
            "Events are available only while retained in the bounded packet-capture ring buffer.",
            "Packet payload bytes are not retained in memory. Evidence drill-down displays packet metadata only.",
            "Reputation matches are indicators, not proof of compromise. No automatic blocking is performed.",
        ],
    }


def evidence_for_event(event_id: str, capture_result: dict[str, Any]) -> dict[str, Any] | None:
    events = capture_result.get("events", [])
    if not isinstance(events, list):
        return None
    for source in events:
        if not isinstance(source, dict) or _event_id(source) != event_id:
            continue
        allowed = (
            "timestamp", "timestamp_ns", "direction", "bytes", "source_ip",
            "destination_ip", "source_port", "destination_port", "protocol",
            "application", "dns_query", "dns_qtype", "dns_rcode", "dns_response",
            "tls_sni", "ip_version", "interface", "path", "client_ip",
            "remote_ip", "client_name", "client_mac", "client_label",
            "device_type", "device_type_confidence", "device_vendor", "remote_port",
            "flow_id", "dns_bypass_indicator",
        )
        metadata = {key: source.get(key) for key in allowed if key in source}
        return {
            "ok": True, "event_id": event_id, "packet_metadata": metadata,
            "packet_payload_saved": False, "evidence_source": "live_packet_capture_ring",
            "limitations": [
                "This is the decoded packet metadata record retained by the live inspector.",
                "Packet bytes and payload contents are not returned by this endpoint.",
                "The event can disappear when its bounded in-memory capture ring is overwritten or the service restarts.",
            ],
        }
    return None
