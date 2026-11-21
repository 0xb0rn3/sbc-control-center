"""Evidence-first security event enrichment for SBC Control Center.

Read-only adapter: callers supply already-collected sensor events and an optional
local reputation snapshot. No firewall actions or remote lookups are performed.
"""
from __future__ import annotations
import ipaddress
from typing import Any, Iterable


def is_public_ip(value: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def enrich_events(events: Iterable[dict[str, Any]], cidrs: Iterable[str] = (),
                  domains: Iterable[str] = ()) -> list[dict[str, Any]]:
    networks = [ipaddress.ip_network(x, strict=False) for x in cidrs]
    domain_set = {str(x).lower().rstrip(".") for x in domains}
    output = []
    for source in events:
        event = dict(source)
        destination = str(event.get("destination_ip") or event.get("dst_ip") or "")
        if not is_public_ip(destination):
            continue
        domain = str(event.get("domain") or event.get("qname") or "").lower().rstrip(".")
        ip = ipaddress.ip_address(destination)
        matched_ip = any(ip in network for network in networks)
        matched_domain = domain in domain_set if domain else False
        event.update({
            "destination_ip": destination,
            "domain": domain,
            "severity": "high" if matched_ip or matched_domain else event.get("severity", "info"),
            "confidence": "feed_match" if matched_ip or matched_domain else "observed",
            "evidence": event.get("evidence", "sensor_metadata"),
            "automatic_action": "none",
        })
        output.append(event)
    return output
