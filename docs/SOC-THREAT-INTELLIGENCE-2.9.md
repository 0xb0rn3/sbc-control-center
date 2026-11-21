# SOC / Threat Intelligence integration contract (2.9)

This change adds a small, testable enrichment core for the network-observability branch.

## Event pipeline

All sensors should emit normalized records with:
- UTC wall-clock timestamp and monotonic sample timestamp
- source/destination IP and port, protocol, interface, device identity
- event type, sensor provenance, severity and confidence
- evidence reference (bounded JSONL record or PCAPNG offset)

The UI, map, incident timeline and alerting should consume this shared event shape.

## Threat map rules

- Plot only public IP addresses with a successful local GeoIP lookup.
- Never geolocate RFC1918, loopback, link-local, multicast or reserved addresses.
- Label locations as approximate; do not imply the user/attacker is physically at that point.
- Distinguish sensor observations, reputation-feed matches and confirmed firewall blocks.
- A DNS direct-upstream packet is an attempt, not proof that DNS redirection failed.
- Reputation matches are indicators, not proof of compromise.

## Reliability and safety

- Keep feed snapshots cached locally; no synchronous remote lookups in packet paths.
- Bound event queues, log sizes, capture duration and retained PCAPNG storage.
- Expose sensor health, event freshness, capture drops and last successful feed refresh.
- Keep IDS integrations (Suricata/Zeek) optional and resource-aware on ARM SBCs.
- No automatic firewall blocking in this integration. Any response action must be a separate, authenticated, audited policy operation with expiry and rollback.
- A monitoring/UI failure must never weaken VPN kill-switch, DNS enforcement or firewall policy.

## Current scope

The enrichment core accepts events and local CIDR/domain indicators. It does not install Suricata, Zeek, GeoIP databases, download threat feeds, or change firewall rules. Those are separate deployment/integration steps.
