#!/usr/bin/env python3
"""Passive, metadata-only DNS bypass detector for the access-point interfaces."""

import csv
import datetime as dt
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
import sbc_site


_SITE = sbc_site.load()
INTERFACES = tuple(sbc_site.ap_interfaces(_SITE))
AP_DNS = {_SITE["ap2_ip"], _SITE["ap_ip"], "127.0.0.1"}
LEASE_FILE = Path("/var/lib/misc/dnsmasq.leases")
STATE_DIR = sbc_site.DNS_BYPASS_STATE
EVENT_FILE = STATE_DIR / "events.jsonl"
MAX_LOG_BYTES = 5 * 1024 * 1024
DEDUP_SECONDS = 60

# Capture filter is deliberately placed before the first -i option.
CAPTURE_FILTER = (
    "port 53 or port 853 or port 784 or "
    "(tcp port 443 and tcp[((tcp[12] & 0xf0) >> 2)] = 0x16) or "
    "(udp port 443 and (udp[8] & 0xc0) = 0xc0)"
)

DISPLAY_FILTER = (
    "dns.flags.response == 0 or "
    "tcp.dstport == 53 or udp.dstport == 53 or "
    "tcp.dstport == 853 or udp.dstport == 853 or "
    "udp.dstport == 784 or "
    "tls.handshake.extensions_server_name"
)

FIELDS = (
    "frame.time_epoch",
    "frame.interface_name",
    "eth.src",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.dstport",
    "udp.dstport",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
)

# Curated known resolver hostnames, not a complete DoH endpoint database.
DOH_HOSTS = {
    "dns.google",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "security.cloudflare-dns.com",
    "family.cloudflare-dns.com",
    "dns.quad9.net",
    "dns10.quad9.net",
    "dns.adguard-dns.com",
    "family.adguard-dns.com",
    "dns.nextdns.io",
    "doh.mullvad.net",
    "dns.mullvad.net",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "dns0.eu",
    "doh.dns.apple.com",
    "doh-dns-apple-com.v.aaplimg.com",
}

DOH_DISCOVERY_HOSTS = {
    "doh.dns.apple.com",
    "doh-dns-apple-com.v.aaplimg.com",
}

lease_cache = {}
lease_refresh = 0.0
seen = {}


def first(value):
    return (value or "").split(",", 1)[0].strip()


def refresh_leases():
    global lease_cache, lease_refresh

    now = time.monotonic()
    if now < lease_refresh:
        return

    fresh = {}
    try:
        for line in LEASE_FILE.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue

            expiry, mac, address, hostname = parts[:4]
            if hostname == "*":
                hostname = None

            fresh[address] = {
                "mac": mac.lower(),
                "hostname": hostname,
            }
    except OSError:
        pass

    lease_cache = fresh
    lease_refresh = now + 10


def rotate_log():
    try:
        if EVENT_FILE.stat().st_size < MAX_LOG_BYTES:
            return
    except FileNotFoundError:
        return

    previous = EVENT_FILE.with_name("events.jsonl.1")
    previous.unlink(missing_ok=True)
    os.replace(EVENT_FILE, previous)


def emit_event(event):
    now = time.monotonic()
    key = (
        event["type"],
        event["source"]["ip"],
        event["destination"]["ip"],
        event["destination"]["port"],
        event.get("evidence", ""),
    )

    if now - seen.get(key, -1e9) < DEDUP_SECONDS:
        return

    seen[key] = now

    if len(seen) > 4096:
        for old_key, timestamp in list(seen.items()):
            if now - timestamp > DEDUP_SECONDS * 2:
                seen.pop(old_key, None)

    rotate_log()

    line = json.dumps(event, separators=(",", ":"), sort_keys=True)

    with EVENT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
    os.chmod(EVENT_FILE, 0o640)

    # Structured event also appears in systemd journal.
    print("KICKPI_DNS_BYPASS " + line, flush=True)


def classify(row):
    interface = first(row.get("frame.interface_name"))
    if interface not in INTERFACES:
        return None

    source = first(row.get("ip.src")) or first(row.get("ipv6.src"))
    destination = first(row.get("ip.dst")) or first(row.get("ipv6.dst"))

    if not source or not destination:
        return None

    if source in AP_DNS:
        return None

    try:
        ipaddress.ip_address(source)
        ipaddress.ip_address(destination)
    except ValueError:
        return None

    tcp_port = first(row.get("tcp.dstport"))
    udp_port = first(row.get("udp.dstport"))

    if tcp_port.isdigit():
        transport, port = "tcp", int(tcp_port)
    elif udp_port.isdigit():
        transport, port = "udp", int(udp_port)
    else:
        return None

    query = first(row.get("dns.qry.name")).rstrip(".")
    sni = first(
        row.get("tls.handshake.extensions_server_name")
    ).lower().rstrip(".")

    event_type = None
    confidence = "high"
    expected_policy = "not independently verified"
    evidence = ""

    indicators = []
    if query.lower() in DOH_DISCOVERY_HOSTS:
        indicators.append("apple_doh_endpoint_dns_lookup")

    if port == 53 and destination not in AP_DNS:
        if destination == "100.64.0.23":
            event_type = "configured_upstream_direct_dns_attempt"
            confidence = "medium"
            evidence = query or "DNS request to the configured upstream resolver"
            expected_policy = (
                "Client addressed the configured upstream resolver directly. "
                "AP prerouting DNAT should redirect this query to local AdGuard; "
                "this observation does not establish a successful bypass."
            )
        else:
            event_type = "external_dns53_attempt"
            evidence = query or "DNS request to non-local resolver"
            expected_policy = (
                "AP prerouting DNAT should redirect this query to local AdGuard; "
                "packet capture alone does not prove a successful bypass."
            )

    elif transport == "tcp" and port == 853:
        event_type = "dot_attempt"
        evidence = "TCP/853"
        expected_policy = (
            "AP firewall has a TCP/853 drop rule; "
            "individual packet verdict is not independently verified."
        )

    elif transport == "udp" and port in (784, 853):
        event_type = "doq_attempt"
        evidence = f"UDP/{port}"
        expected_policy = (
            "AP firewall has UDP/784,853 drop rules; "
            "individual packet verdict is not independently verified."
        )

    elif port == 443 and sni and any(
        sni == host or sni.endswith("." + host)
        for host in DOH_HOSTS
    ):
        event_type = "known_doh_endpoint_sni"
        confidence = "medium"
        evidence = sni
        expected_policy = (
            "HTTPS connection to a known DNS resolver hostname. "
            "SNI alone does not prove that DNS traffic was carried."
        )

    if not event_type:
        return None

    refresh_leases()
    lease = lease_cache.get(source, {})

    captured_mac = first(row.get("eth.src")).lower()
    mac = lease.get("mac") or (
        captured_mac if re.fullmatch(
            r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", captured_mac
        ) else None
    )

    epoch_text = first(row.get("frame.time_epoch"))
    try:
        epoch = float(epoch_text)
    except (ValueError, TypeError):
        epoch = time.time()

    timestamp = dt.datetime.fromtimestamp(
        epoch, tz=dt.timezone.utc
    ).isoformat()

    return {
        "schema": 1,
        "timestamp": timestamp,
        "type": event_type,
        "confidence": confidence,
        "interface": interface,
        "source": {
            "ip": source,
            "mac": mac,
            "hostname": lease.get("hostname"),
        },
        "destination": {
            "ip": destination,
            "port": port,
            "transport": transport,
        },
        "evidence": evidence,
        "indicators": indicators,
        "expected_policy": expected_policy,
        "packet_payload_saved": False,
    }


def main():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o750)

    command = [
        "/usr/bin/tshark",
        "-n", "-l", "-p",
        "-s", "1600",
        "-B", "8",
        "-Q",
        "-f", CAPTURE_FILTER,
        "-Y", DISPLAY_FILTER,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]

    for field in FIELDS:
        command.extend(["-e", field])

    for interface in INTERFACES:
        command.extend(["-i", interface])

    env = {**os.environ, "HOME": str(STATE_DIR)}

    print(
        "Starting passive DNS sensor on " + ", ".join(INTERFACES),
        flush=True,
    )

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env=env,
    )

    try:
        reader = csv.DictReader(process.stdout, delimiter="\t")
        for row in reader:
            if not row:
                continue
            event = classify(row)
            if event:
                emit_event(event)
    finally:
        if process.stdout:
            process.stdout.close()

    code = process.wait()
    raise SystemExit(code if code else 1)


if __name__ == "__main__":
    main()
