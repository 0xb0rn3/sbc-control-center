"""Live threat map: where household traffic goes right now, against live global threat feeds.

Three layers, all located with the local GeoIP database (no outside lookup):
  * household connections: the kernel's connection table (conntrack) for traffic from the two
    access points to public addresses, grouped by destination; drawn home -> VPN exit ->
    destination, because that is the path the traffic takes;
  * global threat activity: free public feeds, refreshed every 30 minutes through the VPN
    tunnel: SANS ISC DShield (top attacking addresses), abuse.ch Feodo Tracker (botnet command
    servers), Spamhaus DROP (hijacked networks) and blocklist.de (addresses reported for
    attacks in the last 48 hours);
  * matches: a household connection to an address or network on any feed, shown in red.

A feed match is an indicator to look at, not proof of compromise, and the map never blocks
anything. Home is the board's configured home_location, or else the city of its time zone.
"""
from __future__ import annotations

import bisect
import ipaddress
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import sbc_site

SITE = sbc_site.load()
FEED_DIR = sbc_site.STATE_DIR / 'threat-intel' / 'feeds'
GEOIP_PATHS = (Path('/usr/share/GeoIP/GeoLite2-City.mmdb'), Path('/usr/share/GeoIP/DB-IP-City-Lite.mmdb'))
CONNTRACK = '/usr/sbin/conntrack'
CURL = '/usr/bin/curl'
REFRESH_SECONDS = 30 * 60
MAX_FEED_BYTES = 8 * 1024 * 1024
FEEDS = {
    'dshield': ('https://isc.sans.edu/api/sources/attacks/200?json', 'SANS ISC DShield: top attacking addresses'),
    'feodo': ('https://feodotracker.abuse.ch/downloads/ipblocklist.json', 'abuse.ch Feodo Tracker: botnet command servers'),
    'drop': ('https://www.spamhaus.org/drop/drop_v4.json', 'Spamhaus DROP: hijacked networks'),
    'blocklist_de': ('https://lists.blocklist.de/lists/all.txt', 'blocklist.de: addresses reported for attacks, 48 h'),
    'urlhaus_domains': ('https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt', 'malware-filter: URLhaus malware hosts'),
    'phishing_domains': ('https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt', 'malware-filter: phishing hosts'),
}
REPUTATION_PATH = sbc_site.STATE_DIR / 'threat-intel' / 'reputation.json'
REPUTATION_MAX_CIDRS = 20000     # the limits threat_intelligence reads
REPUTATION_MAX_DOMAINS = 50000
_DOMAIN = re.compile(r'(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
_lock = threading.Lock()
_reader = None
_feeds: dict[str, Any] = {'ips': {}, 'nets': [], 'points': [], 'state': {}}
_last_load = 0.0


# ---------------------------------------------------------------- places

def _geo_reader():
    global _reader
    if _reader is None:
        try:
            import maxminddb
            path = next(p for p in GEOIP_PATHS if p.exists())
            _reader = maxminddb.open_database(str(path), maxminddb.MODE_MMAP)
        except Exception:
            _reader = False
    return _reader or None


def locate(ip: str) -> dict[str, Any] | None:
    reader = _geo_reader()
    if not reader:
        return None
    try:
        rec = reader.get(ip) or {}
    except Exception:
        return None
    loc = rec.get('location') or {}
    if 'latitude' not in loc:
        return None
    names = lambda key: ((rec.get(key) or {}).get('names') or {}).get('en', '')
    return {'lat': round(loc['latitude'], 3), 'lon': round(loc['longitude'], 3), 'city': names('city'),
            'country': names('country'), 'cc': ((rec.get('country') or {}).get('iso_code') or '').lower()}


def _zone_coordinates(zone: str) -> tuple[float, float] | None:
    for table in ('/usr/share/zoneinfo/zone.tab', '/usr/share/zoneinfo/zone1970.tab'):
        try:
            for line in Path(table).read_text().splitlines():
                parts = line.split('\t')
                if len(parts) >= 3 and parts[2] == zone:
                    m = re.fullmatch(r'([+-])(\d{2})(\d{2})(\d{2})?([+-])(\d{3})(\d{2})(\d{2})?', parts[1])
                    if not m:
                        return None
                    lat = int(m[2]) + int(m[3]) / 60 + int(m[4] or 0) / 3600
                    lon = int(m[6]) + int(m[7]) / 60 + int(m[8] or 0) / 3600
                    return (lat if m[1] == '+' else -lat, lon if m[5] == '+' else -lon)
        except OSError:
            continue
    return None


def home() -> dict[str, Any]:
    raw = SITE.get('home_location', '')
    match = re.fullmatch(r'\s*(-?\d{1,2}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*', raw or '')
    if match:
        return {'lat': float(match[1]), 'lon': float(match[2]), 'label': 'Home'}
    try:
        zone = Path('/etc/timezone').read_text().strip()
    except OSError:
        zone = os.path.realpath('/etc/localtime').split('zoneinfo/')[-1]
    coords = _zone_coordinates(zone)
    return {'lat': coords[0], 'lon': coords[1], 'label': f"Home ({zone.split('/')[-1].replace('_', ' ')})"} if coords else {}


# ---------------------------------------------------------------- feeds

def _fetch(url: str) -> bytes | None:
    """Through the VPN tunnel, so the feeds see the tunnel's address, not the household's."""
    try:
        cp = subprocess.run([CURL, '-fsS', '--max-time', '40', '--max-filesize', str(MAX_FEED_BYTES), '--interface',
                             SITE['vpn_interface'], '-A', sbc_site.USER_AGENT, url], capture_output=True, timeout=50)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return cp.stdout if cp.returncode == 0 and cp.stdout else None


def _public_ip(value: Any) -> str | None:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(ip) if ip.version == 4 and ip.is_global else None


def _parse(name: str, raw: bytes) -> dict[str, Any]:
    if name == 'dshield':
        rows = json.loads(raw)
        return {'points': [{'ip': ip, 'attacks': int(r.get('attacks') or 0), 'reports': int(r.get('count') or 0),
                            'last': str(r.get('lastseen', ''))[:10]}
                           for r in rows if isinstance(r, dict) and (ip := _public_ip(r.get('ip')))]}
    if name == 'feodo':
        rows = json.loads(raw)
        return {'points': [{'ip': ip, 'port': int(r.get('port') or 0), 'malware': str(r.get('malware', ''))[:40],
                            'status': str(r.get('status', ''))[:12], 'last': str(r.get('last_online') or '')[:10]}
                           for r in rows if isinstance(r, dict) and (ip := _public_ip(r.get('ip_address')))]}
    if name == 'drop':
        nets = []
        for line in raw.decode('utf-8', 'replace').splitlines():
            try:
                cidr = json.loads(line).get('cidr')
                net = ipaddress.ip_network(cidr, strict=False)
                if net.version == 4:
                    nets.append(net)
            except (ValueError, AttributeError, TypeError):
                continue
        return {'nets': [str(n) for n in nets]}
    if name == 'blocklist_de':
        return {'ips': [ip for line in raw.decode('utf-8', 'replace').splitlines()[:200000] if (ip := _public_ip(line))]}
    if name in ('urlhaus_domains', 'phishing_domains'):
        domains = []
        for line in raw.decode('utf-8', 'replace').splitlines()[:200000]:
            value = line.strip().lower().rstrip('.')
            if value and not value.startswith(('#', '!')) and _DOMAIN.fullmatch(value):
                domains.append(value)
        return {'domains': domains}
    return {}


def build_reputation() -> dict[str, Any]:
    """The reputation file the threat-intelligence view reads: networks and domains from the feeds."""
    cidrs: list[str] = []
    domains: list[str] = []
    sources = {}
    for name in ('drop', 'feodo', 'dshield', 'blocklist_de', 'urlhaus_domains', 'phishing_domains'):
        try:
            data = json.loads((FEED_DIR / f'{name}.json').read_text())
        except (OSError, ValueError):
            continue
        before = (len(cidrs), len(domains))
        cidrs += data.get('nets', [])
        cidrs += [f"{p['ip']}/32" for p in data.get('points', [])]
        cidrs += [f'{ip}/32' for ip in data.get('ips', [])]
        domains += data.get('domains', [])
        sources[name] = {'fetched': data.get('fetched'), 'cidrs': len(cidrs) - before[0], 'domains': len(domains) - before[1]}
    cidrs = list(dict.fromkeys(cidrs))[:REPUTATION_MAX_CIDRS]      # the most specific sources come first
    domains = list(dict.fromkeys(domains))[:REPUTATION_MAX_DOMAINS]
    doc = {'generated': int(time.time()), 'sources': sources, 'cidrs': cidrs, 'domains': domains}
    REPUTATION_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = REPUTATION_PATH.with_suffix('.tmp')
    tmp.write_text(json.dumps(doc, separators=(',', ':')))
    os.chmod(tmp, 0o640)
    os.replace(tmp, REPUTATION_PATH)
    return {'cidrs': len(cidrs), 'domains': len(domains)}


def refresh_feeds(force: bool = False) -> dict[str, Any]:
    FEED_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    report = {}
    for name, (url, _) in FEEDS.items():
        path = FEED_DIR / f'{name}.json'
        if not force and path.exists() and time.time() - path.stat().st_mtime < REFRESH_SECONDS - 60:
            continue
        raw = _fetch(url)
        if raw is None:
            report[name] = 'unreachable'
            continue
        try:
            parsed = _parse(name, raw)
        except (ValueError, TypeError) as exc:
            report[name] = f'unreadable: {exc}'[:120]
            continue
        parsed['fetched'] = int(time.time())
        tmp = path.with_suffix('.tmp')
        tmp.write_text(json.dumps(parsed, separators=(',', ':')))
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        report[name] = 'updated'
    if report or not REPUTATION_PATH.exists():
        report['reputation'] = build_reputation()
    _load_feeds(force=True)
    return report


def _load_feeds(force: bool = False) -> None:
    global _last_load
    with _lock:
        if not force and time.time() - _last_load < 60:
            return
        ips: dict[str, list[str]] = {}
        nets: list[tuple[int, int, str]] = []
        points: list[dict[str, Any]] = []
        state = {}
        for name, (_, label) in FEEDS.items():
            try:
                data = json.loads((FEED_DIR / f'{name}.json').read_text())
            except (OSError, ValueError):
                state[name] = {'label': label, 'fetched': None, 'entries': 0}
                continue
            entries = 0
            for p in data.get('points', []):
                ips.setdefault(p['ip'], []).append(name)
                geo = locate(p['ip'])
                if geo:
                    points.append({**p, **geo, 'feed': name})
                entries += 1
            for ip in data.get('ips', []):
                ips.setdefault(ip, []).append(name)
                entries += 1
            entries += len(data.get('domains', []))
            for cidr in data.get('nets', []):
                net = ipaddress.ip_network(cidr)
                nets.append((int(net.network_address), int(net.broadcast_address), name))
                entries += 1
            state[name] = {'label': label, 'fetched': data.get('fetched'), 'entries': entries}
        nets.sort()
        _feeds.update({'ips': ips, 'nets': nets, 'points': points, 'state': state})
        _last_load = time.time()


def feed_hits(ip: str) -> list[str]:
    hits = list(_feeds['ips'].get(ip, []))
    try:
        value = int(ipaddress.ip_address(ip))
    except ValueError:
        return hits
    nets = _feeds['nets']
    i = bisect.bisect_right(nets, (value, float('inf'), '')) - 1
    if i >= 0 and nets[i][0] <= value <= nets[i][1]:
        hits.append(nets[i][2])
    return sorted(set(hits))


# ---------------------------------------------------------------- household connections

_CT = re.compile(r'^\S+\s+\d+\s+(\w+)\s+\d+\s+\d+\s+(?:([A-Z_]+)\s+)?src=(\S+) dst=(\S+)(?: sport=(\d+) dport=(\d+))?')


def _client_names() -> dict[str, str]:
    names = {}
    try:
        for line in Path(SITE['dhcp_lease_file']).read_text().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                names[parts[2]] = parts[3] if parts[3] != '*' else parts[2]
    except OSError:
        pass
    return names


def connections() -> list[dict[str, Any]]:
    try:
        out = subprocess.run([CONNTRACK, '-L', '-o', 'extended'], capture_output=True, text=True, timeout=6).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    subnets = [ipaddress.ip_network(s) for s in sbc_site.ap_subnets(SITE)]
    names = _client_names()
    by_dest: dict[str, dict[str, Any]] = {}
    for line in out.splitlines()[:20000]:
        m = _CT.match(line)
        if not m:
            continue
        proto, state, src, dst, _sport, dport = m.groups()
        try:
            src_ip, dst_ip = ipaddress.ip_address(src), ipaddress.ip_address(dst)
        except ValueError:
            continue
        if dst_ip.version != 4 or not dst_ip.is_global or not any(src_ip in n for n in subnets):
            continue
        d = by_dest.setdefault(dst, {'ip': dst, 'count': 0, 'clients': set(), 'ports': set(), 'protos': set()})
        d['count'] += 1
        d['clients'].add(names.get(src, src))
        if dport:
            d['ports'].add(int(dport))
        d['protos'].add(proto)
    rows = []
    for dst, d in by_dest.items():
        geo = locate(dst)
        rows.append({'ip': dst, 'count': d['count'], 'clients': sorted(d['clients'])[:6], 'ports': sorted(d['ports'])[:6],
                     'protos': sorted(d['protos']), 'geo': geo, 'feeds': feed_hits(dst)})
    rows.sort(key=lambda r: (not r['feeds'], -r['count']))
    return rows[:400]


def snapshot() -> dict[str, Any]:
    _load_feeds()
    try:
        import vpn_library
        exit_now = vpn_library.exit_info()
    except Exception:
        exit_now = None
    exit_point = None
    if exit_now and exit_now.get('ip'):
        geo = locate(exit_now['ip'])
        if geo:
            exit_point = {**geo, 'ip': exit_now['ip'], 'hostname': exit_now.get('hostname', '')}
    conns = connections()
    ids_state: dict[str, Any] = {'running': False, 'alerts': []}
    try:
        import ids
        ids_state = ids.status()
        subnets = [ipaddress.ip_network(s) for s in sbc_site.ap_subnets(SITE)]
        for a in ids_state['alerts']:
            # place the alert at its outside end: the remote address, whichever side it is on
            remote = next((ip for ip in (a.get('dest_ip'), a.get('src_ip')) if ip and _public_ip(ip)), None)
            a['remote'] = remote
            a['geo'] = locate(remote) if remote else None
            local = next((ip for ip in (a.get('src_ip'), a.get('dest_ip')) if ip and any(ipaddress.ip_address(ip) in n for n in subnets if ':' not in ip)), None)
            a['device'] = _client_names().get(local, local)
    except Exception as exc:
        ids_state = {'running': False, 'alerts': [], 'error': str(exc)[:200]}
    return {
        'ok': True, 'generated': int(time.time()), 'home': home(), 'exit': exit_point,
        'connections': conns, 'matches': [c for c in conns if c['feeds']],
        'global': _feeds['points'][:1200], 'feeds': _feeds['state'],
        'geoip': bool(_geo_reader()), 'ids': ids_state,
    }


def refresher() -> None:
    """Agent thread: refresh the feeds every 30 minutes (through the tunnel)."""
    time.sleep(45)
    while True:
        try:
            result = refresh_feeds()
            if result:
                print(f'[THREATMAP] feeds: {result}', flush=True)
        except Exception as exc:
            print(f'[THREATMAP] feed refresh failed: {exc}', flush=True)
        time.sleep(300)
