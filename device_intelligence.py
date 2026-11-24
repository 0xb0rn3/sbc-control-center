#!/usr/bin/env python3
"""Best-effort LAN device identity using trusted local network evidence.

MAC OUI data identifies the IEEE address-block assignee, not necessarily the
finished device manufacturer. Locally administered/private MACs deliberately
receive no vendor attribution. Hostname-based device-family guesses carry an
explicit confidence label. Manual labels are local administrator annotations.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
import sbc_site

from typing import Any, Iterable

MAC_RE = re.compile(r'^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$')
LABEL_PATH = sbc_site.STATE_DIR / 'device-labels.json'
OUI_DATA_DIR = sbc_site.STATE_DIR / 'ieee-data'
MAX_OUI_DOWNLOAD = 12 * 1024 * 1024
IEEE_REGISTRIES = {
    'oui.csv': 'https://standards-oui.ieee.org/oui/oui.csv',
    'mam.csv': 'https://standards-oui.ieee.org/oui28/mam.csv',
    'oui36.csv': 'https://standards-oui.ieee.org/oui36/oui36.csv',
}
_observation_lock = __import__('threading').RLock()
_observations_by_ip: dict[str, tuple[float, list[str]]] = {}
_observations_by_mac: dict[str, tuple[float, list[str]]] = {}
OBSERVATION_TTL = 24 * 60 * 60
MAX_OBSERVATIONS = 512
OUI_PATHS = (
    OUI_DATA_DIR / 'oui.csv', OUI_DATA_DIR / 'mam.csv', OUI_DATA_DIR / 'oui36.csv',
    Path('/usr/share/ieee-data/oui.csv'),
    Path('/usr/share/ieee-data/mam.csv'),
    Path('/usr/share/ieee-data/oui36.csv'),
    Path('/var/lib/ieee-data/oui.csv'),
    Path('/var/lib/ieee-data/mam.csv'),
    Path('/var/lib/ieee-data/oui36.csv'),
    Path('/usr/share/ieee-data/oui.txt'),
    Path('/var/lib/ieee-data/oui.txt'),
)
MAX_VENDOR_ROWS = 150_000
MAX_LABELS = 1024
_cache_signature: tuple[tuple[str, int, int], ...] | None = None
_vendor_cache: dict[str, tuple[str, str]] = {}


def normalize_mac(value: Any) -> str | None:
    if not isinstance(value, str) or not MAC_RE.fullmatch(value.strip()):
        return None
    return value.strip().lower().replace('-', ':')


def mac_properties(value: Any) -> dict[str, Any]:
    mac = normalize_mac(value)
    if not mac:
        return {'valid': False, 'kind': 'invalid', 'oui_lookup_allowed': False}
    first = int(mac[:2], 16)
    multicast = bool(first & 1)
    local = bool(first & 2)
    if multicast:
        kind = 'multicast/group address'
    elif local:
        kind = 'locally administered (private/randomized or manually set)'
    else:
        kind = 'globally administered unicast'
    return {
        'valid': True,
        'kind': kind,
        'locally_administered': local,
        'multicast': multicast,
        'oui_lookup_allowed': not local and not multicast,
    }


def _parse_assignment(value: str) -> str | None:
    raw = re.sub(r'[^0-9a-fA-F]', '', value or '').lower()
    if len(raw) not in (6, 7, 9):
        return None
    return raw


def _vendor_rows(path: Path) -> Iterable[tuple[str, str, str]]:
    try:
        if path.suffix.lower() == '.csv':
            with path.open('r', encoding='utf-8-sig', errors='replace', newline='') as stream:
                reader = csv.DictReader(stream)
                for row_no, row in enumerate(reader):
                    if row_no >= MAX_VENDOR_ROWS:
                        break
                    assignment = next((row.get(k) for k in ('Assignment', 'assignment', 'OUI', 'Registry Assignment') if row.get(k)), '')
                    organization = next((row.get(k) for k in ('Organization Name', 'Organization', 'organization', 'Company') if row.get(k)), '')
                    registry = next((row.get(k) for k in ('Registry', 'registry', 'Type') if row.get(k)), path.stem.upper())
                    prefix = _parse_assignment(str(assignment))
                    name = re.sub(r'\s+', ' ', str(organization)).strip()[:160]
                    if prefix and name:
                        yield prefix, name, str(registry).strip()[:16]
        else:
            with path.open('r', encoding='utf-8', errors='replace') as stream:
                for row_no, line in enumerate(stream):
                    if row_no >= MAX_VENDOR_ROWS:
                        break
                    match = re.match(r'^\s*([0-9a-fA-F:-]{6,20})\s+\((?:hex|base 16)\)\s+(.+?)\s*$', line)
                    if match:
                        prefix = _parse_assignment(match.group(1))
                        if prefix:
                            yield prefix, match.group(2).strip()[:160], 'MA-L'
    except OSError:
        return


def load_vendor_database(paths: Iterable[Path] = OUI_PATHS) -> dict[str, tuple[str, str]]:
    """Load IEEE MA-L/MA-M/MA-S data with a tiny mtime-aware process cache."""
    global _cache_signature, _vendor_cache
    signature: list[tuple[str, int, int]] = []
    existing: list[Path] = []
    for path in paths:
        try:
            stat_result = path.stat()
            if path.is_file() and not path.is_symlink():
                existing.append(path)
                signature.append((str(path), stat_result.st_mtime_ns, stat_result.st_size))
        except OSError:
            continue
    current_signature = tuple(signature)
    if current_signature == _cache_signature:
        return _vendor_cache
    result: dict[str, tuple[str, str]] = {}
    for path in existing:
        for prefix, organization, registry in _vendor_rows(path):
            prior = result.get(prefix)
            # Prefer the most specific block; duplicate same-length records
            # preserve the first one, with the explicit registry file order.
            if prior is None:
                result[prefix] = (organization, registry)
            elif prior and prior[0] == organization:
                result[prefix] = (organization, registry)
    _cache_signature = current_signature
    _vendor_cache = result
    return result


def update_vendor_database(directory: Path = OUI_DATA_DIR, timeout: float = 30.0) -> dict[str, Any]:
    """Refresh the local IEEE MA-L/MA-M/MA-S registries; client MACs never leave this host."""
    global _cache_signature
    if os.geteuid() != 0:
        raise PermissionError(f'Run with sudo: sudo {sbc_site.PREFIX}-admin oui update')
    if directory.is_symlink():
        raise RuntimeError('Refusing to update a symlinked IEEE data directory.')
    directory.mkdir(parents=True, exist_ok=True, mode=0o750)
    os.chmod(directory, 0o750)
    downloads: dict[str, bytes] = {}
    counts: dict[str, int] = {}
    for filename, url in IEEE_REGISTRIES.items():
        request = urllib.request.Request(url, headers={
            'User-Agent': f'{sbc_site.USER_AGENT} (local IEEE registry refresh)',
            'Accept': 'text/csv',
        })
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read(MAX_OUI_DOWNLOAD + 1)
        if not data or len(data) > MAX_OUI_DOWNLOAD:
            raise RuntimeError(f'IEEE {filename} is empty or exceeds the {MAX_OUI_DOWNLOAD} byte download limit.')
        rows = list(_vendor_rows_from_bytes(data, filename))
        if len(rows) < 100:
            raise RuntimeError(f'IEEE {filename} did not contain enough valid registry assignments ({len(rows)}).')
        downloads[filename] = data
        counts[filename] = len(rows)
    # Validate all three downloads before replacing any current registry file.
    for filename, data in downloads.items():
        destination = directory / filename
        if destination.is_symlink():
            raise RuntimeError(f'Refusing to replace symlinked IEEE registry file: {destination}')
        fd, temporary = tempfile.mkstemp(prefix=f'.{filename}.', dir=str(directory))
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o644)
            os.replace(temporary, destination)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    _cache_signature = None
    # Count from the validated downloads, including a caller-supplied test/data
    # directory, without depending on the system-wide default OUI_PATHS tuple.
    unique_prefixes = {prefix for filename, data in downloads.items()
                       for prefix, _organization, _registry in _vendor_rows_from_bytes(data, filename)}
    usable = len(unique_prefixes)
    return {
        'ok': True,
        'directory': str(directory),
        'registries': counts,
        'unique_assignments': usable,
        'message': f'Updated local IEEE MA-L, MA-M and MA-S registries ({usable:,} assignments before prefix de-duplication). No client MAC addresses were uploaded.',
    }


def _vendor_rows_from_bytes(data: bytes, filename: str) -> list[tuple[str, str, str]]:
    import io
    result = []
    reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig', errors='replace')))
    for row_no, row in enumerate(reader):
        if row_no >= MAX_VENDOR_ROWS:
            break
        assignment = next((row.get(k) for k in ('Assignment', 'assignment', 'OUI', 'Registry Assignment') if row.get(k)), '')
        organization = next((row.get(k) for k in ('Organization Name', 'Organization', 'organization', 'Company') if row.get(k)), '')
        registry = next((row.get(k) for k in ('Registry', 'registry', 'Type') if row.get(k)), Path(filename).stem.upper())
        prefix = _parse_assignment(str(assignment))
        name = re.sub(r'\s+', ' ', str(organization)).strip()[:160]
        if prefix and name:
            result.append((prefix, name, str(registry).strip()[:16]))
    return result


def lookup_vendor(value: Any, database: dict[str, tuple[str, str]] | None = None) -> dict[str, Any]:
    mac = normalize_mac(value)
    props = mac_properties(mac)
    if not props['valid']:
        return {'vendor': None, 'registry': None, 'oui': None, 'vendor_status': 'invalid MAC address'}
    if not props['oui_lookup_allowed']:
        return {'vendor': None, 'registry': None, 'oui': mac[:8].replace(':', '').upper(),
                'vendor_status': 'private/randomized or non-unicast MAC; vendor lookup intentionally skipped'}
    db = database if database is not None else load_vendor_database()
    compact = mac.replace(':', '').lower()
    for length in (9, 7, 6):
        match = db.get(compact[:length])
        if match:
            return {'vendor': match[0], 'registry': match[1], 'oui': compact[:length].upper(),
                    'vendor_status': 'IEEE address-block assignment'}
    return {'vendor': None, 'registry': None, 'oui': compact[:6].upper(),
            'vendor_status': 'no local IEEE registry match; database may be absent or stale'}


_HOST_HINTS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r'\b(his/1\.0|hisense|vidaa)\b', re.I), 'Hisense VIDAA TV', 'high'),
    (re.compile(r'\b(iphone|ipad|ipod|apple[-_ ]?tv|macbook|imac|mac[-_ ]?mini)\b', re.I), 'Apple device', 'medium'),
    (re.compile(r'\b(pixel|android|galaxy|samsung|oneplus|xiaomi|redmi|oppo|vivo|huawei)\b', re.I), 'Phone / tablet', 'medium'),
    (re.compile(r'\b(roku|fire[-_ ]?tv|chromecast|google[-_ ]?tv|hisense|bravia|tizen|webos|vidaa|smart[-_ ]?tv)\b', re.I), 'Smart TV / streaming device', 'medium'),
    (re.compile(r'\b(printer|hp[-_ ]?print|epson|brother[-_ ]?|canon[-_ ]?)\b', re.I), 'Printer', 'medium'),
    (re.compile(r'\b(laptop|desktop|windows|ubuntu|debian|arch|arxos|thinkpad|probook|elitebook|dell|latitude|macbook)\b', re.I), 'Computer', 'low'),
    (re.compile(r'\b(router|gateway|access[-_ ]?point|switch|ap[-_ ]?\d+)\b', re.I), 'Network equipment', 'medium'),
    (re.compile(r'(_googlecast\._tcp|chromecast|google cast)', re.I), 'Google Cast / streaming device', 'medium'),
    (re.compile(r'(_airplay\._tcp|_raop\._tcp|airplay)', re.I), 'AirPlay / media device', 'low'),
    (re.compile(r'(_ipp\._tcp|_printer\._tcp|printer)', re.I), 'Printer', 'medium'),
    (re.compile(r'(_spotify-connect\._tcp|spotify connect)', re.I), 'Audio streaming device', 'low'),
    (re.compile(r'\b(speaker|echo|alexa|nest|homepod|sonos)\b', re.I), 'Smart speaker', 'medium'),
)


def _classify(hostname: str | None, vendor: str | None, hints: list[str]) -> tuple[str, str, list[str]]:
    evidence: list[str] = []
    candidate_text = ' '.join([hostname or '', *hints])
    for pattern, label, confidence in _HOST_HINTS:
        if pattern.search(candidate_text):
            evidence.append('hostname/service advertisement pattern')
            if hints:
                evidence.append('passive mDNS/SSDP observation')
                return label, 'high' if confidence == 'medium' else confidence, evidence
            return label, confidence, evidence
    if vendor:
        evidence.append('IEEE MAC address-block registrant')
        return 'Networked device (type unknown)', 'low', evidence
    return 'Unknown network device', 'low', evidence


def enrich_client(client: dict[str, Any], database: dict[str, tuple[str, str]] | None = None,
                  labels: dict[str, str] | None = None, hints: list[str] | None = None) -> dict[str, Any]:
    result = dict(client)
    mac = normalize_mac(result.get('mac'))
    hostname = result.get('hostname') or result.get('name')
    props = mac_properties(mac)
    vendor = lookup_vendor(mac, database)
    if labels is None:
        labels = load_labels()
    label = labels.get(mac, '') if mac else ''
    observed_hints = list(hints or [])
    if isinstance(result.get('ip'), str):
        observed_hints.extend(recent_observations(ip=result['ip'], mac=mac))
    device_type, type_confidence, evidence = _classify(hostname, vendor.get('vendor'), observed_hints)
    evidence.extend(hint for hint in observed_hints if isinstance(hint, str) and hint.strip())
    evidence.extend(observed_hints[:8])
    if result.get('associated'):
        evidence.append('Wi-Fi association table')
    if hostname:
        evidence.append('DHCP hostname')
    if result.get('ip'):
        evidence.append('DHCP lease or IP neighbour record')
    confidence = 'high' if label else ('medium' if hostname and vendor.get('vendor') and props.get('oui_lookup_allowed') else 'low')
    result.update({
        'mac': mac or result.get('mac'),
        'mac_kind': props['kind'],
        'mac_locally_administered': props.get('locally_administered', False),
        'mac_vendor': vendor.get('vendor'),
        'mac_vendor_registry': vendor.get('registry'),
        'mac_vendor_oui': vendor.get('oui'),
        'mac_vendor_status': vendor.get('vendor_status'),
        'manufacturer_note': 'IEEE address-block assignee; this is not proof of the finished device brand or model.',
        'device_type': device_type,
        'device_type_confidence': type_confidence,
        'identity_label': label or hostname or device_type,
        'manual_label': label or None,
        'identity_confidence': confidence,
        'identity_evidence': list(dict.fromkeys(evidence)),
        'identity_note': ('Manually labelled by administrator.' if label else
                          'Best-effort identification. Private MAC randomization, spoofing and generic hostnames can prevent exact identification.'),
    })
    return result


def load_labels(path: Path = LABEL_PATH) -> dict[str, str]:
    try:
        if path.is_symlink() or not path.is_file():
            return {}
        info = path.stat()
        if info.st_size > 131072:
            return {}
        raw = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(raw, dict):
            return {}
        result: dict[str, str] = {}
        for mac, label in list(raw.items())[:MAX_LABELS]:
            normalized = normalize_mac(mac)
            if normalized and isinstance(label, str):
                cleaned = ''.join(ch for ch in label.strip() if ch >= ' ' and ch not in '\x7f')[:48]
                if cleaned:
                    result[normalized] = cleaned
        return result
    except (OSError, ValueError, TypeError):
        return {}


def set_label(mac: str, label: str, path: Path = LABEL_PATH) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise PermissionError(f'Run with sudo: sudo {sbc_site.PREFIX}-admin devices label MAC "Friendly name"')
    normalized = normalize_mac(mac)
    if not normalized or mac_properties(normalized).get('multicast'):
        raise ValueError('Supply a valid unicast MAC address.')
    if not isinstance(label, str):
        raise ValueError('Device label must be text.')
    cleaned = ''.join(ch for ch in label.strip() if ch >= ' ' and ch not in '\x7f')[:48]
    if not cleaned:
        raise ValueError('Device label cannot be empty.')
    labels = load_labels(path)
    if normalized not in labels and len(labels) >= MAX_LABELS:
        raise ValueError('Device label registry is full.')
    labels[normalized] = cleaned
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    if path.is_symlink():
        raise RuntimeError('Refusing to replace a symlinked device-label database.')
    fd, temp_name = tempfile.mkstemp(prefix='.device-labels-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(labels, stream, ensure_ascii=False, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
    return {'ok': True, 'mac': normalized, 'label': cleaned, 'message': f'Saved label for {normalized}.'}


def remove_label(mac: str, path: Path = LABEL_PATH) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise PermissionError(f'Run with sudo: sudo {sbc_site.PREFIX}-admin devices unlabel MAC')
    normalized = normalize_mac(mac)
    if not normalized:
        raise ValueError('Supply a valid MAC address.')
    labels = load_labels(path)
    labels.pop(normalized, None)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, temp_name = tempfile.mkstemp(prefix='.device-labels-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(labels, stream, ensure_ascii=False, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
    return {'ok': True, 'mac': normalized, 'message': f'Removed manual label for {normalized}.'}



def remember_observation(ip: str | None = None, mac: str | None = None,
                         hint: str = '', source: str = 'passive network observation') -> None:
    """Keep a bounded in-memory record of passive protocol hints for local attribution."""
    cleaned_hint = re.sub(r'\s+', ' ', str(hint)).strip()[:180]
    normalized_mac = normalize_mac(mac)
    if not cleaned_hint or (not isinstance(ip, str) and not normalized_mac):
        return
    try:
        normalized_ip = str(ipaddress.ip_address(ip)) if isinstance(ip, str) else None
    except ValueError:
        normalized_ip = None
    value = f'{source}: {cleaned_hint}'[:220]
    now = time.monotonic()
    with _observation_lock:
        for key, (expiry, _) in list(_observations_by_ip.items()):
            if expiry < now:
                _observations_by_ip.pop(key, None)
        for key, (expiry, _) in list(_observations_by_mac.items()):
            if expiry < now:
                _observations_by_mac.pop(key, None)
        if normalized_ip:
            expiry, values = _observations_by_ip.get(normalized_ip, (now + OBSERVATION_TTL, []))
            values = (values + [value])[-8:]
            _observations_by_ip[normalized_ip] = (now + OBSERVATION_TTL, list(dict.fromkeys(values)))
        if normalized_mac:
            expiry, values = _observations_by_mac.get(normalized_mac, (now + OBSERVATION_TTL, []))
            values = (values + [value])[-8:]
            _observations_by_mac[normalized_mac] = (now + OBSERVATION_TTL, list(dict.fromkeys(values)))
        while len(_observations_by_ip) > MAX_OBSERVATIONS:
            _observations_by_ip.pop(next(iter(_observations_by_ip)))
        while len(_observations_by_mac) > MAX_OBSERVATIONS:
            _observations_by_mac.pop(next(iter(_observations_by_mac)))


def recent_observations(ip: str | None = None, mac: str | None = None) -> list[str]:
    now = time.monotonic()
    result: list[str] = []
    normalized_mac = normalize_mac(mac)
    with _observation_lock:
        if isinstance(ip, str) and ip in _observations_by_ip:
            expiry, values = _observations_by_ip[ip]
            if expiry >= now:
                result.extend(values)
        if normalized_mac and normalized_mac in _observations_by_mac:
            expiry, values = _observations_by_mac[normalized_mac]
            if expiry >= now:
                result.extend(values)
    return list(dict.fromkeys(result))[:16]


def discover_neighbours(interface: str, subnet: str) -> list[dict[str, Any]]:
    """Read kernel neighbour table for one approved AP; never scans the subnet."""
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', interface):
        return []
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return []
    ip_cmd = shutil.which('ip') or '/usr/sbin/ip'
    try:
        completed = subprocess.run([ip_cmd, '-j', 'neigh', 'show', 'dev', interface],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True, timeout=3,
                                   check=False, env={**os.environ, 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        if completed.returncode != 0:
            return []
        rows = json.loads(completed.stdout)
    except Exception:
        return []
    result = []
    if not isinstance(rows, list):
        return []
    for row in rows[:512]:
        if not isinstance(row, dict):
            continue
        try:
            ip = str(ipaddress.ip_address(row.get('dst', '')))
        except ValueError:
            continue
        mac = normalize_mac(row.get('lladdr'))
        states = row.get('state', [])
        state_text = ','.join(states) if isinstance(states, list) else str(states)
        if ipaddress.ip_address(ip) not in network or not mac or 'FAILED' in state_text.upper() or 'INCOMPLETE' in state_text.upper():
            continue
        result.append({'ip': ip, 'mac': mac, 'neighbour_state': state_text[:80],
                       'associated': False, 'signal': None, 'radio': interface,
                       'discovery_source': 'kernel neighbour table'})
    return result


def enrich_clients(clients: list[dict[str, Any]], *, neighbours: list[dict[str, Any]] | None = None,
                   database: dict[str, tuple[str, str]] | None = None,
                   passive_fingerprints: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Merge station/lease and neighbour observations, then attach identity evidence."""
    merged: dict[str, dict[str, Any]] = {}
    by_ip: dict[str, str] = {}
    for client in clients:
        if not isinstance(client, dict):
            continue
        mac = normalize_mac(client.get('mac'))
        ip = client.get('ip')
        key = mac or (f'ip:{ip}' if isinstance(ip, str) else '')
        if not key:
            continue
        existing = merged.setdefault(key, {})
        existing.update(client)
        if isinstance(ip, str):
            by_ip[ip] = key
    for neighbour in neighbours or []:
        mac = normalize_mac(neighbour.get('mac')) if isinstance(neighbour, dict) else None
        ip = neighbour.get('ip') if isinstance(neighbour, dict) else None
        if not mac or not isinstance(ip, str):
            continue
        key = mac
        if ip in by_ip and by_ip[ip] != key:
            # Prefer the station/lease identity when the neighbour table conflicts.
            key = by_ip[ip]
        existing = merged.setdefault(key, {})
        for field, value in neighbour.items():
            existing.setdefault(field, value)
        existing.setdefault('discovery_source', neighbour.get('discovery_source', 'kernel neighbour table'))
        by_ip[ip] = key
    labels = load_labels()
    fingerprints = passive_fingerprints or {}
    enriched = []
    for row in merged.values():
        item = enrich_client(row, database=database, labels=labels)
        fingerprint = fingerprints.get(str(item.get('ip') or ''))
        if isinstance(fingerprint, dict) and isinstance(fingerprint.get('os'), str):
            item['passive_os'] = fingerprint['os'][:120]
            item['passive_os_confidence'] = 'medium'
            item['passive_os_source'] = 'p0f passive TCP/IP fingerprint'
            item['passive_os_seen'] = fingerprint.get('timestamp')
            item['identity_evidence'] = list(dict.fromkeys(
                list(item.get('identity_evidence') or []) + ['Passive TCP/IP OS fingerprint (p0f)']))
        enriched.append(item)
    return enriched
