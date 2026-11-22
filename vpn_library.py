"""WireGuard server library for the VPN tunnel: every Mullvad server by country, live switching
with an automatic undo, and an optional random rotation every few hours.

One Mullvad key works on every Mullvad server, so the whole server list comes from Mullvad's
public relay list and the key already in the tunnel's config. Config files downloaded from
Mullvad (a .zip or single .conf files) can be imported too; a file with a different key adds
that key, and its servers then switch the tunnel to it.

Where things live (root only):
  <etc>/vpn/servers.json   public data: hostnames, countries, endpoints, server public keys
  <etc>/vpn/keys.json      private keys and tunnel addresses from imported configs (0600)
  <etc>/vpn/state.json     rotation settings and the switch history
  /etc/wireguard/<vpn>.conf the live tunnel; only its [Peer] (and, for another key, the
                            PrivateKey and Address lines) are ever rewritten

Switching rewrites the config, applies it (wg syncconf for the same key: no interface drop;
a restart of the tunnel unit for another key), then waits for a handshake with the new server
and a reply through it. If either does not come, the previous config is put back.
"""
from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import os
import random
import re
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import sbc_site

SITE = sbc_site.load()
IFACE = SITE['vpn_interface']
UNIT = SITE['vpn_unit']
LIB_DIR = sbc_site.ETC_DIR / 'vpn'
SERVERS_PATH = LIB_DIR / 'servers.json'
KEYS_PATH = LIB_DIR / 'keys.json'
STATE_PATH = LIB_DIR / 'state.json'
WG_DIR = Path('/etc/wireguard')
CONF_PATH = WG_DIR / f'{IFACE}.conf'
RELAYS_URL = 'https://api.mullvad.net/www/relays/wireguard/'
PROBE_ADDRESS = '10.64.0.1'  # Mullvad's resolver inside every tunnel; it answers ping
WG = '/usr/bin/wg'
WG_QUICK = '/usr/bin/wg-quick'
SYSTEMCTL = '/usr/bin/systemctl'
PING = '/usr/bin/ping'
CURL = '/usr/bin/curl'
EXIT_CHECK_URL = 'https://am.i.mullvad.net/json'  # asked through the tunnel itself

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_ZIP_ENTRIES = 3000
MAX_CONF_BYTES = 8192
MAX_RELAY_BYTES = 4 * 1024 * 1024
ROTATION_HOURS = (1, 2, 3, 4, 6, 8, 12, 24)
HISTORY_LIMIT = 30

_KEY = re.compile(r'[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=')
_HOST = re.compile(r'[a-z]{2}-[a-z0-9]{2,5}-(?:wg|ovpn|br)-[0-9a-z-]{1,12}')
_CC = re.compile(r'[a-z]{2}')
_lock = threading.RLock()
_last_refresh = 0.0
_last_latency = 0.0
_exit_cache: dict[str, Any] = {'at': 0.0, 'info': None}
# the live connection log the page shows while a switch runs (and after it, until the next one)
_job: dict[str, Any] = {'id': None, 'state': 'idle', 'kind': None, 'lines': [], 'started': None, 'finished': None, 'result': None}
_job_lock = threading.Lock()


def _log(message: str, level: str = 'info') -> None:
    with _job_lock:
        _job['lines'].append({'t': round(time.time(), 2), 'msg': str(message)[:300], 'level': level})
        del _job['lines'][:-80]


def job_status() -> dict[str, Any]:
    with _job_lock:
        return {'ok': True, 'job': {**_job, 'lines': list(_job['lines'])}}


def _begin_job(kind: str) -> str:
    with _job_lock:
        if _job['state'] == 'running':
            raise VpnError('A server switch is already in progress.')
        _job.update(id=secrets.token_hex(6), state='running', kind=kind, lines=[], started=time.time(), finished=None, result=None)
        return _job['id']


def _end_job(result: dict[str, Any]) -> None:
    with _job_lock:
        _job.update(state='done' if result.get('ok') else 'failed', finished=time.time(), result=result)


def _job_body(fn, *args) -> dict[str, Any]:
    try:
        result = fn(*args)
    except Exception as exc:  # the log must always end, whatever went wrong
        _log(str(exc), 'error')
        result = {'ok': False, 'error': str(exc)}
    _end_job(result)
    return result


def start_switch_job(kind: str, fn, *args) -> dict[str, Any]:
    """Run a switch in the background; the page follows it through job_status()."""
    job_id = _begin_job(kind)
    threading.Thread(target=_job_body, args=(fn, *args), daemon=True, name=f'vpn-{kind}').start()
    return {'ok': True, 'job': job_id, 'message': 'Switching…'}


class VpnError(RuntimeError):
    pass


# ---------------------------------------------------------------- files

def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return default
    except Exception as exc:
        raise VpnError(f'{path.name} is unreadable: {exc}') from exc


def _write_private(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f'.{path.name}.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _write_json(path: Path, data: Any) -> None:
    _write_private(path, json.dumps(data, indent=2, ensure_ascii=False) + '\n')


def _run(args: list[str], timeout: float = 20, stdin: str | None = None) -> tuple[int, str]:
    try:
        cp = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, str(exc)
    return cp.returncode, (cp.stdout or '') + (cp.stderr or '')


# ---------------------------------------------------------------- wg-quick configs

def parse_conf(text: str) -> dict[str, Any]:
    """[Interface] keys and the [Peer] blocks of a wg-quick file (case-insensitive keys)."""
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    section = None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line.startswith('['):
            section = line.strip('[] ').lower()
            if section == 'peer':
                peers.append({})
            continue
        if '=' not in line:
            continue
        key, value = (part.strip() for part in line.split('=', 1))
        target = interface if section == 'interface' else peers[-1] if section == 'peer' and peers else None
        if target is not None:
            target[key.lower()] = value
    return {'interface': interface, 'peers': peers}


def _valid_endpoint(value: str) -> tuple[str, int] | None:
    match = re.fullmatch(r'\[?([0-9a-fA-F:.]+)\]?:([0-9]{1,5})', value or '')
    if not match:
        return None
    try:
        ip = ipaddress.ip_address(match.group(1))
    except ValueError:
        return None
    port = int(match.group(2))
    if not 1 <= port <= 65535 or not ip.is_global:
        return None
    return str(ip), port


def _valid_addresses(value: str) -> str | None:
    parts = [p.strip() for p in (value or '').split(',') if p.strip()]
    if not 1 <= len(parts) <= 2:
        return None
    try:
        for part in parts:
            ipaddress.ip_interface(part)
    except ValueError:
        return None
    return ','.join(parts)


def public_key_of(private_key: str) -> str:
    code, out = _run([WG, 'pubkey'], timeout=5, stdin=private_key + '\n')
    out = out.strip()
    if code != 0 or not _KEY.fullmatch(out):
        raise VpnError('Could not derive the public key of a tunnel key.')
    return out


def key_id(public_key: str) -> str:
    return hashlib.sha256(public_key.encode()).hexdigest()[:12]


def _live_conf() -> tuple[str, dict[str, Any]]:
    try:
        text = CONF_PATH.read_text(encoding='utf-8')
    except OSError as exc:
        raise VpnError(f'The tunnel config {CONF_PATH} is unreadable.') from exc
    return text, parse_conf(text)


def _render_conf(live_text: str, private_key: str | None, address: str | None, peer: dict[str, Any]) -> str:
    """The live file with its [Peer] replaced; for another key, PrivateKey and Address too.
    Every other [Interface] line (PostUp, Table, DNS, comments) stays exactly as it was."""
    head = re.split(r'(?im)^\s*\[peer\]', live_text, maxsplit=1)[0].rstrip() + '\n'
    if private_key is not None:
        head = re.sub(r'(?im)^(\s*PrivateKey\s*=\s*).*$', lambda m: m.group(1) + private_key, head, count=1)
    if address is not None:
        head = re.sub(r'(?im)^(\s*Address\s*=\s*).*$', lambda m: m.group(1) + address, head, count=1)
    host = peer.get('hostname', 'server')
    return (head + f"\n[Peer]\n# {host}\nPublicKey = {peer['pubkey']}\nAllowedIPs = 0.0.0.0/0, ::/0\n"
            f"Endpoint = {peer['ipv4']}:{peer['port']}\n")


# ---------------------------------------------------------------- library

def _country_from_host(hostname: str) -> str:
    return hostname[:2] if _HOST.fullmatch(hostname) else ''


def _load_servers() -> dict[str, Any]:
    data = _read_json(SERVERS_PATH, {'servers': [], 'updated': None})
    return data if isinstance(data, dict) and isinstance(data.get('servers'), list) else {'servers': [], 'updated': None}


def _merge_servers(new: list[dict[str, Any]], source: str) -> int:
    data = _load_servers()
    by_host = {s['hostname']: s for s in data['servers'] if isinstance(s, dict) and s.get('hostname')}
    for server in new:
        old = by_host.get(server['hostname'], {})
        # an imported config's key choice survives a later relay-list refresh
        if source == 'mullvad-list' and old.get('key_id'):
            server['key_id'] = old['key_id']
        by_host[server['hostname']] = {**old, **server}
    if source == 'mullvad-list':
        listed = {s['hostname'] for s in new}
        for host, server in by_host.items():
            if server.get('source') == 'mullvad-list' and host not in listed:
                server['active'] = False
    data['servers'] = sorted(by_host.values(), key=lambda s: (s.get('country', ''), s.get('city', ''), s['hostname']))
    data['updated'] = int(time.time())
    _write_json(SERVERS_PATH, data)
    return len(new)


def refresh_relays() -> dict[str, Any]:
    """Mullvad's public WireGuard relay list: no account data is sent."""
    global _last_refresh
    with _lock:
        if time.time() - _last_refresh < 300:
            raise VpnError('The server list was refreshed in the last 5 minutes.')
        _last_refresh = time.time()
    request = urllib.request.Request(RELAYS_URL, headers={'User-Agent': sbc_site.USER_AGENT, 'Accept': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=25) as response:
            raw = response.read(MAX_RELAY_BYTES + 1)
    except Exception as exc:
        raise VpnError(f'Mullvad server list unreachable: {exc}') from exc
    if len(raw) > MAX_RELAY_BYTES:
        raise VpnError('The server list exceeded its size limit.')
    try:
        relays = json.loads(raw)
    except ValueError as exc:
        raise VpnError('The server list is not valid JSON.') from exc
    servers = []
    for relay in relays if isinstance(relays, list) else []:
        if not isinstance(relay, dict) or relay.get('type', 'wireguard') != 'wireguard':
            continue
        host = str(relay.get('hostname', ''))
        endpoint = _valid_endpoint(f"{relay.get('ipv4_addr_in', '')}:51820")
        cc = str(relay.get('country_code', '')).lower()
        if not _HOST.fullmatch(host) or not endpoint or not _KEY.fullmatch(str(relay.get('pubkey', ''))) or not _CC.fullmatch(cc):
            continue
        servers.append({
            'hostname': host, 'country_code': cc,
            'country': str(relay.get('country_name', cc.upper()))[:48],
            'city': str(relay.get('city_name', ''))[:48],
            'ipv4': endpoint[0], 'port': endpoint[1], 'pubkey': relay['pubkey'],
            'owned': bool(relay.get('owned')), 'provider': str(relay.get('provider', ''))[:48],
            'active': bool(relay.get('active')), 'source': 'mullvad-list',
        })
    if len(servers) < 10:
        raise VpnError('The server list had too few valid servers; nothing was changed.')
    with _lock:
        count = _merge_servers(servers, 'mullvad-list')
    return {'ok': True, 'message': f'{count} servers from Mullvad\'s list.', 'count': count}


def import_configs(data: bytes, filename: str) -> dict[str, Any]:
    """Import Mullvad config files (.zip or .conf). Keys go to keys.json, servers to the library."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise VpnError('The file is larger than 2 MB.')
    files: list[tuple[str, str]] = []
    if data[:4] == b'PK\x03\x04':
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as exc:
            raise VpnError('The zip file is damaged.') from exc
        entries = archive.infolist()
        if len(entries) > MAX_ZIP_ENTRIES:
            raise VpnError('The zip holds too many files.')
        for entry in entries:
            name = os.path.basename(entry.filename)
            if entry.is_dir() or not name.endswith('.conf'):
                continue
            if entry.file_size > MAX_CONF_BYTES:
                raise VpnError(f'{name} is too large for a WireGuard config.')
            with archive.open(entry) as member:  # a stream read with a limit: a lying header cannot inflate it
                files.append((name, member.read(MAX_CONF_BYTES + 1)[:MAX_CONF_BYTES].decode('utf-8', 'replace')))
    else:
        files.append((os.path.basename(filename or 'upload.conf'), data[:MAX_CONF_BYTES].decode('utf-8', 'replace')))
    if not files:
        raise VpnError('No .conf files were found.')
    keys = _read_json(KEYS_PATH, {})
    keys = keys if isinstance(keys, dict) else {}
    pub_cache: dict[str, str] = {}
    servers, skipped = [], 0
    for name, text in files:
        conf = parse_conf(text)
        iface, peers = conf['interface'], conf['peers']
        private_key = iface.get('privatekey', '')
        address = _valid_addresses(iface.get('address', ''))
        if not _KEY.fullmatch(private_key) or not address or len(peers) != 1:
            skipped += 1
            continue
        peer = peers[0]
        endpoint = _valid_endpoint(peer.get('endpoint', ''))
        if not endpoint or not _KEY.fullmatch(peer.get('publickey', '')):
            skipped += 1
            continue
        if private_key not in pub_cache:
            pub_cache[private_key] = public_key_of(private_key)
        kid = key_id(pub_cache[private_key])
        keys.setdefault(kid, {'private_key': private_key, 'address': address, 'added': int(time.time())})
        host = name[:-5]
        cc = _country_from_host(host)
        if not cc:
            host, cc = f'imported-{hashlib.sha256(peer["publickey"].encode()).hexdigest()[:8]}', 'xx'
        servers.append({'hostname': host, 'country_code': cc, 'country': cc.upper(), 'city': host[3:6].upper(),
                        'ipv4': endpoint[0], 'port': endpoint[1], 'pubkey': peer['publickey'],
                        'active': True, 'source': 'upload', 'key_id': kid})
    if not servers:
        raise VpnError(f'None of the {len(files)} files is a usable WireGuard config.')
    with _lock:
        _write_json(KEYS_PATH, keys)
        _merge_servers(servers, 'upload')
    return {'ok': True, 'imported': len(servers), 'skipped': skipped, 'keys': len(pub_cache),
            'message': f'Imported {len(servers)} servers' + (f', skipped {skipped} files' if skipped else '') + '.'}


# ---------------------------------------------------------------- live state

def _wg_dump() -> dict[str, Any]:
    code, out = _run([WG, 'show', IFACE, 'dump'], timeout=5)
    if code != 0:
        return {'up': False}
    lines = out.strip().splitlines()
    first = lines[0].split('\t') if lines else []
    peers = []
    for line in lines[1:]:
        f = line.split('\t')
        if len(f) >= 8:
            peers.append({'pubkey': f[0], 'endpoint': f[2], 'handshake': int(f[4] or 0), 'rx': int(f[5] or 0), 'tx': int(f[6] or 0)})
    return {'up': True, 'public_key': first[1] if len(first) > 1 else '', 'peers': peers}


def active() -> dict[str, Any]:
    dump = _wg_dump()
    peer = dump.get('peers', [{}])[0] if dump.get('peers') else {}
    servers = _load_servers()['servers']
    match = next((s for s in servers if s.get('pubkey') == peer.get('pubkey')), None)
    return {
        'up': dump.get('up', False), 'key_id': key_id(dump['public_key']) if dump.get('public_key') else None,
        'server': {k: match.get(k) for k in ('hostname', 'country', 'country_code', 'city', 'ipv4')} if match else None,
        'endpoint': peer.get('endpoint'), 'handshake': peer.get('handshake') or None,
        'rx': peer.get('rx', 0), 'tx': peer.get('tx', 0),
    }


def exit_info(force: bool = False) -> dict[str, Any] | None:
    """Where traffic leaves the tunnel, as Mullvad sees it (asked through the tunnel, cached 2 min)."""
    if not force and time.time() - _exit_cache['at'] < 120:
        return _exit_cache['info']
    code, out = _run([CURL, '-fsS', '--max-time', '8', '--interface', IFACE, EXIT_CHECK_URL], timeout=10)
    info = None
    if code == 0:
        try:
            data = json.loads(out)
            info = {'ip': str(data.get('ip', ''))[:45], 'country': str(data.get('country', ''))[:48],
                    'city': str(data.get('city', ''))[:48], 'via_mullvad': bool(data.get('mullvad_exit_ip')),
                    'hostname': str(data.get('mullvad_exit_ip_hostname') or '')[:40]}
        except ValueError:
            info = None
    _exit_cache.update({'at': time.time(), 'info': info})
    return info


def _state() -> dict[str, Any]:
    state = _read_json(STATE_PATH, {})
    state = state if isinstance(state, dict) else {}
    rotation = state.get('rotation') if isinstance(state.get('rotation'), dict) else {}
    state['rotation'] = {
        'enabled': bool(rotation.get('enabled')),
        'hours': rotation.get('hours') if rotation.get('hours') in ROTATION_HOURS else 6,
        'countries': [c for c in rotation.get('countries', []) if isinstance(c, str) and _CC.fullmatch(c)][:60],
    }
    state['history'] = [h for h in state.get('history', []) if isinstance(h, dict)][-HISTORY_LIMIT:]
    state['last_switch'] = state.get('last_switch') if isinstance(state.get('last_switch'), (int, float)) else None
    state['latency'] = state.get('latency') if isinstance(state.get('latency'), dict) else {}
    return state


def library() -> dict[str, Any]:
    data = _load_servers()
    state = _state()
    keys = _read_json(KEYS_PATH, {})
    countries: dict[str, dict[str, Any]] = {}
    for s in data['servers']:
        if not s.get('active', True):
            continue
        c = countries.setdefault(s['country_code'], {'code': s['country_code'], 'name': s.get('country', s['country_code'].upper()), 'servers': []})
        c['servers'].append({k: s.get(k) for k in ('hostname', 'city', 'ipv4', 'owned', 'provider', 'source')} |
                            {'latency_ms': state['latency'].get(s['hostname']), 'own_key': bool(s.get('key_id'))})
    return {
        'ok': True, 'interface': IFACE, 'unit': UNIT, 'active': active(),
        'countries': sorted(countries.values(), key=lambda c: c['name']),
        'server_count': sum(len(c['servers']) for c in countries.values()),
        'updated': data.get('updated'), 'imported_keys': len(keys) if isinstance(keys, dict) else 0,
        'rotation': state['rotation'], 'last_switch': state['last_switch'], 'history': state['history'][-10:],
        'exit': exit_info(), 'latency_at': state.get('latency_at'),
    }


# ---------------------------------------------------------------- switching

def _apply(text: str, restart: bool) -> None:
    _write_private(CONF_PATH, text)
    if restart:
        code, out = _run([SYSTEMCTL, 'restart', f'{UNIT}.service'], timeout=40)
        if code != 0:
            raise VpnError(f'The tunnel did not restart: {out.strip()[:300]}')
        return
    code, stripped = _run([WG_QUICK, 'strip', IFACE], timeout=10)
    if code != 0:
        raise VpnError(f'wg-quick strip failed: {stripped.strip()[:300]}')
    fd, tmp = tempfile.mkstemp(prefix='.sync.', dir=str(LIB_DIR))
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(stripped)
        os.chmod(tmp, 0o600)
        code, out = _run([WG, 'syncconf', IFACE, tmp], timeout=10)
    finally:
        os.unlink(tmp)
    if code != 0:
        raise VpnError(f'wg syncconf failed: {out.strip()[:300]}')


def _verify(pubkey: str, since: float, timeout: float = 15, log: bool = True) -> bool:
    deadline = time.time() + timeout
    handshake_logged = False
    while time.time() < deadline:
        _run([PING, '-n', '-c', '1', '-W', '2', '-I', IFACE, PROBE_ADDRESS], timeout=4)
        dump = _wg_dump()
        peer = next((p for p in dump.get('peers', []) if p['pubkey'] == pubkey), None)
        if peer and peer['handshake'] >= int(since) - 1:
            if log and not handshake_logged:
                _log(f'Handshake done after {time.time() - since:.1f} s', 'ok')
                handshake_logged = True
            code, out = _run([PING, '-n', '-c', '2', '-W', '2', '-I', IFACE, PROBE_ADDRESS], timeout=6)
            if code == 0:
                if log:
                    rtt = re.search(r'= [0-9.]+/([0-9.]+)/', out)
                    _log(f"Reply through the tunnel from {PROBE_ADDRESS}" + (f' in {float(rtt.group(1)):.0f} ms' if rtt else ''), 'ok')
                return True
        time.sleep(1)
    return False


def switch(hostname: str, reason: str = 'manual') -> dict[str, Any]:
    if not isinstance(hostname, str) or not (_HOST.fullmatch(hostname) or re.fullmatch(r'imported-[0-9a-f]{8}', hostname)):
        raise VpnError('Unknown server name.')
    with _lock:
        server = next((s for s in _load_servers()['servers'] if s.get('hostname') == hostname), None)
        if not server or not server.get('active', True):
            raise VpnError(f'{hostname} is not in the server library.')
        place = ', '.join(p for p in (server.get('city'), server.get('country')) if p)
        _log(f'Switching to {hostname} ({place})')
        live_text, live = _live_conf()
        previous = (active().get('server') or {}).get('hostname') or 'the previous server'
        current_pub = _wg_dump().get('public_key', '')
        current_kid = key_id(current_pub) if current_pub else None
        private_key = address = None
        if server.get('key_id') and server['key_id'] != current_kid:
            keys = _read_json(KEYS_PATH, {})
            entry = keys.get(server['key_id']) if isinstance(keys, dict) else None
            if not entry:
                raise VpnError('The key for this server is missing; import its config again.')
            private_key, address = entry['private_key'], entry['address']
        new_text = _render_conf(live_text, private_key, address, server)
        restart = private_key is not None
        started = time.time()
        _log(f"Writing the tunnel config: server key {server['pubkey'][:8]}…, endpoint {server['ipv4']}:{server['port']}")
        try:
            if restart:
                _log('This server uses another key from your account: restarting the tunnel with it')
            else:
                _log('Applying it live (the interface and its routes stay up)')
            _apply(new_text, restart)
            _log(f'Waiting for the handshake with {hostname}…')
            ok = _verify(server['pubkey'], started)
        except VpnError as exc:
            _log(str(exc), 'error')
            ok = False
        if not ok:
            _log(f'{hostname} did not answer within 15 s', 'error')
            _log(f'Restoring {previous}…', 'warn')
            try:
                _apply(live_text, restart)
                back = _verify(parse_conf(live_text)['peers'][0].get('publickey', ''), time.time(), timeout=12, log=False)
                _log(f'Back on {previous}' if back else f'{previous} restored; its handshake is still pending', 'ok' if back else 'warn')
            except Exception as exc:
                _log(f'Restoring failed: {exc}', 'error')
            raise VpnError(f'{hostname} did not answer through the tunnel within 15 s; the previous server was restored.')
        state = _state()
        state['last_switch'] = int(time.time())
        state['history'].append({'at': int(time.time()), 'hostname': hostname, 'country': server.get('country'),
                                 'city': server.get('city'), 'reason': reason[:24]})
        state['history'] = state['history'][-HISTORY_LIMIT:]
        _write_json(STATE_PATH, state)
    _log('Asking Mullvad where traffic now leaves…')
    exit_now = exit_info(force=True)
    if exit_now:
        _log(f"Exit confirmed: {exit_now['city']}, {exit_now['country']} ({exit_now['ip']})"
             + (' · Mullvad server' if exit_now.get('via_mullvad') else ''), 'ok' if exit_now.get('via_mullvad') else 'warn')
    else:
        _log('The exit check did not answer; the tunnel itself is up', 'warn')
    took = round(time.time() - started, 1)
    _log(f'Connected through {hostname} in {took} s', 'ok')
    return {'ok': True, 'message': f"Connected through {hostname} ({place}).", 'took_seconds': took}


def random_server(countries: list[str] | None = None, exclude: str | None = None) -> str:
    pool = [s for s in _load_servers()['servers']
            if s.get('active', True) and s['hostname'] != exclude
            and (not countries or s['country_code'] in countries)]
    if not pool:
        raise VpnError('No server matches the chosen countries.')
    return random.SystemRandom().choice(pool)['hostname']


def switch_random(countries: list[str] | None = None, reason: str = 'random') -> dict[str, Any]:
    current = (active().get('server') or {}).get('hostname')
    errors = []
    for attempt in range(3):
        host = random_server(countries, exclude=current)
        if attempt:
            _log(f'Trying another server ({attempt + 1} of 3)', 'warn')
        try:
            return switch(host, reason)
        except VpnError as exc:
            errors.append(str(exc))
            current = host
    raise VpnError('Three servers in a row failed: ' + ' | '.join(errors)[:600])


def set_rotation(enabled: Any, hours: Any, countries: Any) -> dict[str, Any]:
    if not isinstance(enabled, bool) or hours not in ROTATION_HOURS or not isinstance(countries, list):
        raise VpnError('Rotation needs on/off, one of the offered intervals, and a list of countries.')
    countries = sorted({c for c in countries if isinstance(c, str) and _CC.fullmatch(c)})[:60]
    known = {s['country_code'] for s in _load_servers()['servers'] if s.get('active', True)}
    if any(c not in known for c in countries):
        raise VpnError('A chosen country has no servers in the library.')
    with _lock:
        state = _state()
        state['rotation'] = {'enabled': enabled, 'hours': hours, 'countries': countries}
        if enabled and not state.get('last_switch'):
            state['last_switch'] = int(time.time())
        _write_json(STATE_PATH, state)
    return {'ok': True, 'message': (f"Rotating every {hours} h among {', '.join(c.upper() for c in countries) or 'all countries'}."
                                    if enabled else 'Rotation is off.')}


def rotation_due(now: float | None = None) -> bool:
    state = _state()
    rotation = state['rotation']
    if not rotation['enabled']:
        return False
    last = state.get('last_switch') or 0
    return (now or time.time()) - last >= rotation['hours'] * 3600


def rotation_tick() -> dict[str, Any] | None:
    """Called about once a minute by the agent: switch when the interval has passed."""
    if not rotation_due():
        return None
    countries = _state()['rotation']['countries'] or None
    try:
        _begin_job('rotation')
    except VpnError:
        return None  # a manual switch is running; check again next minute
    _log('Scheduled rotation')
    result = _job_body(switch_random, countries, 'rotation')
    if result.get('ok'):
        return result
    error = str(result.get('error', 'rotation failed'))
    with _lock:
        state = _state()
        # try again in an hour rather than every minute
        state['last_switch'] = int(time.time()) - max(0, state['rotation']['hours'] * 3600 - 3600)
        state['history'].append({'at': int(time.time()), 'hostname': None, 'reason': 'rotation failed', 'error': error[:200]})
        _write_json(STATE_PATH, state)
    return {'ok': False, 'error': error}


# ---------------------------------------------------------------- latency

def _ping_ms(ip: str) -> float | None:
    code, out = _run([PING, '-n', '-q', '-c', '3', '-i', '0.2', '-W', '1', ip], timeout=6)
    match = re.search(r'= [0-9.]+/([0-9.]+)/', out)
    return round(float(match.group(1)), 1) if code == 0 and match else None


def measure_latency(country: str | None = None) -> dict[str, Any]:
    """Round trip from this server to each VPN server's entry address (outside the tunnel)."""
    global _last_latency
    with _lock:
        if time.time() - _last_latency < 20:
            raise VpnError('A latency measurement ran in the last 20 seconds.')
        _last_latency = time.time()
    servers = [s for s in _load_servers()['servers'] if s.get('active', True) and (not country or s['country_code'] == country)]
    if country and not servers:
        raise VpnError('No servers in that country.')
    servers = servers[:600]
    with ThreadPoolExecutor(max_workers=24) as pool:
        results = dict(zip((s['hostname'] for s in servers), pool.map(lambda s: _ping_ms(s['ipv4']), servers)))
    with _lock:
        state = _state()
        state['latency'].update(results)
        state['latency_at'] = int(time.time())
        _write_json(STATE_PATH, state)
    reached = sorted((ms, host) for host, ms in results.items() if ms is not None)
    return {'ok': True, 'measured': len(results), 'reached': len(reached),
            'fastest': [{'hostname': h, 'latency_ms': ms} for ms, h in reached[:5]]}


# ---------------------------------------------------------------- second tunnel (per-device routing)

SECOND_IFACE = f'{IFACE}2'[:15]
SECOND_CONF = WG_DIR / f'{SECOND_IFACE}.conf'
SECOND_TABLE = 201


def second_up(hostname: str) -> dict[str, Any]:
    """A second tunnel to another server, for devices routed to it. Its default route lives only
    in table 201 (with an unreachable fallback), so nothing else ever uses it."""
    server = next((s for s in _load_servers()['servers'] if s.get('hostname') == hostname and s.get('active', True)), None)
    if not server:
        raise VpnError(f'{hostname} is not in the server library.')
    live = parse_conf(_live_conf()[0])['interface']
    private_key, address = live.get('privatekey', ''), live.get('address', '')
    if server.get('key_id'):
        keys = _read_json(KEYS_PATH, {})
        entry = keys.get(server['key_id']) if isinstance(keys, dict) else None
        if entry:
            private_key, address = entry['private_key'], entry['address']
    if not _KEY.fullmatch(private_key) or not _valid_addresses(address):
        raise VpnError('No usable key for the second tunnel.')
    ipv4 = ','.join(a for a in address.split(',') if ':' not in a)
    text = (f"[Interface]\n# second tunnel for per-device routing ({hostname})\nPrivateKey = {private_key}\nAddress = {ipv4}\n"
            f"Table = off\nPostUp = ip route replace default dev %i table {SECOND_TABLE}\n"
            f"PreDown = ip route del default dev %i table {SECOND_TABLE}\n\n"
            f"[Peer]\nPublicKey = {server['pubkey']}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {server['ipv4']}:{server['port']}\n"
            "PersistentKeepalive = 25\n")
    _write_private(SECOND_CONF, text)
    _log(f'Second tunnel: connecting to {hostname} ({server.get("city")}, {server.get("country")})')
    code, out = _run([SYSTEMCTL, 'restart', f'wg-quick@{SECOND_IFACE}.service'], timeout=40)
    if code != 0:
        raise VpnError(f'The second tunnel did not start: {out.strip()[:300]}')
    started = time.time()
    deadline = started + 15
    while time.time() < deadline:
        _run([PING, '-n', '-c', '1', '-W', '2', '-I', SECOND_IFACE, PROBE_ADDRESS], timeout=4)
        code, hs = _run([WG, 'show', SECOND_IFACE, 'latest-handshakes'], timeout=5)
        parts = hs.split()
        if code == 0 and len(parts) > 1 and parts[1].isdigit() and int(parts[1]) >= int(started) - 1:
            _run([SYSTEMCTL, 'enable', f'wg-quick@{SECOND_IFACE}.service'], timeout=10)
            _log(f'Second tunnel up through {hostname}', 'ok')
            return {'ok': True, 'message': f'Second tunnel up through {hostname}.', 'hostname': hostname}
        time.sleep(1)
    second_down()
    raise VpnError(f'{hostname} gave no handshake on the second tunnel within 15 s; it was taken down.')


def second_down() -> dict[str, Any]:
    _run([SYSTEMCTL, 'disable', '--now', f'wg-quick@{SECOND_IFACE}.service'], timeout=30)
    return {'ok': True, 'message': 'Second tunnel stopped; devices routed to it are cut off until it is back.'}
