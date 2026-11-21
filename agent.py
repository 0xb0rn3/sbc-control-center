#!/usr/bin/env python3
"""Root-side, allow-listed control agent for SBC Control Center."""
from __future__ import annotations

import json
import os
import selectors
import codecs
import platform
import re
import shutil
import socket
import secrets
import subprocess
import threading
import time
import uuid
import tarfile
import hashlib
import hmac
import tempfile
import grp
import ipaddress
import shlex
import struct
import pwd
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import telemetry
import realtime_telemetry
import network_observability
import pam_auth

BASE = Path('/etc/sbc-control-center')
STATE = Path('/var/lib/sbc-control-center')
SOCKET_DIR = Path('/run/sbc-control-center')
SOCKET_PATH = SOCKET_DIR / 'agent.sock'
CONFIG_PATH = BASE / 'config.json'
UPDATE_SOURCE_PATH = BASE / 'update-source.json'
UPDATE_STATE_PATH = STATE / 'portal-update.json'
PRIVILEGE_CONFIG_PATH = BASE / 'privilege.json'
APP_VERSION_PATH = Path('/opt/sbc-control-center/VERSION')
PORTAL_UPDATE_INTERVAL_SECONDS = 6 * 60 * 60
MAX_CONSOLE_OUTPUT = 16_000
PRIVILEGE_GRANT_TTL = 120

DEFAULT_CONFIG = {
    'ap_interface': 'wlan1',
    'ap_ssid': 'SBC-5G',
    'ap_ip': '10.50.0.1',
    'ap_subnet': '10.50.0.0/24',
    'vpn_interface': 'wg0',
    'vpn_unit': 'wg-quick@wg0',
    'dhcp_lease_file': '/var/lib/misc/dnsmasq.leases',
    'ap2_interface': 'wlan0',
    'ap2_ssid': 'SBC-2G',
    'ap2_ip': '10.60.0.1',
    'ap2_subnet': '10.60.0.0/24',
}

SERVICE_LABELS = {
    'hostapd': 'Wi-Fi access point · 5 GHz',
    'hostapd-2g': 'Wi-Fi access point · 2.4 GHz',
    'dnsmasq': 'DHCP service',
    'apguard': 'VPN kill-switch firewall',
    'ap-iface': '5 GHz AP interface and policy routing',
    'ap2-iface': '2.4 GHz AP interface and policy routing',
    'wg-quick@wg0': 'WireGuard tunnel',
    'systemd-networkd': 'Network management',
    'ssh': 'SSH access',
    'sbc-control-center-agent': 'Control Center privileged agent',
    'sbc-control-center-web': 'Control Center web portal',
}

# The web portal cannot send arbitrary unit names or command arguments.
CONTROL_SERVICES = {
    'hostapd': {'start', 'stop', 'restart', 'enable', 'disable'},
    'hostapd-2g': {'start', 'stop', 'restart', 'enable', 'disable'},
    'dnsmasq': {'start', 'stop', 'restart', 'enable', 'disable'},
    'wg-quick@wg0': {'start', 'stop', 'restart', 'enable', 'disable'},
    'apguard': {'start', 'restart', 'enable'},
    'ap-iface': {'start', 'restart', 'enable'},
    'ap2-iface': {'start', 'restart', 'enable'},
}

LOG_SERVICES = {
    'hostapd', 'hostapd-2g', 'dnsmasq', 'apguard', 'ap-iface', 'ap2-iface',
    'wg-quick@wg0', 'systemd-networkd',
    'sbc-control-center-agent', 'sbc-control-center-web',
}

job_lock = threading.RLock()
job: dict[str, Any] = {
    'id': None, 'kind': None, 'state': 'idle', 'started': None,
    'finished': None, 'exit_code': None, 'log': '', 'summary': '',
    'updates_available': 0,
}

portal_update_lock = threading.RLock()
portal_update_state: dict[str, Any] = {
    'state': 'unconfigured', 'checking': False, 'repo': '', 'current_version': '0.0.1-1',
    'latest_version': None, 'release_name': None, 'release_url': None,
    'published_at': None, 'notes': '', 'update_available': False,
    'checked_at': None, 'error': None,
}

privilege_lock = threading.RLock()
privilege_grants: dict[str, dict[str, Any]] = {}
privilege_failures: dict[str, list[float]] = {}
privilege_user_failures: dict[str, list[float]] = {}
telemetry_lock = threading.Lock()
AGENT_CLIENT_LIMIT = 8
agent_client_slots = threading.BoundedSemaphore(AGENT_CLIENT_LIMIT)

PRIVILEGED_ACTIONS = {
    'service', 'update_job', 'wifi_config', 'backup_create', 'reboot', 'poweroff',
    'portal_update_source', 'logs', 'backup_download', 'network_scan',
    'packet_capture_start', 'network_fingerprint', 'network_label', 'network_unlabel',
}


def configured_sudo_user() -> str:
    try:
        data = json.loads(PRIVILEGE_CONFIG_PATH.read_text())
        value = data.get('sudo_user', '') if isinstance(data, dict) else ''
        if isinstance(value, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}[$]?', value):
            return value
    except Exception:
        pass
    return ''


def console_requires_privilege(command: Any) -> bool:
    if not isinstance(command, str):
        return False
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return False
    if parts == ['status']:
        return True
    if parts[:1] in (['nft'], ['journalctl']):
        return True
    if parts in (['ss', '-lntup'], ['wg', 'show']):
        return True
    if len(parts) == 3 and parts[:2] == ['systemctl', 'status'] and parts[2] in SERVICE_LABELS:
        return True
    return False


def privilege_scope(intent: Any) -> dict[str, Any] | None:
    """Return a validated, secret-safe scope for one exact privileged operation.

    The Wi-Fi passphrase is included only in the canonical digest input and is never
    persisted in a grant or diagnostic output. This prevents a one-time approval for
    one operation from being substituted for a different action or target.
    """
    if not isinstance(intent, dict):
        return None
    action = intent.get('action')
    if not isinstance(action, str):
        return None
    if action in {'reboot', 'poweroff', 'backup_create'}:
        return {'action': action}
    if action == 'service':
        unit, verb = intent.get('unit'), intent.get('verb')
        if isinstance(unit, str) and isinstance(verb, str) and verb in CONTROL_SERVICES.get(unit, set()):
            return {'action': action, 'unit': unit, 'verb': verb}
        return None
    if action == 'update_job':
        kind = intent.get('kind')
        return {'action': action, 'kind': kind} if isinstance(kind, str) and kind in {'check_updates', 'install_updates'} else None
    if action == 'wifi_config':
        radio, ssid, channel, password = (intent.get('radio'), intent.get('ssid'),
                                          intent.get('channel'), intent.get('password'))
        if not isinstance(radio, str) or radio not in {'radio5', 'radio2'} or not isinstance(ssid, str) or not ssid or len(ssid.encode('utf-8')) > 32 or any(ord(c) < 32 for c in ssid):
            return None
        if isinstance(channel, bool):
            return None
        try:
            channel = int(channel)
        except (TypeError, ValueError):
            return None
        valid_channels = ({149, 153, 157, 161, 165} if radio == 'radio5' else set(range(1, 12)))
        if channel not in valid_channels:
            return None
        if password not in (None, '') and (not isinstance(password, str) or not 8 <= len(password.encode('utf-8')) <= 63 or not password.isascii() or any(ord(c) < 32 or ord(c) > 126 for c in password)):
            return None
        return {'action': action, 'radio': radio, 'ssid': ssid, 'channel': channel,
                'password': password or ''}
    if action == 'portal_update_source':
        repo = intent.get('repo')
        return {'action': action, 'repo': repo} if isinstance(repo, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}', repo) else None
    if action == 'logs':
        unit = intent.get('unit')
        return {'action': action, 'unit': unit} if isinstance(unit, str) and unit in LOG_SERVICES else None
    if action == 'backup_download':
        name = intent.get('name')
        return {'action': action, 'name': name} if isinstance(name, str) and re.fullmatch(r'sbc-control-config-[0-9]{8}T[0-9]{6}Z\.tar\.gz', name) else None
    if action == 'network_scan':
        interfaces = network_observability.validate_scan_interfaces(intent.get('interfaces'))
        return {'action': action, 'interfaces': interfaces} if interfaces else None
    if action == 'network_fingerprint':
        return network_observability.fingerprint(req.get('address'))
    if action == 'packet_capture_start':
        duration = intent.get('duration_seconds')
        interfaces = network_observability.validate_capture_interfaces(intent.get('interfaces'))
        save_pcap = intent.get('save_pcap', False)
        if isinstance(duration, bool) or not isinstance(duration, int) or not 10 <= duration <= 600:
            return None
        if not interfaces or not isinstance(save_pcap, bool) or (save_pcap and duration > 300):
            return None
        return {'action': action, 'duration_seconds': duration, 'interfaces': interfaces, 'save_pcap': save_pcap}
    if action == 'network_fingerprint':
        address = network_observability.validate_fingerprint_address(intent.get('address'))
        return {'action': action, 'address': address} if address else None
    if action in {'network_label', 'network_unlabel'}:
        mac = intent.get('mac')
        label = intent.get('label', '')
        if not isinstance(mac, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
            return None
        if action == 'network_label' and (not isinstance(label, str) or not label.strip() or len(label) > 64 or any(ord(ch) < 32 for ch in label)):
            return None
        return {'action': action, 'mac': mac.lower(), 'label': label.strip() if isinstance(label, str) else ''}
    if action == 'console':
        command = intent.get('command')
        return {'action': action, 'command': command} if isinstance(command, str) and console_requires_privilege(command) else None
    return None


def privilege_scope_hash(intent: Any) -> bytes | None:
    scope = privilege_scope(intent)
    if scope is None:
        return None
    encoded = json.dumps(scope, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(encoded).digest()


def _sudo_user_is_authorized(username: str) -> bool:
    sudo_path = '/usr/bin/sudo' if Path('/usr/bin/sudo').exists() else shutil.which('sudo')
    if not sudo_path:
        return False
    check = run_cmd([sudo_path, '-l', '-U', username], timeout=8)
    return check.get('rc') == 0


def authorize_privileged_session(req: dict[str, Any]) -> dict[str, Any]:
    session_id = req.get('session_id')
    password = req.get('password')
    scope_hash = privilege_scope_hash(req.get('intent'))
    if not isinstance(session_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', session_id):
        return {'ok': False, 'error': 'A valid authenticated portal session is required.'}
    if scope_hash is None:
        return {'ok': False, 'error': 'The requested privileged operation is not valid or is not in the approved action list.'}
    if not isinstance(password, str) or not password or len(password.encode('utf-8')) > 512 or '\x00' in password:
        return {'ok': False, 'error': 'Enter the Linux administrator password.'}
    username = configured_sudo_user()
    if not username:
        return {'ok': False, 'error': 'No sudo-capable Linux account is configured. Configure sudo_user in the root-owned privilege.json file.'}
    now = time.monotonic()
    with privilege_lock:
        recent_session = [stamp for stamp in privilege_failures.get(session_id, []) if now - stamp < 300]
        recent_account = [stamp for stamp in privilege_user_failures.get(username, []) if now - stamp < 300]
        privilege_failures[session_id] = recent_session
        privilege_user_failures[username] = recent_account
        if len(recent_session) >= 5 or len(recent_account) >= 5:
            return {'ok': False, 'error': 'Administrator verification is temporarily locked. Try again in five minutes.'}
        # Reserve before PAM verification. The account-wide limit prevents an attacker
        # from bypassing the throttle by repeatedly creating fresh portal sessions.
        privilege_failures[session_id] = recent_session + [now]
        privilege_user_failures[username] = recent_account + [now]
        # Bound state for abandoned/expired portal sessions.
        for key, stamps in list(privilege_failures.items()):
            fresh = [stamp for stamp in stamps if now - stamp < 300]
            if fresh:
                privilege_failures[key] = fresh
            else:
                privilege_failures.pop(key, None)
        if len(privilege_failures) > 256:
            for key in list(privilege_failures)[:len(privilege_failures) - 192]:
                privilege_failures.pop(key, None)
    if not _sudo_user_is_authorized(username):
        return {'ok': False, 'error': 'The configured Linux account is not authorized to use sudo. Check the host sudoers policy.'}
    valid = False
    try:
        # PAM service "sudo" checks the account password directly. This deliberately
        # bypasses sudo timestamp/NOPASSWD shortcuts, so a fresh password is required.
        valid = pam_auth.authenticate(username, password, service='sudo')
    except Exception:
        valid = False
    if not valid:
        return {'ok': False, 'error': 'Linux administrator password was not accepted.'}
    token = secrets.token_urlsafe(32)
    with privilege_lock:
        privilege_failures.pop(session_id, None)
        privilege_user_failures.pop(username, None)
        privilege_grants[session_id] = {
            'token_hash': hashlib.sha256(token.encode()).digest(),
            'scope_hash': scope_hash,
            'expires': time.monotonic() + PRIVILEGE_GRANT_TTL,
        }
        for key, value in list(privilege_grants.items()):
            if value.get('expires', 0) < now:
                privilege_grants.pop(key, None)
        if len(privilege_grants) > 128:
            oldest = sorted(privilege_grants, key=lambda key: privilege_grants[key].get('expires', 0))[:32]
            for key in oldest:
                privilege_grants.pop(key, None)
    return {'ok': True, 'token': token, 'expires_in': PRIVILEGE_GRANT_TTL, 'sudo_user': username}


def consume_privilege_grant(req: dict[str, Any]) -> bool:
    session_id = req.get('session_id')
    token = req.get('privilege_token')
    if not isinstance(session_id, str) or not isinstance(token, str) or len(token) > 128:
        return False
    supplied = hashlib.sha256(token.encode()).digest()
    scope_hash = privilege_scope_hash(req)
    if scope_hash is None:
        return False
    with privilege_lock:
        grant = privilege_grants.get(session_id)
        if not grant:
            return False
        if grant.get('expires', 0) < time.monotonic():
            privilege_grants.pop(session_id, None)
            return False
        if not hmac.compare_digest(supplied, grant.get('token_hash', b'')):
            return False
        if not hmac.compare_digest(scope_hash, grant.get('scope_hash', b'')):
            return False
        privilege_grants.pop(session_id, None)
        return True
try:
    _saved_update = json.loads(UPDATE_STATE_PATH.read_text())
    if isinstance(_saved_update, dict):
        portal_update_state.update({k: _saved_update.get(k) for k in portal_update_state if k in _saved_update})
except Exception:
    pass


def current_app_version() -> str:
    try:
        value = APP_VERSION_PATH.read_text().strip()
        return value[:40] if value else 'unknown'
    except OSError:
        return 'unknown'


def read_update_repo() -> str:
    try:
        data = json.loads(UPDATE_SOURCE_PATH.read_text())
        repo = data.get('repo', '') if isinstance(data, dict) else ''
        return repo if isinstance(repo, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}', repo) else ''
    except Exception:
        return ''


def save_update_repo(repo: Any) -> dict[str, Any]:
    if not isinstance(repo, str):
        return {'ok': False, 'error': 'Enter a GitHub repository as owner/repository.'}
    repo = repo.strip()
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}', repo):
        return {'ok': False, 'error': 'Repository format must be owner/repository, using only letters, numbers, dots, underscores or hyphens.'}
    try:
        BASE.mkdir(mode=0o750, parents=True, exist_ok=True)
        tmp = UPDATE_SOURCE_PATH.with_name('.update-source-' + secrets.token_hex(8))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump({'repo': repo}, handle)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, UPDATE_SOURCE_PATH)
        with portal_update_lock:
            portal_update_state.update({'repo': repo, 'state': 'configured', 'error': None, 'latest_version': None, 'release_name': None, 'release_url': None, 'published_at': None, 'notes': '', 'update_available': False, 'checked_at': None})
        schedule_portal_update_check()
        return {'ok': True, 'message': f'Automatic release checks enabled for {repo}.', 'repo': repo}
    except Exception as exc:
        return {'ok': False, 'error': f'Could not save update source: {exc}'}


def numeric_version(value: str) -> tuple[int, ...] | None:
    cleaned = value.strip().lstrip('vV')
    match = re.fullmatch(r'(\d+(?:\.\d+){1,3})(?:-([0-9]+))?(?:\+[A-Za-z0-9.-]+)?', cleaned)
    if not match:
        return None
    try:
        # Numeric release suffixes are revision numbers: 0.0.1-1 > 0.0.1.
        return tuple(int(part) for part in match.group(1).split('.')) + (int(match.group(2) or 0),)
    except ValueError:
        return None


def _persist_portal_update_state() -> None:
    try:
        STATE.mkdir(mode=0o750, parents=True, exist_ok=True)
        with portal_update_lock:
            payload = {k: v for k, v in portal_update_state.items() if k != 'checking'}
        tmp = UPDATE_STATE_PATH.with_name('.portal-update-' + secrets.token_hex(8))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, UPDATE_STATE_PATH)
    except Exception:
        pass


class NoExternalRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _portal_update_worker() -> None:
    repo = read_update_repo()
    current = current_app_version()
    if not repo:
        with portal_update_lock:
            portal_update_state.update({'state': 'unconfigured', 'checking': False, 'repo': '', 'current_version': current})
        return
    url = f'https://api.github.com/repos/{repo}/releases/latest'
    try:
        request = urllib.request.Request(url, headers={
            'Accept': 'application/vnd.github+json',
            'User-Agent': 'SBCControlCenter/0.0.1-1',
            'X-GitHub-Api-Version': '2022-11-28',
        })
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoExternalRedirects())
        with opener.open(request, timeout=12) as response:
            raw = response.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError('Release response exceeded the 1 MB safety limit.')
        data = json.loads(raw.decode('utf-8'))
        tag = str(data.get('tag_name', '')).strip()[:80]
        release_url = str(data.get('html_url', '')).strip()
        parsed_release_url = urlsplit(release_url)
        expected_release_path = f'/{repo}/releases/tag/'
        if (not tag or parsed_release_url.scheme != 'https'
                or parsed_release_url.hostname != 'github.com'
                or parsed_release_url.username or parsed_release_url.password
                or parsed_release_url.port is not None
                or not parsed_release_url.path.startswith(expected_release_path)
                or parsed_release_url.query or parsed_release_url.fragment):
            raise ValueError('GitHub returned a release URL outside the configured repository.')
        current_tuple = numeric_version(current)
        latest_tuple = numeric_version(tag)
        comparable = current_tuple is not None and latest_tuple is not None
        update_available = bool(comparable and latest_tuple > current_tuple)
        notes = str(data.get('body') or '').strip()[:1800]
        with portal_update_lock:
            portal_update_state.update({
                'state': 'update_available' if update_available else 'current' if comparable else 'incomparable',
                'checking': False, 'repo': repo, 'current_version': current,
                'latest_version': tag, 'release_name': str(data.get('name') or tag)[:160],
                'release_url': release_url, 'published_at': str(data.get('published_at') or '')[:40],
                'notes': notes, 'update_available': update_available,
                'error': None if comparable else 'Release tag or installed version is not a comparable numeric version.',
                'checked_at': int(time.time()),
            })
    except Exception as exc:
        with portal_update_lock:
            portal_update_state.update({'state': 'error', 'checking': False, 'repo': repo,
                                        'current_version': current, 'latest_version': None,
                                        'release_name': None, 'release_url': None, 'published_at': None,
                                        'notes': '', 'update_available': False,
                                        'checked_at': int(time.time()), 'error': str(exc)[:300]})
    _persist_portal_update_state()


def schedule_portal_update_check() -> dict[str, Any]:
    with portal_update_lock:
        if portal_update_state.get('checking'):
            return {'ok': True, 'message': 'A portal release check is already running.'}
        portal_update_state['checking'] = True
        portal_update_state['state'] = 'checking'
    threading.Thread(target=_portal_update_worker, daemon=True, name='portal-release-check').start()
    return {'ok': True, 'message': 'Portal release check started.'}


def portal_update_status() -> dict[str, Any]:
    with portal_update_lock:
        snapshot = dict(portal_update_state)
    snapshot['current_version'] = current_app_version()
    snapshot['repo'] = read_update_repo()
    snapshot['configured'] = bool(snapshot['repo'])
    return {'ok': True, 'update': snapshot}


def portal_update_scheduler() -> None:
    # Automatic metadata-only check every six hours. It never installs or executes a release.
    time.sleep(8)
    while True:
        if read_update_repo():
            with portal_update_lock:
                already_running = bool(portal_update_state.get('checking'))
            if not already_running:
                schedule_portal_update_check()
        time.sleep(PORTAL_UPDATE_INTERVAL_SECONDS)


def run_console_command(command: Any) -> dict[str, Any]:
    """Execute a fixed set of read-only diagnostics; never invoke a shell."""
    if not isinstance(command, str) or not command.strip() or len(command) > 180 or any(ord(c) < 32 for c in command):
        return {'ok': False, 'error': 'Enter one command of at most 180 characters.'}
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return {'ok': False, 'error': 'Command quoting is invalid.'}
    if not parts or len(parts) > 6:
        return {'ok': False, 'error': 'Command is empty or contains too many arguments.'}

    help_text = (
        'READ-ONLY ADMIN CONSOLE — supported commands\n'
        '  help                         Show this help\n'
        '  version                      Control Center version\n'
        '  status                       AP, VPN and service summary\n'
        '  hostname                     System hostname\n'
        '  uname -a                     Kernel and architecture\n'
        '  date -Is                     System clock\n'
        '  uptime                       System uptime\n'
        '  free -h                      Memory usage\n'
        '  df -h                        Mounted filesystem usage\n'
        '  lsblk                        Block-device overview\n'
        '  ip -br addr                  Interface addresses\n'
        '  ip link                      Link state\n'
        '  ip -s link                   Interface counters\n'
        '  ip route                     Main routing table\n'
        '  ip rule                      Policy routing rules\n'
        '  wg show                      WireGuard status (no private keys)\n'
        '  nft list table inet apguard  AP firewall table\n'
        '  ss -lntup                    Listening sockets\n'
        '  systemctl --failed           Failed service units\n'
        '  systemctl status UNIT        Status of an approved service\n'
        '  journalctl -u UNIT -n 40     Recent logs (1–100 lines)\n\n'
        'This is a restricted diagnostic console, not a general shell. Commands run as fixed argument arrays without a shell. Pipes, redirection, scripts, arbitrary paths and write commands are disabled.'
    )
    if parts == ['help']:
        return {'ok': True, 'command': command, 'output': help_text}
    if parts == ['version']:
        return {'ok': True, 'command': command, 'output': f"SBC Control Center {current_app_version()}"}
    if parts == ['status']:
        s = get_status()
        services = ', '.join(
            f"{x['unit']}={'up' if x['active'] else 'down'}"
            for x in s.get('services', [])
            if x['unit'] in CONTROL_SERVICES
        )
        output = (
            f"Host: {s.get('hostname')}\nOS: {s.get('os')}\nKernel: {s.get('kernel')}\n"
            f"Uptime: {s.get('uptime_seconds')} seconds\n"
            f"VPN: {'connected' if s.get('vpn', {}).get('active') else 'disconnected'}\n"
            f"Services: {services}"
        )
        return {'ok': True, 'command': command, 'output': output[:MAX_CONSOLE_OUTPUT]}

    fixed = {
        ('hostname',): ['/bin/hostname'],
        ('uname', '-a'): ['/usr/bin/uname', '-a'],
        ('date', '-Is'): ['/usr/bin/date', '-Is'],
        ('uptime',): ['/usr/bin/uptime'],
        ('free', '-h'): ['/usr/bin/free', '-h'],
        ('df', '-h'): ['/usr/bin/df', '-h'],
        ('lsblk',): ['/usr/bin/lsblk', '-o', 'NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS'],
        ('ip', '-br', 'addr'): ['/usr/sbin/ip', '-br', 'addr'],
        ('ip', 'link'): ['/usr/sbin/ip', 'link'],
        ('ip', '-s', 'link'): ['/usr/sbin/ip', '-s', 'link'],
        ('ip', 'route'): ['/usr/sbin/ip', 'route'],
        ('ip', 'rule'): ['/usr/sbin/ip', 'rule'],
        ('wg', 'show'): ['/usr/bin/wg', 'show'],
        ('nft', 'list', 'table', 'inet', 'apguard'): ['/usr/sbin/nft', 'list', 'table', 'inet', 'apguard'],
        ('ss', '-lntup'): ['/usr/bin/ss', '-lntup'],
        ('systemctl', '--failed'): ['/usr/bin/systemctl', '--failed', '--no-pager', '--no-legend'],
    }

    def execute_fixed(args: list[str], timeout: int = 15) -> dict[str, Any]:
        if not Path(args[0]).exists():
            alternate = shutil.which(parts[0])
            if not alternate:
                return {'ok': False, 'error': f'{parts[0]} is not installed on this device.'}
            args = [alternate, *args[1:]]
        result = run_cmd(args, timeout=timeout)
        output = result['out'] or result['err'] or '(no output)'
        truncated = len(output) > MAX_CONSOLE_OUTPUT
        if truncated:
            output = output[:MAX_CONSOLE_OUTPUT] + '\n[output truncated]'
        return {
            'ok': True, 'command': command, 'output': output,
            'exit_code': result['rc'], 'truncated': truncated,
        }

    args = fixed.get(tuple(parts))
    if args:
        return execute_fixed(args)

    if len(parts) == 3 and parts[0:2] == ['systemctl', 'status'] and parts[2] in SERVICE_LABELS:
        return execute_fixed(['/usr/bin/systemctl', 'status', parts[2], '--no-pager', '-l'], timeout=12)

    if len(parts) in (3, 5) and parts[0:2] == ['journalctl', '-u'] and parts[2] in LOG_SERVICES:
        count = 40
        if len(parts) == 5 and parts[3] == '-n' and parts[4].isdigit():
            count = int(parts[4])
        elif len(parts) != 3:
            return {'ok': False, 'error': 'Use: journalctl -u UNIT -n 40 (1–100 lines).'}
        if not 1 <= count <= 100:
            return {'ok': False, 'error': 'Journal line count must be between 1 and 100.'}
        return execute_fixed([
            '/usr/bin/journalctl', '-u', parts[2], '-n', str(count),
            '--no-pager', '-o', 'short-iso',
        ], timeout=15)

    return {'ok': False, 'error': 'Command not allowed. Type help to see the supported read-only commands.'}


def load_config() -> dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    try:
        loaded = json.loads(CONFIG_PATH.read_text())
        if isinstance(loaded, dict):
            for key in DEFAULT_CONFIG:
                if key in loaded and isinstance(loaded[key], str):
                    cfg[key] = loaded[key]
    except Exception:
        pass
    # These values are identifiers, not shell fragments, but validate anyway.
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', cfg['ap_interface']):
        cfg['ap_interface'] = DEFAULT_CONFIG['ap_interface']
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', cfg['vpn_interface']):
        cfg['vpn_interface'] = DEFAULT_CONFIG['vpn_interface']
    if not re.fullmatch(r'wg-quick@[A-Za-z0-9_.-]{1,32}', cfg['vpn_unit']):
        cfg['vpn_unit'] = DEFAULT_CONFIG['vpn_unit']
    return cfg


CFG = load_config()
try:
    network_observability.configure(CFG)
except Exception:
    pass
telemetry_sampler = realtime_telemetry.RealtimeSampler(telemetry.snapshot, capacity=900, interval_seconds=1.0)

# The configured WireGuard unit is added to fixed service registries only after
# validating its systemd unit name. No caller-supplied unit reaches systemctl.
_configured_vpn_unit = CFG['vpn_unit']
if _configured_vpn_unit not in SERVICE_LABELS:
    SERVICE_LABELS[_configured_vpn_unit] = 'WireGuard tunnel'
    CONTROL_SERVICES[_configured_vpn_unit] = {'start', 'stop', 'restart', 'enable', 'disable'}
    LOG_SERVICES.add(_configured_vpn_unit)


def run_cmd(args: list[str], timeout: int = 8, env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        cp = subprocess.run(
            args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
            env={**os.environ, **(env or {})},
        )
        return {'rc': cp.returncode, 'out': cp.stdout.strip(), 'err': cp.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {'rc': 124, 'out': '', 'err': f'Command timed out after {timeout}s'}
    except FileNotFoundError as exc:
        return {'rc': 127, 'out': '', 'err': str(exc)}
    except Exception as exc:
        return {'rc': 1, 'out': '', 'err': str(exc)}


def is_active(unit: str) -> bool:
    return run_cmd(['/usr/bin/systemctl', 'is-active', '--quiet', unit])['rc'] == 0


def read_temp_c() -> float | None:
    values = []
    for p in Path('/sys/class/thermal').glob('thermal_zone*/temp'):
        try:
            raw = int(p.read_text().strip())
            value = raw / 1000.0 if raw > 1000 else float(raw)
            if -10 <= value <= 150:
                values.append(value)
        except Exception:
            continue
    return round(max(values), 1) if values else None


def read_memory() -> dict[str, int]:
    data: dict[str, int] = {}
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            name, rest = line.split(':', 1)
            if name in {'MemTotal', 'MemAvailable'}:
                data[name] = int(rest.strip().split()[0]) * 1024
    except Exception:
        pass
    total = data.get('MemTotal', 0)
    avail = data.get('MemAvailable', 0)
    return {'total': total, 'used': max(0, total - avail), 'available': avail}


def read_leases(path: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    try:
        for line in Path(path).read_text().splitlines():
            parts = line.split()
            if len(parts) >= 5:
                expiry, mac, ip, hostname, client_id = parts[:5]
                result[mac.lower()] = {
                    'mac': mac.lower(), 'ip': ip,
                    'hostname': hostname if hostname != '*' else 'Unknown device',
                    'expires': expiry,
                }
    except Exception:
        pass
    return result


def read_wireless_clients(iface: str, lease_path: str, subnet: str | None = None) -> list[dict[str, Any]]:
    leases = read_leases(lease_path)
    if subnet:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            leases = {mac: lease for mac, lease in leases.items() if ipaddress.ip_address(lease['ip']) in network}
        except ValueError:
            leases = {}
    result = run_cmd(['/usr/sbin/iw', 'dev', iface, 'station', 'dump'], timeout=5)
    if result['rc'] != 0:
        result = run_cmd(['/usr/bin/iw', 'dev', iface, 'station', 'dump'], timeout=5)
    clients: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in result.get('out', '').splitlines():
        line = line.strip()
        if line.startswith('Station '):
            if current:
                lease = leases.get(current['mac'], {})
                current.update(lease)
                clients.append(current)
            mac = line.split()[1].lower()
            current = {'mac': mac, 'signal': None, 'tx_bitrate': None, 'rx_bytes': None, 'tx_bytes': None, 'associated': True}
        elif current and line.startswith('signal:'):
            current['signal'] = line.split(':', 1)[1].strip()
        elif current and line.startswith('tx bitrate:'):
            current['tx_bitrate'] = line.split(':', 1)[1].strip()
        elif current and line.startswith('rx bytes:'):
            current['rx_bytes'] = line.split(':', 1)[1].strip()
        elif current and line.startswith('tx bytes:'):
            current['tx_bytes'] = line.split(':', 1)[1].strip()
    if current:
        current.update(leases.get(current['mac'], {}))
        clients.append(current)
    # Also show DHCP leases for clients that are asleep or not currently associated.
    associated = {c['mac'] for c in clients}
    for mac, lease in leases.items():
        if mac not in associated:
            clients.append({**lease, 'associated': False, 'signal': None, 'tx_bitrate': None})
        else:
            next(c for c in clients if c['mac'] == mac)['associated'] = True
    return clients


def parse_bytes(value: str) -> int:
    try:
        parts = value.split()
        return int(parts[0])
    except Exception:
        return 0


def wireguard_status() -> dict[str, Any]:
    iface = CFG['vpn_interface']
    active = is_active(CFG['vpn_unit'])
    endpoints = run_cmd(['/usr/bin/wg', 'show', iface, 'endpoints'])
    handshakes = run_cmd(['/usr/bin/wg', 'show', iface, 'latest-handshakes'])
    transfers = run_cmd(['/usr/bin/wg', 'show', iface, 'transfer'])
    endpoint = None
    handshake_age = None
    rx = tx = 0
    if endpoints['rc'] == 0 and endpoints['out']:
        bits = endpoints['out'].split()
        if len(bits) >= 2:
            endpoint = bits[-1]
    if handshakes['rc'] == 0 and handshakes['out']:
        bits = handshakes['out'].split()
        if bits:
            try:
                stamp = int(bits[-1])
                handshake_age = max(0, int(time.time()) - stamp) if stamp else None
            except ValueError:
                pass
    if transfers['rc'] == 0 and transfers['out']:
        bits = transfers['out'].split()
        if len(bits) >= 3:
            rx, tx = parse_bytes(bits[-2]), parse_bytes(bits[-1])
    return {
        'active': active, 'interface': iface, 'unit': CFG['vpn_unit'], 'endpoint': endpoint,
        'handshake_age': handshake_age, 'rx_bytes': rx, 'tx_bytes': tx,
    }


def read_hostapd_config(path: str, iface: str, fallback_ssid: str) -> dict[str, Any]:
    values: dict[str, str] = {}
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                values[key.strip()] = value.strip()
    except Exception:
        pass
    try:
        channel_value: int | None = int(values.get('channel', ''))
    except ValueError:
        channel_value = None
    return {
        'interface': values.get('interface', iface),
        'ssid': values.get('ssid', fallback_ssid),
        'channel': channel_value,
        'country': values.get('country_code', '—'),
        'security': 'WPA2-PSK' if values.get('wpa') == '2' else 'Unknown',
        'password_configured': bool(values.get('wpa_passphrase')),
    }


def cpu_model() -> str:
    try:
        for line in Path('/proc/cpuinfo').read_text(errors='replace').splitlines():
            if line.lower().startswith(('model name', 'hardware', 'model')) and ':' in line:
                value = line.split(':', 1)[1].strip()
                if value:
                    return value[:160]
    except Exception:
        pass
    return platform.processor() or 'Not reported by kernel'


def read_storage() -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        for line in Path('/proc/mounts').read_text().splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mountpoint, fs_type = parts[:3]
            if fs_type in {'proc', 'sysfs', 'devtmpfs', 'devpts', 'tmpfs', 'mqueue', 'cgroup', 'cgroup2', 'overlay', 'squashfs'} or mountpoint in seen:
                continue
            seen.add(mountpoint)
            try:
                usage = shutil.disk_usage(mountpoint)
            except Exception:
                continue
            mounts.append({'device': device, 'mount': mountpoint, 'filesystem': fs_type,
                           'total': usage.total, 'used': usage.used, 'free': usage.free})
    except Exception:
        pass
    return sorted(mounts, key=lambda x: (x['mount'] != '/', x['mount']))[:40]


def read_processes() -> list[dict[str, Any]]:
    result = run_cmd(['/usr/bin/ps', '-eo', 'pid,comm,%cpu,%mem,stat', '--sort=-%cpu'], timeout=5)
    if result['rc'] != 0:
        return []
    rows = []
    for line in result['out'].splitlines()[1:16]:
        bits = line.split(None, 4)
        if len(bits) == 5:
            try:
                rows.append({'pid': int(bits[0]), 'name': bits[1][:80],
                             'cpu': float(bits[2]), 'memory': float(bits[3]), 'state': bits[4]})
            except ValueError:
                continue
    return rows


def read_listeners() -> str:
    # Without -p, the unprivileged portal does not request process ownership details.
    result = run_cmd(['/usr/bin/ss', '-lntu'], timeout=6)
    return result['out'] if result['rc'] == 0 else (result['err'] or 'Listener information unavailable.')


def iw_info(iface: str) -> str:
    result = run_cmd(['/usr/sbin/iw', 'dev', iface, 'info'], timeout=5)
    if result['rc'] != 0:
        result = run_cmd(['/usr/bin/iw', 'dev', iface, 'info'], timeout=5)
    return result.get('out', '')


def read_net_counters(iface: str) -> dict[str, int]:
    base = Path('/sys/class/net') / iface / 'statistics'
    out: dict[str, int] = {}
    for key in ('rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets', 'rx_errors', 'tx_errors'):
        try:
            out[key] = int((base / key).read_text().strip())
        except Exception:
            out[key] = 0
    return out


def update_hostapd_config(req: dict[str, Any]) -> dict[str, Any]:
    radio = req.get('radio')
    definitions = {
        'radio5': {'path': Path('/etc/hostapd/hostapd.conf'), 'unit': 'hostapd',
                   'iface': CFG['ap_interface'], 'channels': {149, 153, 157, 161, 165}},
        'radio2': {'path': Path('/etc/hostapd/hostapd-2g.conf'), 'unit': 'hostapd-2g',
                   'iface': CFG['ap2_interface'], 'channels': set(range(1, 12))},
    }
    spec = definitions.get(radio)
    if not spec:
        return {'ok': False, 'error': 'Unknown Wi-Fi radio.'}
    path: Path = spec['path']
    if not path.is_file():
        return {'ok': False, 'error': f'Configuration file not found: {path}'}
    ssid = req.get('ssid')
    channel = req.get('channel')
    password = req.get('password')
    if not isinstance(ssid, str) or not ssid or len(ssid.encode('utf-8')) > 32 or any(ord(c) < 32 for c in ssid):
        return {'ok': False, 'error': 'SSID must be 1–32 UTF-8 bytes and contain no control characters.'}
    try:
        channel = int(channel)
    except (TypeError, ValueError):
        return {'ok': False, 'error': 'Channel must be a number.'}
    if channel not in spec['channels']:
        return {'ok': False, 'error': 'That channel is outside the validated channel list for this radio.'}
    if password is not None and password != '':
        if not isinstance(password, str) or not 8 <= len(password.encode('utf-8')) <= 63 or not password.isascii() or any(ord(c) < 32 or ord(c) > 126 for c in password):
            return {'ok': False, 'error': 'WPA2 passphrase must be 8–63 printable ASCII characters.'}
    old = path.read_bytes()
    try:
        text = old.decode('utf-8')
    except UnicodeDecodeError:
        return {'ok': False, 'error': 'Configuration file is not valid UTF-8; no changes made.'}
    replacements = {'ssid': ssid, 'channel': str(channel)}
    if password:
        replacements['wpa_passphrase'] = password
    lines = text.splitlines()
    found: set[str] = set()
    output: list[str] = []
    for line in lines:
        stripped = line.strip()
        if '=' in stripped and not stripped.startswith('#'):
            key = stripped.split('=', 1)[0].strip()
            if key in replacements:
                if key not in found:
                    output.append(f'{key}={replacements[key]}')
                    found.add(key)
                continue
        output.append(line)
    for key, value in replacements.items():
        if key not in found:
            output.append(f'{key}={value}')
    new = ('\n'.join(output).rstrip() + '\n').encode('utf-8')
    fd, temp_name = tempfile.mkstemp(prefix='.hostapd-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(new)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
        test = run_cmd(['/usr/sbin/hostapd', '-t', str(path)], timeout=12)
        if test['rc'] != 0:
            path.write_bytes(old)
            os.chmod(path, 0o600)
            return {'ok': False, 'error': 'hostapd rejected the proposed configuration: ' + (test['err'] or test['out'])[:500]}
        restart = run_cmd(['/usr/bin/systemctl', 'restart', spec['unit']], timeout=25)
        if restart['rc'] != 0:
            path.write_bytes(old)
            os.chmod(path, 0o600)
            run_cmd(['/usr/bin/systemctl', 'restart', spec['unit']], timeout=25)
            return {'ok': False, 'error': 'AP restart failed; previous configuration was restored. ' + (restart['err'] or restart['out'])[:400]}
        return {'ok': True, 'message': f'{radio} updated and {spec["unit"]} restarted.',
                'config': read_hostapd_config(str(path), spec['iface'], ssid)}
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def create_backup() -> dict[str, Any]:
    backup_dir = STATE / 'backups'
    try:
        portal_gid = grp.getgrnam('sbc-control-center').gr_gid
    except KeyError:
        portal_gid = os.getegid()
    backup_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        os.chown(backup_dir, 0, portal_gid)
    except Exception:
        pass
    os.chmod(backup_dir, 0o750)
    allowed = [
        Path('/etc/hostapd/hostapd.conf'), Path('/etc/hostapd/hostapd-2g.conf'),
        Path('/etc/dnsmasq.d/ap.conf'), Path('/etc/apguard.nft'),
        Path('/etc/systemd/system/ap-iface.service'), Path('/etc/systemd/system/ap2-iface.service'),
        Path('/etc/systemd/system/apguard.service'), Path('/etc/systemd/system/hostapd-2g.service'),
        CONFIG_PATH,
    ]
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    name = f'sbc-control-config-{stamp}.tar.gz'
    target = backup_dir / name
    manifest: list[dict[str, str]] = []
    try:
        with tarfile.open(target, 'w:gz') as archive:
            for source in allowed:
                if source.is_file():
                    data = source.read_bytes()
                    manifest.append({'path': str(source), 'sha256': hashlib.sha256(data).hexdigest()})
                    archive.add(source, arcname=str(source).lstrip('/'), recursive=False)
            import io
            payload = json.dumps({'created_utc': stamp, 'files': manifest}, indent=2).encode()
            info = tarfile.TarInfo('BACKUP-MANIFEST.json')
            info.size = len(payload)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(payload))
        os.chown(target, 0, portal_gid)
        os.chmod(target, 0o640)
        return {'ok': True, 'backup': {'name': name, 'size': target.stat().st_size,
                                      'created': stamp, 'files': len(manifest)}}
    except Exception as exc:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        return {'ok': False, 'error': f'Backup creation failed: {exc}'}


def list_backups() -> dict[str, Any]:
    backup_dir = STATE / 'backups'
    items = []
    try:
        for path in sorted(backup_dir.glob('sbc-control-config-????????T??????Z.tar.gz'), reverse=True)[:20]:
            if path.is_file() and not path.is_symlink():
                items.append({'name': path.name, 'size': path.stat().st_size, 'modified': int(path.stat().st_mtime)})
    except Exception:
        pass
    return {'ok': True, 'backups': items}


def get_status() -> dict[str, Any]:
    services = []
    for unit, label in SERVICE_LABELS.items():
        active = is_active(unit)
        enabled = run_cmd(['/usr/bin/systemctl', 'is-enabled', '--quiet', unit])['rc'] == 0
        services.append({'unit': unit, 'label': label, 'active': active, 'enabled': enabled,
                         'controllable': unit in CONTROL_SERVICES,
                         'allowed_actions': sorted(CONTROL_SERVICES.get(unit, set()))})

    uptime_seconds = 0
    try:
        uptime_seconds = int(float(Path('/proc/uptime').read_text().split()[0]))
    except Exception:
        pass
    try:
        load = [round(float(x), 2) for x in Path('/proc/loadavg').read_text().split()[:3]]
    except Exception:
        load = []
    disk = shutil.disk_usage('/')
    memory = read_memory()
    release = {}
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                release[k] = v.strip().strip('"')
    except Exception:
        pass

    addr = run_cmd(['/usr/sbin/ip', '-j', 'address', 'show'])
    if addr['rc'] != 0:
        addr = run_cmd(['/usr/bin/ip', '-j', 'address', 'show'])
    interfaces = []
    try:
        for item in json.loads(addr['out']):
            ips = []
            for info in item.get('addr_info', []):
                if info.get('family') == 'inet':
                    ips.append(info.get('local'))
            interfaces.append({'name': item.get('ifname'), 'state': item.get('operstate'),
                               'mac': item.get('address'), 'ips': ips})
    except Exception:
        pass

    ap_info = run_cmd(['/usr/sbin/iw', 'dev', CFG['ap_interface'], 'info'])
    if ap_info['rc'] != 0:
        ap_info = run_cmd(['/usr/bin/iw', 'dev', CFG['ap_interface'], 'info'])
    clients = read_wireless_clients(CFG['ap_interface'], CFG['dhcp_lease_file'], CFG['ap_subnet'])
    clients2 = read_wireless_clients(CFG['ap2_interface'], CFG['dhcp_lease_file'], CFG['ap2_subnet'])
    ap5_cfg = read_hostapd_config('/etc/hostapd/hostapd.conf', CFG['ap_interface'], CFG['ap_ssid'])
    ap2_cfg = read_hostapd_config('/etc/hostapd/hostapd-2g.conf', CFG['ap2_interface'], CFG['ap2_ssid'])
    # Firewall rules can reveal sensitive policy and are deliberately not read
    # during automatic dashboard polling. The UI requests them through the
    # one-time sudo/PAM-gated console action instead.
    firewall = {'rc': 1, 'out': 'Firewall inspection requires sudo-password verification.', 'err': ''}
    firewall_loaded = False
    routes = run_cmd(['/usr/sbin/ip', 'route', 'show', 'table', '200'])
    if routes['rc'] != 0:
        routes = run_cmd(['/usr/bin/ip', 'route', 'show', 'table', '200'])
    rules = run_cmd(['/usr/sbin/ip', 'rule', 'show'])
    if rules['rc'] != 0:
        rules = run_cmd(['/usr/bin/ip', 'rule', 'show'])

    service_active = {item['unit']: item['active'] for item in services}
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'hostname': platform.node(), 'os': release.get('PRETTY_NAME', 'Linux'),
        'cpu_model': cpu_model(), 'cpu_cores': os.cpu_count() or 1,
        'kernel': platform.release(), 'architecture': platform.machine(),
        'uptime_seconds': uptime_seconds, 'load': load,
        'memory': memory,
        'disk': {'total': disk.total, 'used': disk.used, 'free': disk.free},
        'temperature_c': read_temp_c(),
        'services': services,
        'vpn': wireguard_status(),
        'ap': {'interface': CFG['ap_interface'], 'ssid': ap5_cfg['ssid'],
               'ip': CFG['ap_ip'], 'subnet': CFG['ap_subnet'],
               'radio_info': ap_info.get('out', ''), 'clients': clients},
        'aps': [
            {'id': 'radio5', 'label': 'SBC-5G · 5 GHz', 'interface': CFG['ap_interface'],
             'ip': CFG['ap_ip'], 'subnet': CFG['ap_subnet'], 'service': 'hostapd',
             'radio_info': ap_info.get('out', ''), 'active': service_active.get('hostapd', False), 'clients': clients, 'config': ap5_cfg,
             'counters': read_net_counters(CFG['ap_interface'])},
            {'id': 'radio2', 'label': 'SBC-2G · 2.4 GHz', 'interface': CFG['ap2_interface'],
             'ip': CFG['ap2_ip'], 'subnet': CFG['ap2_subnet'], 'service': 'hostapd-2g',
             'radio_info': iw_info(CFG['ap2_interface']), 'active': service_active.get('hostapd-2g', False),
             'clients': clients2, 'config': ap2_cfg, 'counters': read_net_counters(CFG['ap2_interface'])},
        ],
        'interfaces': interfaces,
        'storage': read_storage(), 'processes': read_processes(),
        'listeners': read_listeners(),
        'dns_policy': (Path('/etc/dnsmasq.d/ap.conf').read_text(errors='replace')[:12000] if Path('/etc/dnsmasq.d/ap.conf').is_file() else 'dnsmasq AP configuration not found.'),
        'firewall': firewall['out'],
        'firewall_loaded': firewall_loaded,
        'vpn_routes': routes.get('out', ''), 'ip_rules': rules.get('out', ''),
        'job': get_job(),
    }


def append_job_log(chunk: str) -> None:
    with job_lock:
        job['log'] = (job.get('log', '') + chunk)[-24000:]


def get_job() -> dict[str, Any]:
    with job_lock:
        return dict(job)


def execute_job_command(args: list[str], timeout: int, cleanup_unit: str | None = None) -> int:
    env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'APT_LISTCHANGES_FRONTEND': 'none'}
    append_job_log('\n$ ' + ' '.join(args) + '\n')
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                bufsize=0, env=env)
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        os.set_blocking(fd, False)
        selector = selectors.DefaultSelector()
        selector.register(fd, selectors.EVENT_READ)
        decoder = codecs.getincrementaldecoder('utf-8')('replace')
        started = time.monotonic()
        eof = False
        while not eof or proc.poll() is None:
            if time.monotonic() - started > timeout:
                proc.kill()
                proc.wait(timeout=10)
                if cleanup_unit and re.fullmatch(r'[A-Za-z0-9_.@-]{1,180}', cleanup_unit):
                    run_cmd(['/usr/bin/systemctl', 'stop', cleanup_unit], timeout=20)
                append_job_log('\n[Control Center] Command timed out.\n')
                return 124
            events = selector.select(timeout=1)
            for key, _ in events:
                try:
                    data = os.read(fd, 8192)
                except BlockingIOError:
                    continue
                if not data:
                    eof = True
                    try:
                        selector.unregister(fd)
                    except Exception:
                        pass
                else:
                    append_job_log(decoder.decode(data))
            if eof and proc.poll() is not None:
                break
        tail = decoder.decode(b'', final=True)
        if tail:
            append_job_log(tail)
        return int(proc.wait())
    except Exception as exc:
        append_job_log(f'\n[Control Center] {exc}\n')
        return 1



def execute_package_command(args: list[str], timeout: int) -> int:
    """Run one fixed apt operation in a transient host service.

    The privileged agent itself is filesystem-sandboxed. Package maintainer
    scripts legitimately need to modify the host filesystem, so the explicit
    step-up-approved apt operation runs in a separate transient systemd unit
    rather than broadening the long-lived agent's writable paths.
    """
    allowed = {
        ('/usr/bin/apt-get', 'update'),
        ('/usr/bin/apt-get', '-s', 'upgrade'),
        ('/usr/bin/apt-get', 'upgrade', '-y'),
    }
    if not isinstance(args, list) or tuple(args) not in allowed:
        append_job_log('\n[Control Center] Package command rejected.\n')
        return 2
    unit = 'kickpi-control-apt-' + uuid.uuid4().hex
    command = [
        '/usr/bin/systemd-run', '--wait', '--collect', '--pipe', '--quiet',
        '--service-type=exec', f'--unit={unit}',
        '--setenv=DEBIAN_FRONTEND=noninteractive',
        '--setenv=APT_LISTCHANGES_FRONTEND=none', *args,
    ]
    return execute_job_command(command, timeout, cleanup_unit=unit)

def job_worker(kind: str) -> None:
    exit_code = 0
    summary = ''
    try:
        if kind == 'check_updates':
            exit_code = execute_package_command(['/usr/bin/apt-get', 'update'], 1800)
            if exit_code == 0:
                exit_code = execute_package_command(['/usr/bin/apt-get', '-s', 'upgrade'], 900)
            with job_lock:
                text_log = job.get('log', '')
                count = sum(1 for line in text_log.splitlines() if line.startswith('Inst '))
                job['updates_available'] = count if exit_code == 0 else 0
                if exit_code != 0:
                    summary = 'Update check failed; inspect the operation output.'
                else:
                    summary = f'{count} package update(s) available.' if count else 'No package upgrades are currently available.'
        elif kind == 'install_updates':
            exit_code = execute_package_command(['/usr/bin/apt-get', 'upgrade', '-y'], 3600)
            summary = 'Package upgrade completed.' if exit_code == 0 else 'Package upgrade failed; inspect the job log.'
        else:
            exit_code, summary = 2, 'Unknown job type.'
    except Exception as exc:
        exit_code, summary = 1, str(exc)
    with job_lock:
        job['state'] = 'completed' if exit_code == 0 else 'failed'
        job['exit_code'] = exit_code
        job['finished'] = int(time.time())
        job['summary'] = summary
        if kind == 'check_updates' and exit_code != 0:
            job['updates_available'] = 0


def start_job(kind: str) -> dict[str, Any]:
    if kind not in {'check_updates', 'install_updates'}:
        return {'ok': False, 'error': 'Unsupported update operation.'}
    with job_lock:
        if job['state'] == 'running':
            return {'ok': False, 'error': 'Another package operation is already running.'}
        if kind == 'install_updates' and job.get('updates_available', 0) <= 0:
            return {'ok': False, 'error': 'Run Check for updates first. No confirmed upgrade list is available.'}
        job.update({'id': str(uuid.uuid4()), 'kind': kind, 'state': 'running',
                    'started': int(time.time()), 'finished': None,
                    'exit_code': None, 'log': '', 'summary': '',
                    'updates_available': job.get('updates_available', 0) if kind == 'install_updates' else 0})
        threading.Thread(target=job_worker, args=(kind,), daemon=True).start()
        return {'ok': True, 'job': dict(job)}


def do_action(req: dict[str, Any]) -> dict[str, Any]:
    action = req.get('action')
    if action == 'privilege_info':
        username = configured_sudo_user()
        return {'ok': True, 'sudo_user': username, 'configured': bool(username)}
    if action == 'privilege_authorize':
        return authorize_privileged_session(req)
    needs_privilege = action in PRIVILEGED_ACTIONS or (action == 'console' and console_requires_privilege(req.get('command')))
    if needs_privilege and not consume_privilege_grant(req):
        return {'ok': False, 'error': 'Fresh Linux sudo-password verification is required for this operation.'}
    if action == 'status':
        return {'ok': True, 'data': get_status()}
    if action == 'telemetry':
        try:
            return {'ok': True, 'telemetry': telemetry_sampler.read(
                after_sequence=req.get('after_sequence', 0), limit=req.get('limit', 900))}
        except (TypeError, ValueError) as exc:
            return {'ok': False, 'error': str(exc)}
    if action == 'network_inventory':
        try:
            return {'ok': True, 'network': network_observability.inventory()}
        except Exception as exc:
            return {'ok': False, 'error': str(exc)[:240]}
    if action == 'network_scan':
        return network_observability.scan(req.get('interfaces'))
    if action == 'packet_capture_start':
        try:
            return network_observability.capture_start(req.get('duration_seconds'), req.get('interfaces'), req.get('save_pcap', False))
        except Exception as exc:
            return {'ok': False, 'error': str(exc)[:240]}
    if action == 'packet_capture_stop':
        try:
            return network_observability.capture_stop()
        except Exception as exc:
            return {'ok': False, 'error': str(exc)[:240]}
    if action == 'packet_capture_snapshot':
        try:
            after, limit = req.get('after', 0), req.get('limit', 200)
            if isinstance(after, bool) or not isinstance(after, int) or after < 0 or isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= 250:
                return {'ok': False, 'error': 'Invalid packet event cursor or limit.'}
            return network_observability.capture_snapshot(after, limit)
        except Exception as exc:
            return {'ok': False, 'error': str(exc)[:240]}
    if action == 'packet_flow_series':
        flow_id, limit = req.get('flow_id'), req.get('limit', 60)
        if not isinstance(flow_id, str) or not re.fullmatch(r'[0-9a-f]{24}', flow_id):
            return {'ok': False, 'error': 'Invalid flow identifier.'}
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 60:
            return {'ok': False, 'error': 'Invalid flow history limit.'}
        try:
            return network_observability.flow_series(flow_id, limit)
        except Exception as exc:
            return {'ok': False, 'error': str(exc)[:240]}
    if action == 'packet_analyse':
        return network_observability.analyse_capture(req.get('name'))
    if action == 'dns_status':
        return network_observability.dns_status()
    if action == 'dns_query_log':
        return network_observability.dns_query_log(req.get('limit', 50))
    if action == 'network_label':
        return network_observability.set_client_label(req.get('mac'), req.get('label'))
    if action == 'network_unlabel':
        return network_observability.remove_client_label(req.get('mac'))
    if action == 'job_status':
        return {'ok': True, 'job': get_job()}
    if action == 'portal_update_status':
        return portal_update_status()
    if action == 'portal_update_source':
        return save_update_repo(req.get('repo'))
    if action == 'portal_update_check':
        if not read_update_repo():
            return {'ok': False, 'error': 'Configure a public GitHub owner/repository first.'}
        return schedule_portal_update_check()
    if action == 'console':
        return run_console_command(req.get('command'))
    if action == 'backup_create':
        return create_backup()
    if action == 'backup_list':
        return list_backups()
    if action == 'backup_download':
        name = req.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'sbc-control-config-[0-9]{8}T[0-9]{6}Z\.tar\.gz', name):
            return {'ok': False, 'error': 'Invalid backup name.'}
        backup_path = STATE / 'backups' / name
        try:
            if backup_path.is_symlink() or not backup_path.is_file():
                return {'ok': False, 'error': 'Backup not found.'}
        except OSError:
            return {'ok': False, 'error': 'Backup is unavailable.'}
        return {'ok': True, 'name': name}
    if action == 'wifi_config':
        return update_hostapd_config(req)
    if action == 'service':
        unit = req.get('unit')
        verb = req.get('verb')
        if unit not in CONTROL_SERVICES or verb not in CONTROL_SERVICES[unit]:
            return {'ok': False, 'error': 'That service operation is not permitted.'}
        result = run_cmd(['/usr/bin/systemctl', verb, unit], timeout=45)
        return {'ok': result['rc'] == 0, 'message': f'{verb} {unit}: ' + ('completed' if result['rc'] == 0 else result['err'] or result['out'])}
    if action == 'logs':
        unit = req.get('unit')
        if unit not in LOG_SERVICES:
            return {'ok': False, 'error': 'Log access for that service is not permitted.'}
        result = run_cmd(['/usr/bin/journalctl', '-u', unit, '-n', '160', '--no-pager', '-o', 'short-iso'], timeout=12)
        return {'ok': result['rc'] == 0, 'unit': unit, 'text': result['out'] or result['err']}
    if action == 'update_job':
        return start_job(req.get('kind', ''))
    if action in {'reboot', 'poweroff'}:
        command = ['/usr/bin/systemctl', 'reboot' if action == 'reboot' else 'poweroff']
        try:
            subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
            return {'ok': True, 'message': f'{action.capitalize()} requested.'}
        except Exception as exc:
            return {'ok': False, 'error': str(exc)}
    return {'ok': False, 'error': 'Unknown operation.'}


def agent_peer_allowed(conn: socket.socket) -> bool:
    """Only accept the dedicated unprivileged portal identity over the local socket."""
    if not hasattr(socket, 'SO_PEERCRED'):
        return False
    try:
        _pid, uid, _gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
        portal_uid = pwd.getpwnam('sbc-control-center').pw_uid
        return uid == portal_uid and portal_uid != 0
    except Exception:
        return False


def handle_client(conn: socket.socket) -> None:
    try:
        if not agent_peer_allowed(conn):
            conn.sendall(b'{"ok":false,"error":"Agent peer credentials rejected."}\n')
            return
        conn.settimeout(10)
        chunks = []
        total = 0
        while total <= 16384:
            part = conn.recv(4096)
            if not part:
                break
            chunks.append(part)
            total += len(part)
            if b'\n' in part:
                break
        raw = b''.join(chunks).split(b'\n', 1)[0]
        if not raw or len(raw) > 16384:
            response = {'ok': False, 'error': 'Invalid request.'}
        else:
            request = json.loads(raw.decode('utf-8'))
            if not isinstance(request, dict):
                response = {'ok': False, 'error': 'Invalid request format.'}
            else:
                response = do_action(request)
        conn.sendall((json.dumps(response, separators=(',', ':')) + '\n').encode())
    except Exception as exc:
        try:
            conn.sendall((json.dumps({'ok': False, 'error': str(exc)}) + '\n').encode())
        except Exception:
            pass
    finally:
        conn.close()


def main() -> None:
    telemetry_sampler.start()
    threading.Thread(target=portal_update_scheduler, daemon=True, name='portal-update-scheduler').start()
    SOCKET_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    os.umask(0o007)
    server.bind(str(SOCKET_PATH))
    os.chmod(SOCKET_PATH, 0o660)
    # systemd creates the runtime directory with the portal group.
    try:
        import grp
        os.chown(SOCKET_PATH, 0, grp.getgrnam('sbc-control-center').gr_gid)
    except Exception:
        pass
    server.listen(16)
    while True:
        conn, _ = server.accept()
        # A compromised portal UID must not be able to create an unbounded number
        # of privileged-agent threads. Reject excess work without queue growth.
        if not agent_client_slots.acquire(blocking=False):
            try:
                conn.sendall(b'{\"ok\":false,\"error\":\"Agent busy; retry shortly.\"}\n')
            except OSError:
                pass
            finally:
                conn.close()
            continue
        def bounded_client(client: socket.socket) -> None:
            try:
                handle_client(client)
            finally:
                agent_client_slots.release()
        try:
            threading.Thread(target=bounded_client, args=(conn,), daemon=True, name='agent-client').start()
        except Exception:
            agent_client_slots.release()
            conn.close()


if __name__ == '__main__':
    main()
