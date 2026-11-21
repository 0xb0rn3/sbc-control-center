#!/usr/bin/env python3
"""Unprivileged HTTPS web UI with optional WebAuthn support via python-fido2."""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import http.cookies
import ipaddress
import json
import re
import os
import pwd
import secrets
import socket
import ssl
import struct
import stat
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

try:
    from fido2.server import Fido2Server
    from fido2.webauthn import AttestedCredentialData, AuthenticatorData
    try:
        from fido2.features import webauthn_json_mapping
        if not webauthn_json_mapping.enabled:
            webauthn_json_mapping.enabled = True
    except (ImportError, AttributeError):
        # python-fido2 2.x uses the WebAuthn JSON mapping by default.
        pass
    FIDO2_AVAILABLE = True
except ImportError:
    Fido2Server = None  # type: ignore[assignment,misc]
    AttestedCredentialData = None  # type: ignore[assignment,misc]
    AuthenticatorData = None  # type: ignore[assignment,misc]
    FIDO2_AVAILABLE = False

BASE = Path('/etc/sbc-control-center')
SOCKET_PATH = Path('/run/sbc-control-center/agent.sock')
AUTH_PATH = BASE / 'auth.json'
KEY_PATH = BASE / 'session.key'
CERT_PATH = Path('/etc/sbc-control-center/tls.crt')
PRIVATE_KEY_PATH = Path('/etc/sbc-control-center/tls.key')
TOTP_STATE_PATH = Path('/var/lib/sbc-control-center-web/totp-last-step')
PASSKEYS_PATH = Path('/var/lib/sbc-control-center-web/passkeys.json')
HTML_PATH = Path('/opt/sbc-control-center/index.html')
BACKGROUND_PATH = Path('/opt/sbc-control-center/assets/ui-background.png')
BIND = os.environ.get('PORTAL_BIND', '0.0.0.0')
PORT = int(os.environ.get('PORTAL_PORT', '8443'))
SESSION_IDLE_TTL = 20 * 60
SESSION_ABSOLUTE_TTL = 8 * 60 * 60
MAX_BODY = 65536
LOGIN_WINDOW = 10 * 60
LOGIN_LIMIT = 6
LOGIN_COOLDOWN_BASE = 60
LOGIN_COOLDOWN_MAX = 15 * 60
ACCOUNT_LOGIN_LIMIT = 10
ACCOUNT_LOGIN_COOLDOWN_BASE = 60
ACCOUNT_LOGIN_COOLDOWN_MAX = 15 * 60
COOKIE_NAME = '__Host-kpc_session'
PASSKEY_MAX_CREDENTIALS = 10
WEBAUTHN_CHALLENGE_TTL = 120
WEBAUTHN_MANAGEMENT_TTL = 300
WEBAUTHN_USER_ID = hashlib.sha256(b'sbc-control-center-admin').digest()


def valid_webauthn_rp_id(value: str) -> bool:
    """Accept a stable DNS hostname only; WebAuthn RP IDs cannot be IP literals."""
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    value = value.strip().lower().rstrip('.')
    if not value or any(ch in value for ch in '/:@\\'):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    labels = value.split('.')
    if len(labels) < 2:
        return False
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label) is not None
        for label in labels
    )


_configured_rp_id = os.environ.get('PORTAL_WEBAUTHN_RP_ID', 'sbc-control-center.local').strip().lower().rstrip('.')
WEBAUTHN_RP_ID = _configured_rp_id if valid_webauthn_rp_id(_configured_rp_id) else ''
WEBAUTHN_ORIGIN = f'https://{WEBAUTHN_RP_ID}:{PORT}' if WEBAUTHN_RP_ID else ''
webauthn_challenges: dict[str, dict[str, Any]] = {}
webauthn_challenges_lock = threading.RLock()
passkeys_lock = threading.RLock()

sessions: dict[str, dict[str, Any]] = {}
sessions_lock = threading.RLock()
login_attempts: dict[str, dict[str, Any]] = {}
account_login_state: dict[str, Any] = {'failures': [], 'blocked_until': 0, 'level': 0, 'last_seen': 0}
login_lock = threading.RLock()
login_verify_slots = threading.BoundedSemaphore(2)
totp_lock = threading.RLock()
last_totp_step = -1


def load_secret() -> bytes:
    return KEY_PATH.read_bytes().strip()


def load_auth() -> dict[str, Any]:
    return json.loads(AUTH_PATH.read_text())


def pbkdf2(password: str, salt: bytes, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, rounds, dklen=32)


def totp_counter(secret: str, code: str, now: float | None = None) -> int | None:
    """Return the matching 30-second TOTP counter, accepting +/- one time step."""
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        return None
    try:
        padded = secret.upper() + ('=' * ((8 - len(secret) % 8) % 8))
        key = base64.b32decode(padded, casefold=True)
    except Exception:
        return None
    counter = int((time.time() if now is None else now) // 30)
    for candidate in (counter - 1, counter, counter + 1):
        if candidate < 0:
            continue
        digest = hmac.new(key, candidate.to_bytes(8, 'big'), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        number = (int.from_bytes(digest[offset:offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000
        if hmac.compare_digest(f'{number:06d}', code):
            return candidate
    return None


def login_blocked(ip: str, now: float) -> int:
    """Per-source progressive throttling without a global account lockout."""
    with login_lock:
        # Bound state growth and discard stale source records.
        for address, state in list(login_attempts.items()):
            state['failures'] = [t for t in state['failures'] if now - t < LOGIN_WINDOW]
            if now - state.get('last_seen', now) > 3600 and state.get('blocked_until', 0) <= now:
                login_attempts.pop(address, None)
        state = login_attempts.get(ip)
        if not state:
            return 0
        state['last_seen'] = now
        return max(0, int(state.get('blocked_until', 0) - now + 0.999))


def record_login_failure(ip: str, now: float) -> int:
    with login_lock:
        state = login_attempts.setdefault(ip, {'failures': [], 'blocked_until': 0, 'level': 0, 'last_seen': now})
        state['last_seen'] = now
        state['failures'] = [t for t in state['failures'] if now - t < LOGIN_WINDOW]
        state['failures'].append(now)
        if len(state['failures']) >= LOGIN_LIMIT:
            delay = min(LOGIN_COOLDOWN_MAX, LOGIN_COOLDOWN_BASE * (2 ** min(state['level'], 4)))
            state['level'] = min(state['level'] + 1, 5)
            state['blocked_until'] = now + delay
            state['failures'].clear()
            return delay
        if len(login_attempts) > 1024:
            oldest = sorted(login_attempts, key=lambda k: login_attempts[k].get('last_seen', 0))[:256]
            for address in oldest:
                login_attempts.pop(address, None)
        return 0


def account_login_blocked(now: float) -> int:
    """Aggregate failed login attempts across sources to resist distributed guessing."""
    with login_lock:
        state = account_login_state
        state['failures'] = [t for t in state['failures'] if now - t < LOGIN_WINDOW]
        if now - state.get('last_seen', now) > 3600 and state.get('blocked_until', 0) <= now:
            state.update({'failures': [], 'level': 0, 'blocked_until': 0})
        state['last_seen'] = now
        return max(0, int(state.get('blocked_until', 0) - now + 0.999))


def record_account_login_failure(now: float) -> int:
    with login_lock:
        state = account_login_state
        state['last_seen'] = now
        state['failures'] = [t for t in state['failures'] if now - t < LOGIN_WINDOW]
        state['failures'].append(now)
        if len(state['failures']) >= ACCOUNT_LOGIN_LIMIT:
            delay = min(ACCOUNT_LOGIN_COOLDOWN_MAX, ACCOUNT_LOGIN_COOLDOWN_BASE * (2 ** min(state['level'], 4)))
            state['level'] = min(state['level'] + 1, 5)
            state['blocked_until'] = now + delay
            state['failures'].clear()
            return delay
        return 0


def reset_account_login_failures() -> None:
    with login_lock:
        account_login_state.update({'failures': [], 'blocked_until': 0, 'level': 0, 'last_seen': time.time()})


def verify_mfa(auth_data: dict[str, Any], supplied: Any) -> bool:
    global last_totp_step
    secret = auth_data.get('totp_secret')
    if not secret:
        return supplied in (None, '')
    step = totp_counter(str(secret), supplied if isinstance(supplied, str) else '')
    if step is None:
        return False
    with totp_lock:
        persisted_step = last_totp_step
        try:
            persisted_step = max(persisted_step, int(TOTP_STATE_PATH.read_text().strip()))
        except FileNotFoundError:
            pass
        except Exception:
            # Fail closed if persistent replay state is unreadable or malformed.
            return False
        if step <= persisted_step:
            return False
        try:
            TOTP_STATE_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            tmp = TOTP_STATE_PATH.with_name('.totp-step-' + secrets.token_hex(8))
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='ascii') as handle:
                handle.write(str(step) + '\n')
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, TOTP_STATE_PATH)
        except Exception:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            return False
        last_totp_step = step
    return True


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 16384:
        raise ValueError('Invalid WebAuthn binary field.')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('Invalid WebAuthn binary field.')
    return base64.urlsafe_b64decode(value + ('=' * ((4 - len(value) % 4) % 4)))


def load_passkey_records() -> list[dict[str, Any]]:
    """Read validated public credential material from the portal state directory."""
    with passkeys_lock:
        try:
            data = json.loads(PASSKEYS_PATH.read_text(encoding='utf-8'))
        except FileNotFoundError:
            return []
        if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('credentials'), list):
            raise ValueError('Passkey store format is invalid.')
        records = data['credentials']
        if len(records) > PASSKEY_MAX_CREDENTIALS:
            raise ValueError('Passkey store exceeds the credential limit.')
        cleaned: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                raise ValueError('Passkey store contains an invalid record.')
            credential_id = record.get('id')
            credential_data = record.get('credential_data')
            label = record.get('label')
            if not isinstance(credential_id, str) or not isinstance(credential_data, str):
                raise ValueError('Passkey store contains incomplete credential data.')
            if not isinstance(label, str) or not 1 <= len(label) <= 40:
                raise ValueError('Passkey store contains an invalid credential label.')
            credential_id_bytes = b64url_decode(credential_id)
            if not 1 <= len(credential_id_bytes) <= 1024:
                raise ValueError('Passkey store contains an invalid credential identifier.')
            raw_data = b64url_decode(credential_data)
            if FIDO2_AVAILABLE:
                parsed = AttestedCredentialData(raw_data)
                if not hmac.compare_digest(b64url_encode(parsed.credential_id), credential_id):
                    raise ValueError('Passkey credential identifier does not match its public key.')
            cleaned.append({
                'id': credential_id,
                'credential_data': credential_data,
                'label': label,
                'created_at': int(record.get('created_at', 0)),
                'last_used_at': int(record.get('last_used_at', 0)),
                'sign_count': max(0, int(record.get('sign_count', 0))),
            })
        return cleaned


def save_passkey_records(records: list[dict[str, Any]]) -> None:
    if len(records) > PASSKEY_MAX_CREDENTIALS:
        raise ValueError(f'You can register up to {PASSKEY_MAX_CREDENTIALS} passkeys.')
    with passkeys_lock:
        PASSKEYS_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix='.passkeys-', dir=str(PASSKEYS_PATH.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump({'version': 1, 'credentials': records}, handle, separators=(',', ':'))
                handle.write('\n')
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, PASSKEYS_PATH)
            os.chmod(PASSKEYS_PATH, 0o600)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass


def passkey_credential_objects(records: list[dict[str, Any]] | None = None) -> list[Any]:
    if not FIDO2_AVAILABLE:
        raise RuntimeError('Passkey support is not installed on this server.')
    records = load_passkey_records() if records is None else records
    return [AttestedCredentialData(b64url_decode(record['credential_data'])) for record in records]


def passkey_server() -> Any:
    if not FIDO2_AVAILABLE or not WEBAUTHN_RP_ID:
        raise RuntimeError('Passkey support is unavailable. Configure a stable DNS hostname and install python3-fido2.')
    # Explicit origin allowlist. Never derive the RP ID or trusted origin from headers.
    return Fido2Server(
        {'id': WEBAUTHN_RP_ID, 'name': "SBC Control Center"},
        attestation='none',
        verify_origin=lambda origin: isinstance(origin, str) and hmac.compare_digest(origin, WEBAUTHN_ORIGIN),
    )


def prune_webauthn_challenges(now: float | None = None) -> None:
    now = time.time() if now is None else now
    with webauthn_challenges_lock:
        for key, value in list(webauthn_challenges.items()):
            if now - value.get('created', 0) > WEBAUTHN_CHALLENGE_TTL:
                webauthn_challenges.pop(key, None)
        if len(webauthn_challenges) > 512:
            oldest = sorted(webauthn_challenges, key=lambda key: webauthn_challenges[key].get('created', 0))[:128]
            for key in oldest:
                webauthn_challenges.pop(key, None)


def create_webauthn_challenge(kind: str, state: Any, ip: str, sid: str | None = None) -> str:
    now = time.time()
    prune_webauthn_challenges(now)
    challenge_id = secrets.token_urlsafe(24)
    with webauthn_challenges_lock:
        if len(webauthn_challenges) >= 512:
            raise RuntimeError('Passkey service is busy. Try again shortly.')
        webauthn_challenges[challenge_id] = {
            'kind': kind, 'state': state, 'ip': ip, 'sid': sid, 'created': now,
        }
    return challenge_id


def take_webauthn_challenge(challenge_id: Any, kind: str, ip: str, sid: str | None = None) -> dict[str, Any] | None:
    if not isinstance(challenge_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{24,80}', challenge_id):
        return None
    with webauthn_challenges_lock:
        record = webauthn_challenges.get(challenge_id)
        if not record:
            return None
        if time.time() - record.get('created', 0) > WEBAUTHN_CHALLENGE_TTL:
            webauthn_challenges.pop(challenge_id, None)
            return None
        # A mismatched source cannot burn the legitimate browser's one-time challenge.
        if record.get('kind') != kind or record.get('ip') != ip or record.get('sid') != sid:
            return None
        return webauthn_challenges.pop(challenge_id, None)


def admin_password_valid(data: dict[str, Any]) -> bool:
    try:
        auth_data = load_auth()
        rounds = int(auth_data['iterations'])
        if auth_data.get('algorithm') != 'pbkdf2_sha256' or not 100_000 <= rounds <= 2_000_000:
            return False
        password = data.get('password')
        if not isinstance(password, str) or len(password.encode('utf-8')) > 1024:
            password = ''
        salt = bytes.fromhex(auth_data['salt'])
        expected = bytes.fromhex(auth_data['hash'])
        candidate = pbkdf2(password, salt, rounds)
        password_ok = hmac.compare_digest(candidate, expected)
        mfa_ok = verify_mfa(auth_data, data.get('otp')) if password_ok else False
        return password_ok and mfa_ok
    except Exception:
        return False


def agent_request(payload: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(SOCKET_PATH))
        sock.sendall((json.dumps(payload, separators=(',', ':')) + '\n').encode())
        data = b''
        while b'\n' not in data and len(data) < 2_000_000:
            part = sock.recv(65536)
            if not part:
                break
            data += part
        if not data:
            return {'ok': False, 'error': 'Privileged agent returned no response.'}
        return json.loads(data.split(b'\n', 1)[0].decode())
    except Exception as exc:
        return {'ok': False, 'error': f'Cannot contact the local control agent: {exc}'}
    finally:
        sock.close()


def cookie_signature(sid: str) -> str:
    return hmac.new(load_secret(), sid.encode(), hashlib.sha256).hexdigest()


def client_ip(handler: BaseHTTPRequestHandler) -> str:
    return handler.client_address[0] if handler.client_address else 'unknown'


def local_host_header_allowed(host_header: str) -> bool:
    """Accept only this device's interface addresses and explicit local aliases.

    Checking Host on every request helps prevent DNS-rebinding attacks against a
    browser that is tricked into treating the appliance as an attacker's origin.
    PORTAL_ALLOWED_HOSTS may add deliberate local aliases, never wildcard hosts.
    """
    host = (host_header or '').strip().lower()
    if not host or len(host) > 255 or any(ch in host for ch in '\r\n/@\\'):
        return False
    allowed = {
        f'127.0.0.1:{PORT}', f'localhost:{PORT}', f'[::1]:{PORT}',
    }
    if WEBAUTHN_RP_ID:
        allowed.add(f'{WEBAUTHN_RP_ID}:{PORT}')
    try:
        hostname = socket.gethostname().strip().lower().rstrip('.')
        fqdn = socket.getfqdn().strip().lower().rstrip('.')
        for name in (hostname, fqdn):
            if name and name not in {'localhost', 'localhost.localdomain'}:
                allowed.add(f'{name}:{PORT}')
    except OSError:
        pass
    for extra in os.environ.get('PORTAL_ALLOWED_HOSTS', '').split(','):
        candidate = extra.strip().lower()
        if candidate:
            allowed.add(candidate)
    # Discover active IPv4 addresses through sysfs. Avoid socket.if_nameindex():
    # on this Armbian/sunxi system its libc implementation attempts an
    # AF_PACKET operation, which is intentionally unavailable under the
    # service's RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 sandbox.
    # SIOCGIFADDR uses the already permitted AF_INET datagram socket instead.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            interfaces = Path('/sys/class/net').iterdir()
            for interface_path in interfaces:
                try:
                    interface = interface_path.name
                    request = struct.pack('256s', interface.encode('ascii', 'ignore')[:15])
                    response = fcntl.ioctl(probe.fileno(), 0x8915, request)  # SIOCGIFADDR
                    address = socket.inet_ntoa(response[20:24])
                    allowed.add(f'{address}:{PORT}')
                except (OSError, UnicodeError):
                    continue
        except OSError:
            # The explicit loopback/hostname/PORTAL_ALLOWED_HOSTS entries
            # remain usable when sysfs is unavailable; unknown hosts still fail closed.
            pass
    finally:
        probe.close()
    return host in allowed


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Bound request threads and apply a socket timeout against slow clients."""
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, server_address: tuple[str, int], handler_class: type[BaseHTTPRequestHandler]):
        self._request_slots = threading.BoundedSemaphore(32)
        super().__init__(server_address, handler_class)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(15)
        return request, address

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'SBCControlCenter'
    sys_version = ''

    def log_message(self, fmt: str, *args: Any) -> None:
        # Avoid logging cookies, request bodies, or credentials.
        print(f'[{self.log_date_time_string()}] {client_ip(self)} {fmt % args}', flush=True)

    def security_headers(self, nonce: str | None = None) -> None:
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('X-Permitted-Cross-Domain-Policies', 'none')
        # HSTS is emitted only on the TLS listener; this application never
        # creates a plaintext HTTP listener or redirect endpoint.
        if isinstance(self.connection, ssl.SSLSocket):
            self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        if nonce:
            csp = (f"default-src 'self'; style-src 'self' 'unsafe-inline'; "
                   f"script-src 'self' 'nonce-{nonce}'; img-src 'self' data:; "
                   "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                   "form-action 'self'; frame-ancestors 'none'")
        else:
            csp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        self.send_header('Content-Security-Policy', csp)

    def send_json(self, status: int, payload: dict[str, Any], extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.security_headers()
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def same_origin_request(self) -> bool:
        host = self.headers.get('Host', '')
        if not local_host_header_allowed(host):
            return False
        fetch_site = self.headers.get('Sec-Fetch-Site', '').lower()
        if fetch_site and fetch_site not in {'same-origin', 'none'}:
            return False
        origin = self.headers.get('Origin')
        if not origin:
            return True  # Non-browser clients may omit Origin; CSRF token is still required for authenticated actions.
        try:
            parsed = urllib.parse.urlsplit(origin)
            return parsed.scheme == 'https' and parsed.netloc.lower() == host.lower() and not parsed.username and not parsed.password
        except Exception:
            return False

    def read_json(self) -> dict[str, Any]:
        content_type = self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
        if content_type != 'application/json':
            raise ValueError('Content-Type must be application/json.')
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('Transfer-Encoding is not supported.')
        try:
            length = int(self.headers.get('Content-Length', ''))
        except ValueError:
            raise ValueError('A valid Content-Length is required.')
        if length < 2 or length > MAX_BODY:
            raise ValueError('Request body size is invalid.')
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError('Incomplete request body.')
        value = json.loads(raw.decode('utf-8'))
        if not isinstance(value, dict):
            raise ValueError('Expected a JSON object.')
        return value

    def session(self) -> tuple[str | None, dict[str, Any] | None]:
        raw = self.headers.get('Cookie', '')
        cookies = http.cookies.SimpleCookie()
        try:
            cookies.load(raw)
            value = cookies.get(COOKIE_NAME)
            if not value:
                return None, None
            token = value.value
            sid, sig = token.split('.', 1)
            expected = cookie_signature(sid)
            if not hmac.compare_digest(sig, expected):
                return None, None
            now = time.time()
            with sessions_lock:
                item = sessions.get(sid)
                if (not item or now - item['created'] > SESSION_ABSOLUTE_TTL
                        or now - item['last_activity'] > SESSION_IDLE_TTL):
                    sessions.pop(sid, None)
                    return None, None
                # Background dashboard polling must not keep an abandoned session alive.
                if self.headers.get('X-User-Activity') == '1':
                    item['last_activity'] = now
                return sid, dict(item)
        except Exception:
            return None, None

    def require_session(self) -> tuple[str, dict[str, Any]] | None:
        sid, item = self.session()
        if not sid or not item:
            self.send_json(401, {'ok': False, 'error': 'Your session has expired. Please sign in again.'})
            return None
        return sid, item

    def verify_csrf(self, item: dict[str, Any]) -> bool:
        supplied = self.headers.get('X-CSRF-Token', '')
        return bool(supplied) and hmac.compare_digest(supplied, item.get('csrf', ''))

    def passkey_host_matches(self) -> bool:
        # GET requests normally omit Origin, so advertise hostname readiness separately.
        return bool(
            FIDO2_AVAILABLE and WEBAUTHN_RP_ID and
            self.headers.get('Host', '').strip().lower() == f'{WEBAUTHN_RP_ID}:{PORT}'.lower()
        )

    def passkey_origin_matches(self) -> bool:
        # Every WebAuthn ceremony is POSTed from the exact HTTPS origin.
        return bool(
            self.passkey_host_matches() and
            self.headers.get('Origin', '').strip().lower() == WEBAUTHN_ORIGIN.lower()
        )

    def require_passkey_origin(self) -> bool:
        if not self.passkey_origin_matches():
            self.send_json(400, {
                'ok': False,
                'error': f'Passkeys require the trusted canonical address {WEBAUTHN_ORIGIN or "configured hostname"}. Do not use an IP address.',
            })
            return False
        return True

    def issue_session(self, auth_method: str) -> tuple[str, str, str]:
        now = time.time()
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with sessions_lock:
            for old_sid, old_item in list(sessions.items()):
                if now - old_item.get('created', 0) > SESSION_ABSOLUTE_TTL or now - old_item.get('last_activity', 0) > SESSION_IDLE_TTL:
                    sessions.pop(old_sid, None)
            if len(sessions) >= 10:
                oldest_sid = min(sessions, key=lambda key: sessions[key].get('last_activity', 0))
                sessions.pop(oldest_sid, None)
            sessions[sid] = {
                'csrf': csrf, 'created': now, 'last_activity': now,
                'auth_method': auth_method,
            }
        value = sid + '.' + cookie_signature(sid)
        cookie = f'{COOKIE_NAME}={value}; Path=/; HttpOnly; Secure; SameSite=Strict'
        return sid, csrf, cookie

    def session_passkey_management_ready(self, sid: str) -> bool:
        with sessions_lock:
            current = sessions.get(sid)
            return bool(current and current.get('passkey_manage_until', 0) >= time.time())

    def do_GET(self) -> None:
        if not local_host_header_allowed(self.headers.get('Host', '')):
            self.send_error(421, 'Misdirected Request')
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == '/assets/ui-background.png':
            try:
                body = BACKGROUND_PATH.read_bytes()
            except OSError:
                self.send_error(404, 'Theme asset not found')
                return
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Content-Length', str(len(body)))
            self.security_headers()
            self.send_header('Cache-Control', 'public, max-age=86400')
            self.end_headers()
            self.wfile.write(body)
            return
        if path == '/':
            try:
                body = HTML_PATH.read_bytes()
            except Exception:
                body = b'SBC Control Center UI file is missing.'
            nonce = secrets.token_urlsafe(18)
            body = body.replace(b'<script>', f'<script nonce="{nonce}">'.encode(), 1)
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.security_headers(nonce)
            self.end_headers()
            self.wfile.write(body)
            return
        if path == '/api/me':
            sid, item = self.session()
            try:
                mfa_enabled = bool(load_auth().get('totp_secret'))
            except Exception:
                mfa_enabled = False
            try:
                passkey_count = len(load_passkey_records()) if FIDO2_AVAILABLE else 0
                passkey_store_ok = True
            except Exception:
                passkey_count = 0
                passkey_store_ok = False
            privilege_info = agent_request({'action': 'privilege_info'}, timeout=4)
            public_state = {
                'sudo_user': privilege_info.get('sudo_user', '') if privilege_info.get('ok') else '',
                'sudo_configured': bool(privilege_info.get('configured')) if privilege_info.get('ok') else False,
                'mfa_enabled': mfa_enabled,
                'passkey_count': passkey_count,
                'passkey_store_ok': passkey_store_ok,
                'passkey_supported': bool(FIDO2_AVAILABLE and WEBAUTHN_RP_ID),
                'passkey_origin_matches': self.passkey_host_matches(),
                'passkey_rp_id': WEBAUTHN_RP_ID or None,
                'passkey_origin': WEBAUTHN_ORIGIN or None,
            }
            if not sid or not item:
                self.send_json(200, {'ok': True, 'authenticated': False, **public_state})
            else:
                self.send_json(200, {
                    'ok': True, 'authenticated': True, 'csrf': item['csrf'],
                    'auth_method': item.get('auth_method', 'password'), **public_state,
                })
            return
        if path == '/api/passkeys':
            auth = self.require_session()
            if not auth:
                return
            try:
                records = load_passkey_records()
            except Exception:
                self.send_json(503, {'ok': False, 'error': 'Passkey records could not be read safely.'})
                return
            self.send_json(200, {
                'ok': True,
                'credentials': [
                    {'id': row['id'], 'label': row['label'], 'created_at': row['created_at'], 'last_used_at': row['last_used_at']}
                    for row in records
                ],
                'supported': bool(FIDO2_AVAILABLE and WEBAUTHN_RP_ID),
                'origin_matches': self.passkey_host_matches(),
                'rp_id': WEBAUTHN_RP_ID or None,
                'origin': WEBAUTHN_ORIGIN or None,
            })
            return
        if path == '/api/status':
            auth = self.require_session()
            if not auth:
                return
            result = agent_request({'action': 'status'}, timeout=35)
            self.send_json(200 if result.get('ok') else 503, result)
            return
        if path == '/api/telemetry':
            auth = self.require_session()
            if not auth:
                return
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
            try:
                after = int(query.get('after', ['0'])[0])
                limit = int(query.get('limit', ['900'])[0])
                if after < 0 or not 1 <= limit <= 900:
                    raise ValueError
            except (TypeError, ValueError):
                self.send_json(400, {'ok': False, 'error': 'Invalid telemetry cursor or limit.'})
                return
            result = agent_request({'action': 'telemetry', 'after_sequence': after, 'limit': limit}, timeout=5)
            self.send_json(200 if result.get('ok') else 503, result)
            return
        if path == '/api/network-observability':
            auth = self.require_session()
            if not auth:
                return
            result = agent_request({'action': 'network_inventory'}, timeout=20)
            self.send_json(200 if result.get('ok') else 503, result)
            return
        if path == '/api/packet-flow-series':
            auth = self.require_session()
            if not auth:
                return
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
            flow_id = query.get('flow_id', [''])[0]
            try:
                limit = int(query.get('limit', ['60'])[0])
                if not re.fullmatch(r'[0-9a-f]{24}', flow_id) or not 1 <= limit <= 60:
                    raise ValueError
            except (TypeError, ValueError):
                self.send_json(400, {'ok': False, 'error': 'Invalid flow identifier or history limit.'})
                return
            result = agent_request({'action': 'packet_flow_series', 'flow_id': flow_id, 'limit': limit}, timeout=5)
            self.send_json(200 if result.get('ok') else 404, result)
            return
        if path == '/api/packet-capture':
            auth = self.require_session()
            if not auth:
                return
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
            try:
                after = int(query.get('after', ['0'])[0])
                limit = int(query.get('limit', ['200'])[0])
                if after < 0 or not 0 <= limit <= 250:
                    raise ValueError
            except (TypeError, ValueError):
                self.send_json(400, {'ok': False, 'error': 'Invalid packet event cursor or limit.'})
                return
            result = agent_request({'action': 'packet_capture_snapshot', 'after': after, 'limit': limit}, timeout=5)
            self.send_json(200 if result.get('ok') else 503, result)
            return
        if path == '/api/dns-query-log':
            auth = self.require_session()
            if not auth:
                return
            result = agent_request({'action': 'dns_query_log', 'limit': 50}, timeout=5)
            self.send_json(200 if result.get('ok') else 503, result)
            return
        if path == '/api/job':
            auth = self.require_session()
            if not auth:
                return
            self.send_json(200, agent_request({'action': 'job_status'}))
            return
        if path == '/api/portal-update':
            auth = self.require_session()
            if not auth:
                return
            self.send_json(200, agent_request({'action': 'portal_update_status'}))
            return
        if path == '/api/backups':
            auth = self.require_session()
            if not auth:
                return
            self.send_json(200, agent_request({'action': 'backup_list'}))
            return
        if path.startswith('/api/backups/'):
            auth = self.require_session()
            if not auth:
                return
            self.send_json(405, {'ok': False, 'error': 'Backup downloads require fresh Linux sudo-password verification. Use the Download archive control.'}, {'Allow': 'POST'})
            return
        if path == '/api/logs':
            auth = self.require_session()
            if not auth:
                return
            self.send_json(405, {'ok': False, 'error': 'System journal access requires fresh Linux sudo-password verification. Use the protected Logs action.'}, {'Allow': 'POST'})
            return
        self.send_json(404, {'ok': False, 'error': 'Not found.'})

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if not self.same_origin_request():
            self.send_json(403, {'ok': False, 'error': 'Cross-origin request rejected.'})
            return
        try:
            data = self.read_json()
        except Exception as exc:
            self.send_json(400, {'ok': False, 'error': str(exc)})
            return

        if path == '/api/passkeys/login/begin':
            if not self.require_passkey_origin():
                return
            ip = client_ip(self)
            now = time.time()
            blocked = max(login_blocked(ip, now), account_login_blocked(now))
            if blocked:
                self.send_json(429, {'ok': False, 'error': 'Sign-in temporarily rate-limited. Try again shortly.'}, {'Retry-After': str(blocked)})
                return
            if not FIDO2_AVAILABLE:
                self.send_json(503, {'ok': False, 'error': 'Passkey support is not installed on this server.'})
                return
            try:
                records = load_passkey_records()
                if not records:
                    raise ValueError('No passkeys are enrolled.')
                request_options, state = passkey_server().authenticate_begin(
                    passkey_credential_objects(records), user_verification='required'
                )
                ceremony_id = create_webauthn_challenge('login', state, ip)
                self.send_json(200, {'ok': True, 'ceremony_id': ceremony_id, 'options': dict(request_options)})
            except Exception:
                self.send_json(503, {'ok': False, 'error': 'Passkey sign-in is unavailable. Use your administrator password instead.'})
            return

        if path == '/api/passkeys/login/complete':
            if not self.require_passkey_origin():
                return
            ip = client_ip(self)
            ceremony = take_webauthn_challenge(data.get('ceremony_id'), 'login', ip)
            if not ceremony or not FIDO2_AVAILABLE:
                delay = max(record_login_failure(ip, time.time()), record_account_login_failure(time.time()))
                headers = {'Retry-After': str(delay)} if delay else None
                self.send_json(401, {'ok': False, 'error': 'Passkey sign-in failed or expired. Try again.'}, headers)
                return
            try:
                records = load_passkey_records()
                credentials = passkey_credential_objects(records)
                credential_response = data.get('credential')
                if not isinstance(credential_response, dict) or not isinstance(credential_response.get('response'), dict):
                    raise ValueError('Incomplete passkey response.')
                auth_data = AuthenticatorData(b64url_decode(credential_response['response'].get('authenticatorData')))
                matched = passkey_server().authenticate_complete(ceremony['state'], credentials, credential_response)
                if not auth_data.is_user_verified():
                    raise ValueError('The authenticator did not verify the user.')
                credential_id = b64url_encode(matched.credential_id)
                now = time.time()
                with passkeys_lock:
                    latest = load_passkey_records()
                    record = next((row for row in latest if hmac.compare_digest(row['id'], credential_id)), None)
                    if not record:
                        raise ValueError('The authenticator is no longer registered.')
                    old_count = int(record.get('sign_count', 0))
                    new_count = int(auth_data.counter)
                    if old_count > 0 and new_count > 0 and new_count <= old_count:
                        raise ValueError('The authenticator counter did not advance.')
                    record['sign_count'] = max(old_count, new_count)
                    record['last_used_at'] = int(now)
                    save_passkey_records(latest)
            except Exception:
                delay = max(record_login_failure(ip, time.time()), record_account_login_failure(time.time()))
                headers = {'Retry-After': str(delay)} if delay else None
                print(f'[AUTH] {ip} passkey-sign-in-failed', flush=True)
                self.send_json(401, {'ok': False, 'error': 'Passkey sign-in failed. Try again or use your administrator password.'}, headers)
                return
            with login_lock:
                login_attempts.pop(ip, None)
            reset_account_login_failures()
            _sid, csrf, cookie = self.issue_session('passkey')
            try:
                mfa_enabled = bool(load_auth().get('totp_secret'))
            except Exception:
                mfa_enabled = False
            print(f'[AUTH] {ip} sign-in-success method=passkey', flush=True)
            self.send_json(200, {'ok': True, 'csrf': csrf, 'auth_method': 'passkey',
                                 'mfa_enabled': mfa_enabled,
                                 'passkey_count': len(load_passkey_records())}, {'Set-Cookie': cookie})
            return

        if path == '/api/login':
            ip = client_ip(self)
            now = time.time()
            blocked = max(login_blocked(ip, now), account_login_blocked(now))
            if blocked:
                self.send_json(429, {'ok': False, 'error': 'Sign-in temporarily rate-limited. Try again shortly.'}, {'Retry-After': str(blocked)})
                return
            if not login_verify_slots.acquire(blocking=False):
                self.send_json(429, {'ok': False, 'error': 'Sign-in service is busy. Try again shortly.'}, {'Retry-After': '2'})
                return
            try:
                valid = admin_password_valid(data)
            finally:
                login_verify_slots.release()
            if not valid:
                delay = max(record_login_failure(ip, now), record_account_login_failure(now))
                print(f'[AUTH] {ip} sign-in-failed', flush=True)
                headers = {'Retry-After': str(delay)} if delay else None
                status = 429 if delay else 401
                self.send_json(status, {'ok': False, 'error': 'Sign-in failed. Check your credentials and try again.'}, headers)
                return
            with login_lock:
                login_attempts.pop(ip, None)
            reset_account_login_failures()
            _sid, csrf, cookie = self.issue_session('password')
            try:
                passkey_count = len(load_passkey_records())
                mfa_enabled = bool(load_auth().get('totp_secret'))
            except Exception:
                passkey_count = 0
                mfa_enabled = False
            print(f'[AUTH] {ip} sign-in-success mfa={mfa_enabled} method=password', flush=True)
            self.send_json(200, {'ok': True, 'csrf': csrf, 'auth_method': 'password',
                                 'mfa_enabled': mfa_enabled, 'passkey_count': passkey_count}, {'Set-Cookie': cookie})
            return

        auth = self.require_session()
        if not auth:
            return
        sid, item = auth

        if path == '/api/backups/download':
            if not self.verify_csrf(item):
                self.send_json(403, {'ok': False, 'error': 'CSRF validation failed.'})
                return
            name = data.get('name')
            token = data.get('privilege_token')
            if not isinstance(name, str) or not re.fullmatch(r'sbc-control-config-[0-9]{8}T[0-9]{6}Z\.tar\.gz', name):
                self.send_json(400, {'ok': False, 'error': 'Invalid backup name.'})
                return
            allowed = agent_request({'action': 'backup_download', 'session_id': sid,
                                     'privilege_token': token, 'name': name}, timeout=12)
            if not allowed.get('ok'):
                self.send_json(403, allowed)
                return
            backup_path = Path('/var/lib/sbc-control-center/backups') / name
            fd = None
            try:
                fd = os.open(backup_path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
                    raise ValueError('Backup is not a regular file or exceeds the 64 MiB download limit.')
                with os.fdopen(fd, 'rb', closefd=True) as handle:
                    fd = None
                    body = handle.read(64 * 1024 * 1024 + 1)
                if len(body) > 64 * 1024 * 1024:
                    raise ValueError('Backup exceeds the download limit.')
            except Exception as exc:
                if fd is not None:
                    os.close(fd)
                self.send_json(404, {'ok': False, 'error': f'Backup is unavailable: {exc}'})
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/gzip')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Disposition', f'attachment; filename="{name}"')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.security_headers()
            self.end_headers()
            self.wfile.write(body)
            return

        if path == '/api/privilege/authorize':
            if not self.verify_csrf(item):
                self.send_json(403, {'ok': False, 'error': 'CSRF validation failed.'})
                return
            password = data.get('password')
            if not isinstance(password, str) or len(password.encode('utf-8')) > 512:
                self.send_json(400, {'ok': False, 'error': 'Password input is invalid.'})
                return
            intent = data.get('intent')
            if not isinstance(intent, dict):
                self.send_json(400, {'ok': False, 'error': 'The privileged operation scope is missing.'})
                return
            result = agent_request({'action': 'privilege_authorize', 'session_id': sid,
                                    'password': password, 'intent': intent}, timeout=12)
            self.send_json(200 if result.get('ok') else 403, result)
            return

        if path.startswith('/api/passkeys/'):
            if not self.verify_csrf(item):
                self.send_json(403, {'ok': False, 'error': 'CSRF validation failed.'})
                return
            if not self.require_passkey_origin():
                return
            if not FIDO2_AVAILABLE:
                self.send_json(503, {'ok': False, 'error': 'Passkey support is not installed on this server.'})
                return

            if path == '/api/passkeys/reauth':
                ip = client_ip(self)
                now = time.time()
                blocked = max(login_blocked(ip, now), account_login_blocked(now))
                if blocked:
                    self.send_json(429, {'ok': False, 'error': 'Security confirmation is temporarily rate-limited.'}, {'Retry-After': str(blocked)})
                    return
                if not login_verify_slots.acquire(blocking=False):
                    self.send_json(429, {'ok': False, 'error': 'Security confirmation service is busy. Try again shortly.'}, {'Retry-After': '2'})
                    return
                try:
                    valid = admin_password_valid(data)
                finally:
                    login_verify_slots.release()
                if not valid:
                    delay = max(record_login_failure(ip, now), record_account_login_failure(now))
                    headers = {'Retry-After': str(delay)} if delay else None
                    self.send_json(403, {'ok': False, 'error': 'Security confirmation failed. Check your password and authenticator code.'}, headers)
                    return
                with sessions_lock:
                    current = sessions.get(sid)
                    if not current:
                        self.send_json(401, {'ok': False, 'error': 'Your session has expired. Sign in again.'})
                        return
                    current['passkey_manage_until'] = now + WEBAUTHN_MANAGEMENT_TTL
                self.send_json(200, {'ok': True, 'expires_in': WEBAUTHN_MANAGEMENT_TTL})
                return

            if not self.session_passkey_management_ready(sid):
                self.send_json(403, {'ok': False, 'error': 'Confirm your administrator password again before changing passkeys.'})
                return

            if path == '/api/passkeys/register/begin':
                try:
                    records = load_passkey_records()
                    if len(records) >= PASSKEY_MAX_CREDENTIALS:
                        raise ValueError(f'You can register up to {PASSKEY_MAX_CREDENTIALS} passkeys.')
                    creation_options, state = passkey_server().register_begin(
                        {'id': WEBAUTHN_USER_ID, 'name': 'admin', 'displayName': "SBC Control Center"},
                        credentials=passkey_credential_objects(records),
                        resident_key_requirement='required',
                        user_verification='required',
                    )
                    ceremony_id = create_webauthn_challenge('register', state, client_ip(self), sid)
                    self.send_json(200, {'ok': True, 'ceremony_id': ceremony_id, 'options': dict(creation_options)})
                except ValueError as exc:
                    self.send_json(400, {'ok': False, 'error': str(exc)})
                except Exception:
                    self.send_json(503, {'ok': False, 'error': 'Passkey registration could not be started. Check the server configuration and try again.'})
                return

            if path == '/api/passkeys/register/complete':
                ceremony = take_webauthn_challenge(data.get('ceremony_id'), 'register', client_ip(self), sid)
                if not ceremony:
                    self.send_json(400, {'ok': False, 'error': 'Passkey registration expired. Confirm your password and start again.'})
                    return
                label = data.get('label', 'This device')
                if not isinstance(label, str):
                    label = ''
                label = label.strip()
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,39}', label):
                    self.send_json(400, {'ok': False, 'error': 'Use a 1 to 40 character label with letters, numbers, spaces, dots, underscores, parentheses or hyphens.'})
                    return
                try:
                    credential_response = data.get('credential')
                    if not isinstance(credential_response, dict) or not isinstance(credential_response.get('response'), dict):
                        raise ValueError('Incomplete passkey response.')
                    registered = passkey_server().register_complete(ceremony['state'], credential_response)
                    if not registered.is_user_verified():
                        raise ValueError('The authenticator did not verify the user.')
                    credential_data = registered.credential_data
                    if credential_data is None:
                        raise ValueError('The authenticator did not return a public credential.')
                    credential_id = b64url_encode(credential_data.credential_id)
                    raw_credential_data = b64url_encode(bytes(credential_data))
                    with passkeys_lock:
                        records = load_passkey_records()
                        if len(records) >= PASSKEY_MAX_CREDENTIALS:
                            raise ValueError(f'You can register up to {PASSKEY_MAX_CREDENTIALS} passkeys.')
                        if any(hmac.compare_digest(row['id'], credential_id) for row in records):
                            raise ValueError('This passkey is already registered.')
                        records.append({
                            'id': credential_id,
                            'credential_data': raw_credential_data,
                            'label': label,
                            'created_at': int(time.time()),
                            'last_used_at': 0,
                            'sign_count': max(0, int(registered.counter)),
                        })
                        save_passkey_records(records)
                    with sessions_lock:
                        current = sessions.get(sid)
                        if current:
                            current.pop('passkey_manage_until', None)
                    self.send_json(200, {'ok': True, 'credential_count': len(records)})
                except ValueError as exc:
                    self.send_json(400, {'ok': False, 'error': str(exc)})
                except Exception:
                    self.send_json(400, {'ok': False, 'error': 'Passkey registration could not be verified. No credential was saved.'})
                return

            if path == '/api/passkeys/remove':
                credential_id = data.get('credential_id')
                if not isinstance(credential_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,2048}', credential_id):
                    self.send_json(400, {'ok': False, 'error': 'Select a valid registered passkey.'})
                    return
                with passkeys_lock:
                    records = load_passkey_records()
                    remaining = [row for row in records if not hmac.compare_digest(row['id'], credential_id)]
                    if len(remaining) == len(records):
                        self.send_json(404, {'ok': False, 'error': 'That passkey is no longer registered.'})
                        return
                    save_passkey_records(remaining)
                with sessions_lock:
                    current = sessions.get(sid)
                    if current:
                        current.pop('passkey_manage_until', None)
                self.send_json(200, {'ok': True, 'credential_count': len(remaining)})
                return

            self.send_json(404, {'ok': False, 'error': 'Not found.'})
            return

        if path == '/api/logout':
            if not self.verify_csrf(item):
                self.send_json(403, {'ok': False, 'error': 'CSRF validation failed.'})
                return
            with sessions_lock:
                sessions.pop(sid, None)
            self.send_json(200, {'ok': True}, {'Set-Cookie': f'{COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'})
            return
        if path == '/api/action':
            if not self.verify_csrf(item):
                self.send_json(403, {'ok': False, 'error': 'CSRF validation failed.'})
                return
            action = data.get('action')
            if action == 'service':
                payload = {'action': 'service', 'unit': data.get('unit'), 'verb': data.get('verb')}
            elif action == 'update_job':
                payload = {'action': 'update_job', 'kind': data.get('kind')}
            elif action in {'reboot', 'poweroff'}:
                payload = {'action': action}
            elif action == 'wifi_config':
                payload = {'action': 'wifi_config', 'radio': data.get('radio'),
                           'ssid': data.get('ssid'), 'channel': data.get('channel'),
                           'password': data.get('password')}
            elif action == 'backup_create':
                payload = {'action': 'backup_create'}
            elif action == 'logs':
                payload = {'action': 'logs', 'unit': data.get('unit')}
            elif action == 'console':
                payload = {'action': 'console', 'command': data.get('command')}
            elif action == 'portal_update_source':
                payload = {'action': 'portal_update_source', 'repo': data.get('repo')}
            elif action == 'portal_update_check':
                payload = {'action': 'portal_update_check'}
            elif action == 'network_scan':
                payload = {'action': 'network_scan', 'interfaces': data.get('interfaces')}
            elif action == 'network_fingerprint':
                payload = {'action': 'network_fingerprint', 'address': data.get('address')}
            elif action == 'packet_capture_start':
                payload = {'action': 'packet_capture_start', 'duration_seconds': data.get('duration_seconds'),
                           'interfaces': data.get('interfaces'), 'save_pcap': data.get('save_pcap', False)}
            elif action == 'packet_capture_stop':
                payload = {'action': 'packet_capture_stop'}
            elif action == 'packet_analyse':
                payload = {'action': 'packet_analyse', 'name': data.get('name')}
            elif action == 'network_label':
                payload = {'action': 'network_label', 'mac': data.get('mac'), 'label': data.get('label')}
            elif action == 'network_unlabel':
                payload = {'action': 'network_unlabel', 'mac': data.get('mac')}
            else:
                self.send_json(400, {'ok': False, 'error': 'Unsupported action.'})
                return
            payload['session_id'] = sid
            token = data.get('privilege_token')
            if isinstance(token, str):
                payload['privilege_token'] = token
            self.send_json(200, agent_request(payload, timeout=50))
            return
        self.send_json(404, {'ok': False, 'error': 'Not found.'})

    def do_HEAD(self) -> None:
        if not local_host_header_allowed(self.headers.get('Host', '')):
            self.send_error(421, 'Misdirected Request')
            return
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
        else:
            self.send_error(404)


def drop_web_privileges() -> int:
    """Drop to the dedicated unprivileged account before opening the HTTP listener."""
    account = pwd.getpwnam('sbc-control-center')
    current_uid = os.geteuid()
    if current_uid == 0:
        # Do not inherit optional groups (for example sudo/adm) from the host account.
        os.setgroups([account.pw_gid])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
        current_uid = os.geteuid()
    if account.pw_uid == 0 or current_uid != account.pw_uid:
        raise PermissionError('The web portal must run as the unprivileged sbc-control-center account.')
    # Refuse unexpected supplementary capabilities such as adm, sudo, or docker.
    # systemd starts this service with only its dedicated primary group.
    unexpected_groups = set(os.getgroups()) - {account.pw_gid}
    if unexpected_groups:
        raise PermissionError('The web portal account has unexpected supplementary groups; remove them before starting the service.')
    return current_uid


def build_tls_context() -> ssl.SSLContext:
    """Build the only supported listener context; plaintext HTTP is never served."""
    if not CERT_PATH.is_file() or not PRIVATE_KEY_PATH.is_file():
        raise RuntimeError('TLS certificate or private key is missing. Run install.sh first.')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(str(CERT_PATH), str(PRIVATE_KEY_PATH))
    return context


def main() -> None:
    drop_web_privileges()
    try:
        context = build_tls_context()
    except (OSError, RuntimeError, ssl.SSLError) as exc:
        raise SystemExit(f'HTTPS startup refused: {exc}') from exc
    server = BoundedThreadingHTTPServer((BIND, PORT), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f'SBC Control Center listening on https://{BIND}:{PORT}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
