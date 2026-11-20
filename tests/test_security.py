import base64
import importlib.util
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sbc_web', ROOT / 'web.py')
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        web.login_attempts.clear()
        web.account_login_state.update({'failures': [], 'blocked_until': 0, 'level': 0, 'last_seen': 0})
        web.last_totp_step = -1

    def test_totp_rfc6238_sha1_vector(self):
        secret = base64.b32encode(b'12345678901234567890').decode().rstrip('=')
        self.assertEqual(web.totp_counter(secret, '287082', now=59), 1)
        self.assertIsNone(web.totp_counter(secret, '000000', now=59))

    def test_progressive_login_throttle(self):
        for _ in range(web.LOGIN_LIMIT - 1):
            self.assertEqual(web.record_login_failure('192.0.2.10', 1000), 0)
        delay = web.record_login_failure('192.0.2.10', 1000)
        self.assertEqual(delay, web.LOGIN_COOLDOWN_BASE)
        self.assertGreater(web.login_blocked('192.0.2.10', 1001), 0)
        self.assertEqual(web.login_blocked('192.0.2.10', 1061), 0)
        for _ in range(web.LOGIN_LIMIT):
            result = web.record_login_failure('192.0.2.10', 1100)
        self.assertEqual(result, web.LOGIN_COOLDOWN_BASE * 2)

    def test_totp_is_replay_protected_across_calls(self):
        secret = base64.b32encode(b'12345678901234567890').decode().rstrip('=')
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'totp-last-step'
            with mock.patch.object(web, 'TOTP_STATE_PATH', state), mock.patch.object(web.time, 'time', return_value=59):
                self.assertTrue(web.verify_mfa({'totp_secret': secret}, '287082'))
                self.assertEqual(state.read_text().strip(), '1')
                self.assertFalse(web.verify_mfa({'totp_secret': secret}, '287082'))

    def test_idle_session_only_refreshes_on_user_activity(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            original_key_path = web.KEY_PATH
            web.KEY_PATH = Path(tmp) / 'session.key'
            web.KEY_PATH.write_bytes(b'test-session-signing-key')
            sid = 'test-session-id'
            cookie = sid + '.' + web.cookie_signature(sid)
            web.sessions.clear()
            web.sessions[sid] = {'csrf': 'csrf', 'created': 1000.0, 'last_activity': 1000.0}
            fake = SimpleNamespace(headers={'Cookie': f'{web.COOKIE_NAME}={cookie}'})
            with mock.patch.object(web.time, 'time', return_value=1100.0):
                web.Handler.session(fake)
            self.assertEqual(web.sessions[sid]['last_activity'], 1000.0)
            fake.headers['X-User-Activity'] = '1'
            with mock.patch.object(web.time, 'time', return_value=1150.0):
                web.Handler.session(fake)
            self.assertEqual(web.sessions[sid]['last_activity'], 1150.0)
            with mock.patch.object(web.time, 'time', return_value=2351.0):
                got_sid, item = web.Handler.session(fake)
            self.assertIsNone(got_sid)
            self.assertIsNone(item)
            web.sessions.clear()
            web.KEY_PATH = original_key_path


    def test_root_launched_web_portal_drops_to_dedicated_unprivileged_uid(self):
        from types import SimpleNamespace
        with mock.patch.object(web.pwd, 'getpwnam', return_value=SimpleNamespace(pw_name='sbc-control-center', pw_uid=1234, pw_gid=2345)), \
             mock.patch.object(web.os, 'geteuid', side_effect=[0, 1234]), \
             mock.patch.object(web.os, 'setgroups') as setgroups, \
             mock.patch.object(web.os, 'setgid') as setgid, \
             mock.patch.object(web.os, 'setuid') as setuid, \
             mock.patch.object(web.os, 'getgroups', return_value=[2345]):
            self.assertEqual(web.drop_web_privileges(), 1234)
        setgroups.assert_called_once_with([2345])
        setgid.assert_called_once_with(2345)
        setuid.assert_called_once_with(1234)

    def test_web_portal_refuses_unexpected_supplementary_groups(self):
        from types import SimpleNamespace
        with mock.patch.object(web.pwd, 'getpwnam', return_value=SimpleNamespace(pw_name='sbc-control-center', pw_uid=1234, pw_gid=2345)), \
             mock.patch.object(web.os, 'geteuid', return_value=1234), \
             mock.patch.object(web.os, 'getgroups', return_value=[2345, 27]):
            with self.assertRaises(PermissionError):
                web.drop_web_privileges()

    def test_web_portal_refuses_to_run_as_an_unrelated_unprivileged_user(self):
        from types import SimpleNamespace
        with mock.patch.object(web.pwd, 'getpwnam', return_value=SimpleNamespace(pw_name='sbc-control-center', pw_uid=1234, pw_gid=2345)), \
             mock.patch.object(web.os, 'geteuid', return_value=1000):
            with self.assertRaises(PermissionError):
                web.drop_web_privileges()

    def test_local_host_allowlist_rejects_untrusted_host(self):
        self.assertTrue(web.local_host_header_allowed(f'127.0.0.1:{web.PORT}'))
        self.assertFalse(web.local_host_header_allowed(f'attacker.example:{web.PORT}'))
        self.assertFalse(web.local_host_header_allowed(f'192.0.2.123:{web.PORT}'))

    def test_host_allowlist_works_without_if_nameindex_or_af_packet(self):
        # The production service is sandboxed without AF_PACKET. Interface
        # discovery must use sysfs + AF_INET ioctl, never libc if_nameindex().
        from types import SimpleNamespace
        fake_response = b'\x00' * 20 + web.socket.inet_aton('192.0.2.44') + b'\x00' * 12
        with mock.patch.object(web.socket, 'if_nameindex', side_effect=OSError(97, 'Address family not supported')) as if_names, \
             mock.patch.object(web.Path, 'iterdir', return_value=[SimpleNamespace(name='eth-test')]), \
             mock.patch.object(web.fcntl, 'ioctl', return_value=fake_response):
            self.assertTrue(web.local_host_header_allowed(f'192.0.2.44:{web.PORT}'))
            if_names.assert_not_called()

    def test_account_throttle_counts_failures_across_sources(self):
        for _ in range(web.ACCOUNT_LOGIN_LIMIT - 1):
            self.assertEqual(web.record_account_login_failure(1000), 0)
        delay = web.record_account_login_failure(1000)
        self.assertEqual(delay, web.ACCOUNT_LOGIN_COOLDOWN_BASE)
        self.assertGreater(web.account_login_blocked(1001), 0)
        self.assertEqual(web.account_login_blocked(1061), 0)
        for _ in range(web.ACCOUNT_LOGIN_LIMIT):
            delay = web.record_account_login_failure(1100)
        self.assertEqual(delay, web.ACCOUNT_LOGIN_COOLDOWN_BASE * 2)
        web.reset_account_login_failures()
        self.assertEqual(web.account_login_blocked(1101), 0)

    def test_global_theme_asset_is_served_from_same_origin(self):
        original_asset = web.BACKGROUND_PATH
        with tempfile.TemporaryDirectory() as tmp:
            asset = Path(tmp) / 'ui-background.png'
            content = b'\x89PNG\r\n\x1a\n' + b'test-image-data'
            asset.write_bytes(content)
            web.BACKGROUND_PATH = asset
            server = ThreadingHTTPServer(('127.0.0.1', 0), web.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                request = Request(
                    f'http://127.0.0.1:{server.server_port}/assets/ui-background.png',
                    headers={'Host': f'127.0.0.1:{web.PORT}'},
                )
                with urlopen(request, timeout=3) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers.get_content_type(), 'image/png')
                    self.assertEqual(response.read(), content)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                web.BACKGROUND_PATH = original_asset

    def test_no_mfa_accepts_only_absent_code(self):
        self.assertTrue(web.verify_mfa({}, None))
        self.assertTrue(web.verify_mfa({}, ''))
        self.assertFalse(web.verify_mfa({}, '123456'))

    def test_webauthn_rp_id_requires_a_dns_hostname_not_an_ip(self):
        self.assertTrue(web.valid_webauthn_rp_id('sbc-control-center.local'))
        self.assertTrue(web.valid_webauthn_rp_id('server.home.example'))
        for value in ('127.0.0.1', '10.50.0.1', '::1', 'localhost', 'https://home.example', '*.home.example', 'bad_name.local'):
            with self.subTest(value=value):
                self.assertFalse(web.valid_webauthn_rp_id(value))

    def test_webauthn_challenge_is_single_use_and_bound_to_ip_and_session(self):
        with mock.patch.object(web.time, 'time', return_value=1000.0):
            challenge_id = web.create_webauthn_challenge('register', {'challenge': 'state'}, '192.0.2.10', 'session-a')
            self.assertIsNone(web.take_webauthn_challenge(challenge_id, 'register', '192.0.2.11', 'session-a'))
            # Wrong-source attempts cannot consume a challenge belonging to another client.
            self.assertIsNotNone(web.take_webauthn_challenge(challenge_id, 'register', '192.0.2.10', 'session-a'))
            self.assertIsNone(web.take_webauthn_challenge(challenge_id, 'register', '192.0.2.10', 'session-a'))

    def test_passkey_store_is_atomic_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'passkeys.json'
            original = web.PASSKEYS_PATH
            web.PASSKEYS_PATH = target
            record = {
                'id': web.b64url_encode(b'credential-id-123'),
                'credential_data': web.b64url_encode(b'public-credential-material'),
                'label': 'This laptop',
                'created_at': 100,
                'last_used_at': 0,
                'sign_count': 0,
            }
            try:
                web.save_passkey_records([record])
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                self.assertEqual(web.load_passkey_records(), [record])
                self.assertEqual(list(Path(tmp).glob('.passkeys-*')), [])
            finally:
                web.PASSKEYS_PATH = original

    def test_passkey_host_readiness_does_not_require_get_origin_header(self):
        class FakeHandler:
            headers = {'Host': f'{web.WEBAUTHN_RP_ID}:{web.PORT}'}
            passkey_host_matches = web.Handler.passkey_host_matches

        fake = FakeHandler()
        with mock.patch.object(web, 'FIDO2_AVAILABLE', True):
            self.assertTrue(web.Handler.passkey_host_matches(fake))
            self.assertFalse(web.Handler.passkey_origin_matches(fake))
            fake.headers['Origin'] = web.WEBAUTHN_ORIGIN
            self.assertTrue(web.Handler.passkey_origin_matches(fake))

    def test_passkey_management_requires_recent_step_up(self):
        web.sessions.clear()
        web.sessions['admin-session'] = {'passkey_manage_until': 200.0}
        fake = type('FakeHandler', (), {})()
        with mock.patch.object(web.time, 'time', return_value=199.0):
            self.assertTrue(web.Handler.session_passkey_management_ready(fake, 'admin-session'))
        with mock.patch.object(web.time, 'time', return_value=201.0):
            self.assertFalse(web.Handler.session_passkey_management_ready(fake, 'admin-session'))
        web.sessions.clear()

    def test_tls_context_requires_certificate_and_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(web, 'CERT_PATH', Path(tmp) / 'missing-cert.pem'), \
                 mock.patch.object(web, 'PRIVATE_KEY_PATH', Path(tmp) / 'missing-key.pem'):
                with self.assertRaisesRegex(RuntimeError, 'TLS certificate or private key is missing'):
                    web.build_tls_context()

    def test_tls_context_uses_tls_12_minimum_and_disables_compression(self):
        class FakeContext:
            def __init__(self):
                self.minimum_version = None
                self.options = 0
                self.loaded = None
            def load_cert_chain(self, cert, key): self.loaded = (cert, key)
        fake = FakeContext()
        with mock.patch.object(web, 'CERT_PATH', Path('/trusted/cert.pem')), \
             mock.patch.object(web, 'PRIVATE_KEY_PATH', Path('/trusted/key.pem')), \
             mock.patch.object(Path, 'is_file', return_value=True), \
             mock.patch.object(web.ssl, 'SSLContext', return_value=fake):
            result = web.build_tls_context()
        self.assertIs(result, fake)
        self.assertEqual(fake.minimum_version, web.ssl.TLSVersion.TLSv1_2)
        self.assertTrue(fake.options & web.ssl.OP_NO_COMPRESSION)
        self.assertEqual(fake.loaded, ('/trusted/cert.pem', '/trusted/key.pem'))

    def test_strict_transport_security_is_only_sent_on_tls_connections(self):
        class FakeTLSConnection: pass
        class HeaderSink:
            connection = FakeTLSConnection()
            def __init__(self): self.headers = []
            def send_header(self, key, value): self.headers.append((key, value))
        tls_sink = HeaderSink()
        with mock.patch.object(web.ssl, 'SSLSocket', FakeTLSConnection):
            web.Handler.security_headers(tls_sink)
            self.assertTrue(any(key == 'Strict-Transport-Security' and 'max-age=31536000' in value for key, value in tls_sink.headers))
            plain_sink = HeaderSink(); plain_sink.connection = object()
            web.Handler.security_headers(plain_sink)
            self.assertFalse(any(key == 'Strict-Transport-Security' for key, value in plain_sink.headers))

    def test_application_has_no_plaintext_http_server_fallback(self):
        source = (ROOT / 'web.py').read_text(encoding='utf-8')
        self.assertIn('context.wrap_socket(server.socket, server_side=True)', source)
        self.assertIn('context = build_tls_context()', source)
        self.assertNotIn('HTTPServer((BIND, 80)', source)


if __name__ == '__main__':
    unittest.main(verbosity=2)


class PamRootokTests(unittest.TestCase):
    def test_pam_rootok_included_stack_is_rejected(self):
        import pam_auth
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'sudo').write_text('auth include common-auth\n')
            (root / 'common-auth').write_text('auth sufficient pam_rootok.so\n')
            self.assertTrue(pam_auth.pam_stack_uses_rootok('sudo', root))

    def test_pam_stack_without_rootok_is_accepted(self):
        import pam_auth
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'sudo').write_text('auth include common-auth\naccount required pam_unix.so\n')
            (root / 'common-auth').write_text('auth required pam_unix.so\n')
            self.assertFalse(pam_auth.pam_stack_uses_rootok('sudo', root))

    def test_unreadable_or_missing_pam_stack_fails_closed(self):
        import pam_auth
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(pam_auth.pam_stack_uses_rootok('sudo', tmp))


class AgentHardeningTests(unittest.TestCase):
    def test_agent_socket_workers_are_bounded(self):
        source = (ROOT / 'agent.py').read_text()
        self.assertIn('AGENT_CLIENT_LIMIT = 8', source)
        self.assertIn('threading.BoundedSemaphore(AGENT_CLIENT_LIMIT)', source)
        self.assertIn('agent_client_slots.acquire(blocking=False)', source)

    def test_root_agent_systemd_sandbox_is_enabled(self):
        installer = (ROOT / 'install.sh').read_text()
        self.assertIn('ProtectSystem=strict', installer)
        self.assertIn('ProtectKernelTunables=yes', installer)
        self.assertIn('ProtectKernelModules=yes', installer)
        self.assertIn('ProtectControlGroups=yes', installer)
        self.assertIn('ReadWritePaths=/etc/', installer)
        self.assertIn('/var/lib/', installer)

    def test_upgrade_installs_and_rolls_back_hardened_agent_unit(self):
        upgrade = (ROOT / 'upgrade.sh').read_text()
        self.assertIn('ProtectSystem=strict', upgrade)
        self.assertIn('UNIT_BACKUP=1', upgrade)
        self.assertIn('/etc/systemd/system/sbc-control-center-agent.service', upgrade)

    def test_telemetry_polling_is_non_overlapping_one_second_delay(self):
        markup = (ROOT / 'index.html').read_text()
        self.assertIn('function scheduleTelemetryPoll()', markup)
        self.assertIn('await refreshTelemetry();scheduleTelemetryPoll();},1000)', markup)
        self.assertNotIn('setInterval(refreshTelemetry,1500)', markup)
