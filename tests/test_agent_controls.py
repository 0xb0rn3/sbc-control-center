import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sbc_agent_test', ROOT / 'agent.py')
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

class AgentControlTests(unittest.TestCase):
    def test_console_help_is_available(self):
        result = agent.run_console_command('help')
        self.assertTrue(result['ok'])
        self.assertIn('not a general shell', result['output'])

    def test_console_rejects_shell_syntax_and_mutations(self):
        for command in ('rm -rf /', 'ip -br addr; reboot', 'bash -c id', 'cat /etc/shadow', 'systemctl restart ssh', 'ip route add default'):
            with self.subTest(command=command), mock.patch.object(agent, 'run_cmd') as run:
                result = agent.run_console_command(command)
                self.assertFalse(result['ok'])
                run.assert_not_called()

    def test_console_runs_fixed_arguments_without_shell(self):
        with mock.patch.object(agent, 'run_cmd', return_value={'rc': 0, 'out': 'Mem: test', 'err': ''}) as run:
            result = agent.run_console_command('free -h')
        self.assertTrue(result['ok'])
        self.assertEqual(result['output'], 'Mem: test')
        self.assertEqual(run.call_args.args[0], ['/usr/bin/free', '-h'])

    def test_console_journal_requires_approved_unit_and_bounded_count(self):
        with mock.patch.object(agent, 'run_cmd', return_value={'rc': 0, 'out': 'ok', 'err': ''}) as run:
            self.assertTrue(agent.run_console_command('journalctl -u dnsmasq -n 40')['ok'])
            self.assertEqual(run.call_args.args[0], ['/usr/bin/journalctl', '-u', 'dnsmasq', '-n', '40', '--no-pager', '-o', 'short-iso'])
            run.reset_mock()
            self.assertFalse(agent.run_console_command('journalctl -u unknown -n 40')['ok'])
            self.assertFalse(agent.run_console_command('journalctl -u dnsmasq -n 999')['ok'])
            run.assert_not_called()

    def test_update_repo_is_strictly_owner_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = agent.UPDATE_SOURCE_PATH
            original_base = agent.BASE
            agent.BASE = Path(tmp)
            agent.UPDATE_SOURCE_PATH = Path(tmp) / 'source.json'
            try:
                with mock.patch.object(agent, 'schedule_portal_update_check', return_value={'ok': True}):
                    self.assertFalse(agent.save_update_repo('owner/repo;curl bad')['ok'])
                    result = agent.save_update_repo('0xb0rn3/sbc-control-center')
                self.assertTrue(result['ok'])
                self.assertEqual(agent.read_update_repo(), '0xb0rn3/sbc-control-center')
            finally:
                agent.UPDATE_SOURCE_PATH = original
                agent.BASE = original_base


    def test_portal_release_checker_only_uses_validated_github_release(self):
        import json
        import io
        with tempfile.TemporaryDirectory() as tmp:
            original_state_path = agent.UPDATE_STATE_PATH
            original_state_dir = agent.STATE
            original_state = dict(agent.portal_update_state)
            agent.STATE = Path(tmp)
            agent.UPDATE_STATE_PATH = Path(tmp) / 'portal-update.json'
            agent.portal_update_state.update({'state': 'checking', 'checking': True, 'repo': '0xb0rn3/sbc-control-center'})
            payload = json.dumps({
                'tag_name': 'v0.0.2', 'name': 'Release 0.0.2',
                'html_url': 'https://github.com/0xb0rn3/sbc-control-center/releases/tag/v0.0.2',
                'published_at': '2026-11-20T00:00:00Z', 'body': 'Security fixes and UI improvements.'
            }).encode()
            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def read(self, limit): return payload
            class Opener:
                def open(self, request, timeout):
                    self.url = request.full_url
                    self.timeout = timeout
                    return Response()
            opener = Opener()
            try:
                with mock.patch.object(agent, 'read_update_repo', return_value='0xb0rn3/sbc-control-center'), \
                     mock.patch.object(agent, 'current_app_version', return_value='0.0.1-1'), \
                     mock.patch.object(agent.urllib.request, 'build_opener', return_value=opener):
                    agent._portal_update_worker()
                self.assertEqual(opener.url, 'https://api.github.com/repos/0xb0rn3/sbc-control-center/releases/latest')
                self.assertEqual(opener.timeout, 12)
                self.assertEqual(agent.portal_update_state['latest_version'], 'v0.0.2')
                self.assertTrue(agent.portal_update_state['update_available'])
                self.assertIsNone(agent.portal_update_state['error'])
                self.assertTrue(agent.UPDATE_STATE_PATH.exists())
            finally:
                agent.UPDATE_STATE_PATH = original_state_path
                agent.STATE = original_state_dir
                agent.portal_update_state.clear()
                agent.portal_update_state.update(original_state)

    def test_release_checker_rejects_untrusted_release_url(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            original_state_path = agent.UPDATE_STATE_PATH
            original_state_dir = agent.STATE
            original_state = dict(agent.portal_update_state)
            agent.STATE = Path(tmp)
            agent.UPDATE_STATE_PATH = Path(tmp) / 'portal-update.json'
            payload = json.dumps({
                'tag_name': 'v0.0.1', 'name': 'Release 0.0.2',
                'html_url': 'https://github.com.attacker.invalid/owner/repo/releases/tag/v0.0.1',
                'published_at': '2026-11-20T00:00:00Z', 'body': 'Unexpected host.'
            }).encode()
            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def read(self, limit): return payload
            class Opener:
                def open(self, request, timeout): return Response()
            try:
                with mock.patch.object(agent, 'read_update_repo', return_value='owner/repo'), \
                     mock.patch.object(agent, 'current_app_version', return_value='0.0.1-1'), \
                     mock.patch.object(agent.urllib.request, 'build_opener', return_value=Opener()):
                    agent._portal_update_worker()
                self.assertEqual(agent.portal_update_state['state'], 'error')
                self.assertFalse(agent.portal_update_state['update_available'])
                self.assertIn('outside the configured repository', agent.portal_update_state['error'])
            finally:
                agent.UPDATE_STATE_PATH = original_state_path
                agent.STATE = original_state_dir
                agent.portal_update_state.clear()
                agent.portal_update_state.update(original_state)

    def test_console_supports_read_only_host_diagnostics(self):
        with mock.patch.object(agent, 'run_cmd', return_value={'rc': 0, 'out': 'sample output', 'err': ''}) as run:
            result = agent.run_console_command('systemctl --failed')
        self.assertTrue(result['ok'])
        self.assertEqual(run.call_args.args[0], ['/usr/bin/systemctl', '--failed', '--no-pager', '--no-legend'])
        run.reset_mock()
        self.assertFalse(agent.run_console_command('systemctl restart ssh')['ok'])
        run.assert_not_called()

    def test_configured_vpn_unit_is_validated_and_registered(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            original_path = agent.CONFIG_PATH
            config_path = Path(tmp) / 'config.json'
            agent.CONFIG_PATH = config_path
            try:
                config_path.write_text(json.dumps({'vpn_interface': 'wg-home', 'vpn_unit': 'wg-quick@wg-home'}))
                cfg = agent.load_config()
                self.assertEqual(cfg['vpn_interface'], 'wg-home')
                self.assertEqual(cfg['vpn_unit'], 'wg-quick@wg-home')
                config_path.write_text(json.dumps({'vpn_interface': 'bad;command', 'vpn_unit': 'wg-quick@bad;command'}))
                cfg = agent.load_config()
                self.assertEqual(cfg['vpn_interface'], agent.DEFAULT_CONFIG['vpn_interface'])
                self.assertEqual(cfg['vpn_unit'], agent.DEFAULT_CONFIG['vpn_unit'])
            finally:
                agent.CONFIG_PATH = original_path


    def test_root_only_actions_require_a_fresh_sudo_grant(self):
        requests = [
            {'action': 'service', 'unit': 'dnsmasq', 'verb': 'restart'},
            {'action': 'update_job', 'kind': 'check_updates'},
            {'action': 'logs', 'unit': 'dnsmasq'},
            {'action': 'backup_download', 'name': 'sbc-control-config-20261120T120000Z.tar.gz'},
            {'action': 'backup_create'},
            {'action': 'wifi_config', 'radio': 'radio5', 'ssid': 'Test AP', 'channel': 149, 'password': 'sample-password'},
            {'action': 'reboot'},
            {'action': 'poweroff'},
            {'action': 'portal_update_source', 'repo': 'owner/repo'},
            {'action': 'console', 'command': 'nft list table inet apguard'},
            {'action': 'console', 'command': 'journalctl -u dnsmasq -n 40'},
            {'action': 'console', 'command': 'ss -lntup'},
            {'action': 'console', 'command': 'systemctl status dnsmasq'},
            {'action': 'console', 'command': 'wg show'},
        ]
        with mock.patch.object(agent, 'run_cmd') as run, \
             mock.patch.object(agent, 'start_job') as start_job, \
             mock.patch.object(agent, 'consume_privilege_grant', return_value=False):
            for request in requests:
                with self.subTest(action=request['action'], command=request.get('command')):
                    result = agent.do_action(request)
                    self.assertFalse(result['ok'])
                    self.assertIn('sudo-password verification', result['error'])
            run.assert_not_called()
            start_job.assert_not_called()

    def test_privileged_console_classification_includes_root_diagnostics(self):
        for command in ('status', 'nft list table inet apguard', 'journalctl -u dnsmasq -n 40',
                        'ss -lntup', 'systemctl status dnsmasq', 'wg show'):
            with self.subTest(command=command):
                self.assertTrue(agent.console_requires_privilege(command))
        for command in ('help', 'free -h', 'uptime', 'ip -br addr'):
            with self.subTest(command=command):
                self.assertFalse(agent.console_requires_privilege(command))

    def test_sudo_authorization_returns_a_single_use_session_and_action_bound_token(self):
        session_id = 'S' * 48
        intent = {'action': 'service', 'unit': 'dnsmasq', 'verb': 'restart'}
        with mock.patch.object(agent, 'configured_sudo_user', return_value='admin'), \
             mock.patch.object(agent, '_sudo_user_is_authorized', return_value=True), \
             mock.patch.object(agent.pam_auth, 'authenticate', return_value=True) as pam:
            result = agent.authorize_privileged_session({'session_id': session_id, 'password': 'correct-test-password', 'intent': intent})
        self.assertTrue(result['ok'])
        self.assertEqual(result['expires_in'], agent.PRIVILEGE_GRANT_TTL)
        self.assertEqual(result['sudo_user'], 'admin')
        self.assertNotIn('correct-test-password', repr(agent.privilege_grants))
        pam.assert_called_once_with('admin', 'correct-test-password', service='sudo')
        request = {'session_id': session_id, 'privilege_token': result['token'], **intent}
        mismatch = {'session_id': session_id, 'privilege_token': result['token'], 'action': 'poweroff'}
        self.assertFalse(agent.consume_privilege_grant(mismatch))
        self.assertTrue(agent.consume_privilege_grant(request))
        self.assertFalse(agent.consume_privilege_grant(request))

    def test_sudo_authorization_rejects_missing_or_unapproved_scope(self):
        session_id = 'T' * 48
        with mock.patch.object(agent.pam_auth, 'authenticate') as pam:
            missing = agent.authorize_privileged_session({'session_id': session_id, 'password': 'irrelevant'})
            invalid = agent.authorize_privileged_session({'session_id': session_id, 'password': 'irrelevant',
                                                          'intent': {'action': 'console', 'command': 'reboot'}})
        self.assertFalse(missing['ok'])
        self.assertFalse(invalid['ok'])
        pam.assert_not_called()

    def test_privilege_scope_rejects_malformed_json_types(self):
        for intent in (None, [], {'action': []}, {'action': 'service', 'unit': [], 'verb': 'restart'},
                       {'action': 'update_job', 'kind': []}, {'action': 'wifi_config', 'radio': [], 'ssid': 'abc', 'channel': 1},
                       {'action': 'logs', 'unit': []}, {'action': 'backup_download', 'name': []}):
            with self.subTest(intent=intent):
                self.assertIsNone(agent.privilege_scope_hash(intent))

    def test_privilege_scope_binds_wifi_configuration_without_persisting_passphrase(self):
        intent = {'action': 'wifi_config', 'radio': 'radio5', 'ssid': 'Test network',
                  'channel': '149', 'password': 'correct-horse-battery'}
        scope_hash = agent.privilege_scope_hash(intent)
        self.assertIsNotNone(scope_hash)
        self.assertNotIn('correct-horse-battery', repr(scope_hash))
        changed = {**intent, 'ssid': 'Other network'}
        self.assertNotEqual(scope_hash, agent.privilege_scope_hash(changed))

    def test_sudo_authentication_is_rate_limited_across_new_sessions(self):
        agent.privilege_user_failures.clear()
        intent = {'action': 'service', 'unit': 'dnsmasq', 'verb': 'restart'}
        with mock.patch.object(agent, 'configured_sudo_user', return_value='admin'), \
             mock.patch.object(agent, '_sudo_user_is_authorized', return_value=True), \
             mock.patch.object(agent.pam_auth, 'authenticate', return_value=False) as pam:
            for i in range(5):
                result = agent.authorize_privileged_session({'session_id': f'{i:040d}', 'password': 'wrong', 'intent': intent})
                self.assertFalse(result['ok'])
            blocked = agent.authorize_privileged_session({'session_id': 'Z' * 40, 'password': 'wrong', 'intent': intent})
        self.assertIn('temporarily locked', blocked['error'])
        self.assertEqual(pam.call_count, 5)
        agent.privilege_user_failures.clear()
        agent.privilege_failures.clear()

    def test_agent_socket_only_accepts_the_dedicated_portal_uid(self):
        import struct
        from types import SimpleNamespace
        class Peer:
            def __init__(self, uid): self.uid = uid
            def getsockopt(self, *_args): return struct.pack('3i', 123, self.uid, 100)
        with mock.patch.object(agent.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1234)):
            self.assertTrue(agent.agent_peer_allowed(Peer(1234)))
            self.assertFalse(agent.agent_peer_allowed(Peer(0)))
            self.assertFalse(agent.agent_peer_allowed(Peer(2000)))

    def test_backup_download_is_in_the_privileged_action_set(self):
        with mock.patch.object(agent, 'consume_privilege_grant', return_value=False):
            result = agent.do_action({'action': 'backup_download',
                                      'name': 'sbc-control-config-20261120T120000Z.tar.gz'})
        self.assertFalse(result['ok'])
        self.assertIn('sudo-password verification', result['error'])

    def test_numeric_version(self):
        self.assertEqual(agent.numeric_version('v0.0.1'), (0, 0, 1, 0))
        self.assertEqual(agent.numeric_version('v0.0.1-1'), (0, 0, 1, 1))
        self.assertGreater(agent.numeric_version('0.0.1-1'), agent.numeric_version('0.0.1'))
        self.assertGreater(agent.numeric_version('2.10.0'), agent.numeric_version('2.9.9'))
        self.assertGreater(agent.numeric_version('0.0.1-2'), agent.numeric_version('0.0.1-1'))
        self.assertGreater(agent.numeric_version('0.0.2'), agent.numeric_version('0.0.1-1'))
        self.assertLess(agent.numeric_version('0.0.1'), agent.numeric_version('0.0.1-1'))
        self.assertIsNone(agent.numeric_version('latest'))
    def test_dashboard_status_avoids_privileged_firewall_and_process_owner_queries(self):
        calls = []
        def fake_run(args, timeout=10):
            calls.append(args)
            if args[:3] == ['/usr/sbin/ip', '-j', 'address'] or args[:3] == ['/usr/bin/ip', '-j', 'address']:
                return {'rc': 0, 'out': '[]', 'err': ''}
            return {'rc': 0, 'out': '', 'err': ''}
        with mock.patch.object(agent, 'run_cmd', side_effect=fake_run), \
             mock.patch.object(agent, 'wireguard_status', return_value={'active': False}), \
             mock.patch.object(agent, 'read_storage', return_value=[]), \
             mock.patch.object(agent, 'read_processes', return_value=[]), \
             mock.patch.object(agent, 'read_listeners', return_value='LISTEN'):
            status = agent.get_status()
        self.assertIn('sudo-password verification', status['firewall'])
        self.assertFalse(status['firewall_loaded'])
        self.assertFalse(any(args[:2] in (['/usr/sbin/nft', 'list'], ['/usr/bin/nft', 'list']) for args in calls))
        self.assertFalse(any(args == ['/usr/bin/ss', '-lntup'] for args in calls))

    def test_read_listener_summary_does_not_request_process_ownership(self):
        with mock.patch.object(agent, 'run_cmd', return_value={'rc': 0, 'out': 'LISTEN', 'err': ''}) as run:
            self.assertEqual(agent.read_listeners(), 'LISTEN')
        self.assertEqual(run.call_args.args[0], ['/usr/bin/ss', '-lntu'])


if __name__ == '__main__':
    unittest.main(verbosity=2)


class PackageSandboxTests(unittest.TestCase):
    def test_package_command_uses_transient_systemd_unit(self):
        with mock.patch.object(agent.uuid, 'uuid4', return_value=type('U', (), {'hex': 'a' * 32})()), \
             mock.patch.object(agent, 'execute_job_command', return_value=0) as execute:
            self.assertEqual(agent.execute_package_command(['/usr/bin/apt-get', 'update'], 1800), 0)
        command, timeout = execute.call_args.args[:2]
        self.assertIn('/usr/bin/systemd-run', command)
        self.assertIn('--wait', command)
        self.assertIn('--collect', command)
        self.assertIn('--pipe', command)
        self.assertIn('--unit=kickpi-control-apt-' + 'a' * 32, command)
        self.assertEqual(command[-2:], ['/usr/bin/apt-get', 'update'])
        self.assertEqual(timeout, 1800)

    def test_package_command_rejects_unapproved_apt_arguments(self):
        with mock.patch.object(agent, 'execute_job_command') as execute:
            self.assertEqual(agent.execute_package_command(['/usr/bin/apt-get', 'install', 'evil'], 10), 2)
            execute.assert_not_called()
