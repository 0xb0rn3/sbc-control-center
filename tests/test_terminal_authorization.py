import hashlib
import time
import unittest
from unittest import mock

import agent


class TerminalPrivilegeTests(unittest.TestCase):
    def setUp(self):
        self.session_id = 's' * 43
        with agent.privilege_lock:
            agent.privilege_grants.pop(self.session_id, None)

    def tearDown(self):
        with agent.privilege_lock:
            agent.privilege_grants.pop(self.session_id, None)

    def test_root_shell_is_denied_without_fresh_approval(self):
        with mock.patch.object(agent.TERMINAL_MANAGER, 'start') as start:
            result = agent.do_action({
                'action': 'terminal_start',
                'session_id': self.session_id,
                'rows': 24,
                'cols': 80,
            })
        self.assertFalse(result['ok'])
        self.assertIn('Fresh Linux sudo-password verification', result['error'])
        start.assert_not_called()

    def test_terminal_approval_is_one_time_and_session_bound(self):
        token = 'one-use-terminal-token-value'
        intent = {'action': 'terminal_start'}
        scope_hash = agent.privilege_scope_hash(intent)
        self.assertIsNotNone(scope_hash)
        with agent.privilege_lock:
            agent.privilege_grants[self.session_id] = {
                'token_hash': hashlib.sha256(token.encode()).digest(),
                'scope_hash': scope_hash,
                'expires': time.monotonic() + 30,
            }
        req = {
            'action': 'terminal_start',
            'session_id': self.session_id,
            'privilege_token': token,
        }
        self.assertTrue(agent.consume_privilege_grant(req))
        self.assertFalse(agent.consume_privilege_grant(req))

    def test_token_for_another_session_cannot_start_terminal(self):
        token = 'session-bound-terminal-token'
        with agent.privilege_lock:
            agent.privilege_grants[self.session_id] = {
                'token_hash': hashlib.sha256(token.encode()).digest(),
                'scope_hash': agent.privilege_scope_hash({'action': 'terminal_start'}),
                'expires': time.monotonic() + 30,
            }
        req = {
            'action': 'terminal_start',
            'session_id': 'x' * 43,
            'privilege_token': token,
        }
        self.assertFalse(agent.consume_privilege_grant(req))


if __name__ == '__main__':
    unittest.main()
