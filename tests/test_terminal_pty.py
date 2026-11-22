import contextlib
import io
import time
import unittest

import terminal_pty


class TerminalManagerTests(unittest.TestCase):
    def setUp(self):
        self.manager = terminal_pty.TerminalManager(max_sessions=1, idle_ttl=60, absolute_ttl=120)
        self.owner = 'a' * 43

    def tearDown(self):
        self.manager.close_owner(self.owner, 'test cleanup')

    def test_start_write_and_read_real_pty(self):
        started = self.manager.start(self.owner, actor='unit-test', rows=24, cols=90)
        terminal_id = started['terminal_id']
        self.assertEqual(started['user'], 'root')
        self.manager.write(self.owner, terminal_id, b"printf 'PTY_SESSION_OK\\n'\n")
        output = bytearray()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and b'PTY_SESSION_OK' not in output:
            output.extend(self.manager.read(self.owner, terminal_id)['data'])
            time.sleep(0.03)
        self.assertIn(b'PTY_SESSION_OK', output)

    def test_exited_shell_frees_its_slot(self):
        started = self.manager.start(self.owner)
        self.manager.write(self.owner, started['terminal_id'], b'exit\n')
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                if self.manager.read(self.owner, started['terminal_id']).get('exit_code') is not None:
                    break
            except terminal_pty.TerminalError:
                break
            time.sleep(0.05)
        self.manager.EXITED_GRACE = 0
        time.sleep(0.05)
        self.manager.reap_expired()
        self.manager.reap_expired()
        # the slot is free again: a new shell starts despite max_sessions=1
        self.assertTrue(self.manager.start(self.owner)['terminal_id'])

    def test_terminal_is_bound_to_portal_session(self):
        started = self.manager.start(self.owner)
        with self.assertRaises(terminal_pty.TerminalError):
            self.manager.read('b' * 43, started['terminal_id'])
        self.assertTrue(self.manager.attach(self.owner, started['terminal_id'])['terminal_id'])

    def test_session_and_input_limits(self):
        started = self.manager.start(self.owner)
        with self.assertRaises(terminal_pty.TerminalError):
            self.manager.start(self.owner)
        with self.assertRaises(terminal_pty.TerminalError):
            self.manager.write(self.owner, started['terminal_id'], b'x' * 8193)

    def test_close_owner_removes_terminal(self):
        started = self.manager.start(self.owner)
        self.assertEqual(self.manager.close_owner(self.owner), 1)
        with self.assertRaises(terminal_pty.TerminalError):
            self.manager.read(self.owner, started['terminal_id'])


    def test_lifecycle_audit_does_not_log_terminal_input(self):
        started = self.manager.start(self.owner, actor='unit-test', client_ip='192.0.2.10')
        terminal_id = started['terminal_id']
        secret_command = "printf 'DO_NOT_LOG_THIS_COMMAND'\n"
        self.manager.write(self.owner, terminal_id, secret_command.encode())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            self.manager.read(self.owner, terminal_id)
            time.sleep(0.02)
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            self.manager.close(self.owner, terminal_id, 'closed')
        self.assertIn('[TERMINAL] event=end', log.getvalue())
        self.assertIn('actor=unit-test', log.getvalue())
        self.assertIn('client=192.0.2.10', log.getvalue())
        self.assertNotIn('DO_NOT_LOG_THIS_COMMAND', log.getvalue())

    def test_resize_validation(self):
        started = self.manager.start(self.owner)
        with self.assertRaises(terminal_pty.TerminalError):
            self.manager.resize(self.owner, started['terminal_id'], 2, 100)


if __name__ == '__main__':
    unittest.main()
