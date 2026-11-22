#!/usr/bin/env python3
"""Bounded PTY sessions for the privileged control agent.

The agent launches a single-threaded worker subprocess for each shell. The
worker owns the PTY and Bash; this threaded agent never forks a shell itself.
No network listener is created and terminal input/output are not persisted.
"""
from __future__ import annotations

import errno
import hashlib
import os
import re
import select
import secrets
import signal
import struct
import subprocess
import sys
import threading
import time
from typing import Any

OWNER_RE = re.compile(r'^[A-Za-z0-9_-]{32,128}$')
TERMINAL_ID_RE = re.compile(r'^[A-Za-z0-9_-]{24,96}$')
WORKER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'terminal_pty_worker.py')
SYSTEMD_RUN = '/usr/bin/systemd-run'
SYSTEMCTL = '/usr/bin/systemctl'


def host_shell_available() -> bool:
    """The shell runs as its own transient systemd service, outside the agent's sandbox.

    The agent is sandboxed (read-only /usr and /etc, no /home, no new privileges), and a shell it
    forked would inherit that, so ordinary administration (apt, passwd, editing /etc) would fail.
    Started by systemd instead, the shell is a full root shell on the host. Reaching it still takes
    the portal login (password plus TOTP or a passkey) and a fresh sudo password for each shell.
    """
    return os.geteuid() == 0 and os.path.exists(SYSTEMD_RUN) and os.path.isdir('/run/systemd/system')


class TerminalError(RuntimeError):
    """A terminal operation failed validation or the PTY is no longer active."""


class TerminalManager:
    """Manage a small number of session-bound root PTYs."""

    def __init__(self, max_sessions: int = 2, idle_ttl: int = 900,
                 absolute_ttl: int = 3600) -> None:
        self.max_sessions = max(1, min(int(max_sessions), 4))
        self.idle_ttl = max(60, min(int(idle_ttl), 3600))
        self.absolute_ttl = max(self.idle_ttl, min(int(absolute_ttl), 7200))
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _valid_owner(owner: Any) -> bool:
        return isinstance(owner, str) and OWNER_RE.fullmatch(owner) is not None

    @staticmethod
    def _valid_terminal_id(terminal_id: Any) -> bool:
        return isinstance(terminal_id, str) and TERMINAL_ID_RE.fullmatch(terminal_id) is not None

    @staticmethod
    def _validate_size(rows: int, cols: int) -> None:
        if isinstance(rows, bool) or not isinstance(rows, int) or not 5 <= rows <= 100:
            raise TerminalError('Terminal rows must be between 5 and 100.')
        if isinstance(cols, bool) or not isinstance(cols, int) or not 20 <= cols <= 300:
            raise TerminalError('Terminal columns must be between 20 and 300.')

    @staticmethod
    def _frame(kind: bytes, payload: bytes = b'') -> bytes:
        if len(kind) != 1 or len(payload) > 8192:
            raise TerminalError('Invalid terminal control frame.')
        return kind + struct.pack('!I', len(payload)) + payload

    @staticmethod
    def _write_pipe(fd: int, data: bytes, timeout: float = 0.5) -> int:
        view = memoryview(data)
        written = 0
        deadline = time.monotonic() + timeout
        while written < len(view):
            try:
                count = os.write(fd, view[written:])
                if count <= 0:
                    break
                written += count
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                    break
            except OSError as exc:
                if exc.errno in (errno.EPIPE, errno.EBADF, errno.EIO):
                    break
                raise
        return written

    def start(self, owner_session: str, actor: str = 'administrator',
              client_ip: str = 'unknown', rows: int = 28, cols: int = 100) -> dict[str, Any]:
        if not self._valid_owner(owner_session):
            raise TerminalError('A valid authenticated portal session is required.')
        self._validate_size(rows, cols)
        with self._lock:
            self._reap_locked(time.monotonic())
            if any(item['owner_session'] == owner_session for item in self._sessions.values()):
                raise TerminalError('This browser session already owns a live terminal. Reconnect to it or close it first.')
            if len(self._sessions) >= self.max_sessions:
                raise TerminalError('The terminal service is at its session limit. Close another terminal first.')
            if not os.path.isfile(WORKER_PATH):
                raise TerminalError('Terminal worker is missing from the Control Center installation.')

            env = {
                'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                'LANG': 'C.UTF-8',
                'LC_ALL': 'C.UTF-8',
                'PYTHONIOENCODING': 'utf-8',
            }
            worker = [sys.executable, '-I', WORKER_PATH, str(rows), str(cols)]
            unit = None
            if host_shell_available():
                unit = f'sbc-terminal-{secrets.token_hex(6)}'
                # --pipe hands this process's pipes straight to the worker; RuntimeMaxSec ends the
                # shell even if the agent itself dies before it can close the session.
                worker = [SYSTEMD_RUN, '--quiet', '--pipe', '--wait', '--collect', f'--unit={unit}',
                          '--description=Control Center root terminal',
                          '-p', f'RuntimeMaxSec={int(self.absolute_ttl) + 60}', '-p', 'KillMode=control-group',
                          *worker]
            try:
                proc = subprocess.Popen(
                    worker,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    bufsize=0,
                    close_fds=True,
                    env=env,
                )
                assert proc.stdin is not None and proc.stdout is not None
                input_fd = proc.stdin.fileno()
                output_fd = proc.stdout.fileno()
                os.set_blocking(input_fd, False)
                os.set_blocking(output_fd, False)
            except Exception as exc:
                try:
                    proc.kill()  # type: ignore[possibly-undefined]
                except Exception:
                    pass
                raise TerminalError('Could not start the isolated terminal worker.') from exc

            terminal_id = secrets.token_urlsafe(24)
            now = time.monotonic()
            self._sessions[terminal_id] = {
                'owner_session': owner_session,
                'proc': proc,
                'input_fd': input_fd,
                'output_fd': output_fd,
                'created': now,
                'last_activity': now,
                'exit_code': None,
                'actor': str(actor)[:64],
                'client_ip': str(client_ip)[:64],
                'closed': False,
                'rows': rows,
                'cols': cols,
                'unit': unit,
            }
            return {
                'terminal_id': terminal_id,
                'user': 'root',
                'rows': rows,
                'cols': cols,
                'idle_timeout_seconds': self.idle_ttl,
                'maximum_lifetime_seconds': self.absolute_ttl,
            }

    def attach(self, owner_session: str, terminal_id: str) -> dict[str, Any]:
        if not self._valid_owner(owner_session) or not self._valid_terminal_id(terminal_id):
            raise TerminalError('Terminal session identifier is invalid.')
        with self._lock:
            self._reap_locked(time.monotonic())
            item = self._sessions.get(terminal_id)
            if not item or item['owner_session'] != owner_session or item['closed']:
                raise TerminalError('That terminal is no longer available to this browser session.')
            return {'terminal_id': terminal_id, 'user': 'root',
                    'rows': item['rows'], 'cols': item['cols']}

    def write(self, owner_session: str, terminal_id: str, data: bytes) -> int:
        if not self._valid_owner(owner_session) or not self._valid_terminal_id(terminal_id):
            raise TerminalError('Terminal session identifier is invalid.')
        if not isinstance(data, bytes) or not data or len(data) > 8192:
            raise TerminalError('Terminal input must contain between 1 and 8192 bytes.')
        with self._lock:
            item = self._owned_locked(owner_session, terminal_id)
            if self._poll_exit_locked(item) is not None:
                raise TerminalError('The shell has exited. Close this terminal and start a new session.')
            frame = self._frame(b'W', data)
            written = self._write_pipe(item['input_fd'], frame)
            if written != len(frame):
                raise TerminalError('The terminal input queue is full. Try sending a smaller paste.')
            item['last_activity'] = time.monotonic()
            return len(data)

    def read(self, owner_session: str, terminal_id: str, max_bytes: int = 8192) -> dict[str, Any]:
        if not self._valid_owner(owner_session) or not self._valid_terminal_id(terminal_id):
            raise TerminalError('Terminal session identifier is invalid.')
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 32768:
            raise TerminalError('Terminal output limit is invalid.')
        with self._lock:
            item = self._owned_locked(owner_session, terminal_id)
            chunks: list[bytes] = []
            total = 0
            fd = item['output_fd']
            while total < max_bytes:
                try:
                    ready, _, _ = select.select([fd], [], [], 0)
                    if not ready:
                        break
                    chunk = os.read(fd, min(4096, max_bytes - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                except BlockingIOError:
                    break
                except OSError as exc:
                    if exc.errno in (errno.EIO, errno.EBADF, errno.EPIPE):
                        break
                    raise
            exit_code = self._poll_exit_locked(item)
            return {'data': b''.join(chunks), 'running': exit_code is None,
                    'exit_code': exit_code, 'idle_timeout_seconds': self.idle_ttl}

    def resize(self, owner_session: str, terminal_id: str, rows: int, cols: int) -> None:
        if not self._valid_owner(owner_session) or not self._valid_terminal_id(terminal_id):
            raise TerminalError('Terminal session identifier is invalid.')
        self._validate_size(rows, cols)
        with self._lock:
            item = self._owned_locked(owner_session, terminal_id)
            frame = self._frame(b'R', struct.pack('!HH', rows, cols))
            if self._write_pipe(item['input_fd'], frame) != len(frame):
                raise TerminalError('Could not resize the terminal.')
            item['rows'] = rows
            item['cols'] = cols
            item['last_activity'] = time.monotonic()

    def close(self, owner_session: str, terminal_id: str, reason: str = 'closed') -> bool:
        if not self._valid_owner(owner_session) or not self._valid_terminal_id(terminal_id):
            return False
        with self._lock:
            item = self._sessions.get(terminal_id)
            if not item or item['owner_session'] != owner_session:
                return False
            self._close_locked(terminal_id, item, reason)
            return True

    def close_owner(self, owner_session: str, reason: str = 'portal session ended') -> int:
        if not self._valid_owner(owner_session):
            return 0
        with self._lock:
            matches = [(key, item) for key, item in self._sessions.items()
                       if item['owner_session'] == owner_session]
            for key, item in matches:
                self._close_locked(key, item, reason)
            return len(matches)

    def reap_expired(self) -> int:
        with self._lock:
            return self._reap_locked(time.monotonic())

    def _owned_locked(self, owner_session: str, terminal_id: str) -> dict[str, Any]:
        self._reap_locked(time.monotonic())
        item = self._sessions.get(terminal_id)
        if not item or item['owner_session'] != owner_session or item['closed']:
            raise TerminalError('That terminal is no longer available to this browser session.')
        return item

    @staticmethod
    def _poll_exit_locked(item: dict[str, Any]) -> int | None:
        if item['exit_code'] is not None:
            return item['exit_code']
        code = item['proc'].poll()
        if code is not None:
            item['exit_code'] = code
        return item['exit_code']

    EXITED_GRACE = 60  # an exited shell stays readable this long, so a reconnecting tab sees its exit code

    def _reap_locked(self, now: float) -> int:
        expired = [
            (key, item, 'idle timeout' if now - item['last_activity'] > self.idle_ttl else 'maximum lifetime')
            for key, item in self._sessions.items()
            if now - item['last_activity'] > self.idle_ttl or now - item['created'] > self.absolute_ttl
        ]
        for key, item in self._sessions.items():
            if key in {k for k, _, _ in expired}:
                continue
            if self._poll_exit_locked(item) is not None:
                item.setdefault('exited_at', now)
                if now - item['exited_at'] > self.EXITED_GRACE:
                    expired.append((key, item, 'shell exited'))
        for key, item, reason in expired:
            self._close_locked(key, item, reason)
        return len(expired)

    def _close_locked(self, terminal_id: str, item: dict[str, Any], reason: str) -> None:
        if item.get('closed'):
            self._sessions.pop(terminal_id, None)
            return
        item['closed'] = True
        proc: subprocess.Popen[bytes] = item['proc']
        try:
            session_tag = hashlib.sha256(item['owner_session'].encode()).hexdigest()[:12]
            terminal_tag = hashlib.sha256(terminal_id.encode()).hexdigest()[:12]
            safe_reason = re.sub(r'[^A-Za-z0-9 _-]', '', str(reason))[:48] or 'closed'
            print(
                f"[TERMINAL] event=end actor={item['actor']} client={item['client_ip']} "
                f"session={session_tag} terminal={terminal_tag} reason={safe_reason}",
                flush=True,
            )
        except Exception:
            # Audit metadata must never prevent an administrator from closing a PTY.
            pass
        try:
            if proc.poll() is None:
                frame = self._frame(b'X')
                self._write_pipe(item['input_fd'], frame, timeout=0.1)
                try:
                    proc.wait(timeout=0.8)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=0.5)
        finally:
            if item.get('unit'):
                try:
                    subprocess.run([SYSTEMCTL, 'stop', '--no-block', item['unit']], timeout=3,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                except Exception:
                    pass
            for stream in (proc.stdin, proc.stdout):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            self._sessions.pop(terminal_id, None)
