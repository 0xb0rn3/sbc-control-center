#!/usr/bin/env python3
"""Single-threaded PTY worker. Input on stdin is framed; PTY output goes to stdout."""
from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import select
import signal
import struct
import sys
import termios
import time

DEFAULT_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
child_pid: int | None = None


def stop_child(_signum=None, _frame=None):
    global child_pid
    if child_pid:
        try:
            os.killpg(child_pid, signal.SIGHUP)
        except ProcessLookupError:
            pass


def set_winsize(fd: int, rows: int, cols: int) -> None:
    if not 5 <= rows <= 100 or not 20 <= cols <= 300:
        return
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))


def main() -> int:
    global child_pid
    if len(sys.argv) != 3:
        return 64
    try:
        rows, cols = int(sys.argv[1]), int(sys.argv[2])
    except ValueError:
        return 64
    if not 5 <= rows <= 100 or not 20 <= cols <= 300:
        return 64

    signal.signal(signal.SIGTERM, stop_child)
    signal.signal(signal.SIGINT, stop_child)
    env = {
        'HOME': '/root', 'USER': 'root', 'LOGNAME': 'root', 'SHELL': '/bin/bash',
        'PATH': DEFAULT_PATH, 'TERM': 'xterm-256color', 'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8', 'PS1': '[\\u@\\h \\w]# ', 'HISTFILE': '/dev/null',
    }
    pid, master_fd = os.forkpty()
    if pid == 0:
        try:
            # Ensure an unexpectedly killed worker cannot leave Bash orphaned.
            parent_pid = os.getppid()
            ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0)
            if os.getppid() != parent_pid:
                os._exit(127)
            os.umask(0o022)
            try:
                os.chdir('/root')
            except OSError:
                os.chdir('/')
            # a normal login shell: the system profile, root's bashrc, tab completion
            os.execve('/bin/bash', ['/bin/bash', '--login', '-i'], env)
        except BaseException:
            os._exit(127)
    child_pid = pid
    set_winsize(master_fd, rows, cols)
    os.set_blocking(master_fd, False)
    os.set_blocking(0, False)
    os.set_blocking(1, False)

    inbound = bytearray()
    to_pty = bytearray()
    to_parent = bytearray()
    shell_done = False
    close_requested = False
    exit_status = 0

    try:
        while True:
            readers = [] if len(to_parent) >= 262144 else [master_fd]
            if not close_requested:
                readers.append(0)
            writers = [1] if to_parent else []
            if to_pty:
                writers.append(master_fd)
            readable, writable, _ = select.select(readers, writers, [], 0.20)

            if 0 in readable:
                try:
                    chunk = os.read(0, 16384)
                    if not chunk:
                        close_requested = True
                    else:
                        inbound.extend(chunk)
                        if len(inbound) > 32768:
                            close_requested = True
                            inbound.clear()
                except BlockingIOError:
                    pass
                except OSError as exc:
                    if exc.errno not in (errno.EIO, errno.EBADF):
                        raise
                    close_requested = True

            while len(inbound) >= 5:
                kind = inbound[0:1]
                length = struct.unpack('!I', inbound[1:5])[0]
                if length > 8192:
                    close_requested = True
                    inbound.clear()
                    break
                if len(inbound) < 5 + length:
                    break
                payload = bytes(inbound[5:5 + length])
                del inbound[:5 + length]
                if kind == b'W' and 1 <= length <= 8192:
                    if len(to_pty) + len(payload) > 65536:
                        close_requested = True
                        break
                    to_pty.extend(payload)
                elif kind == b'R' and length == 4:
                    new_rows, new_cols = struct.unpack('!HH', payload)
                    set_winsize(master_fd, new_rows, new_cols)
                elif kind == b'X' and length == 0:
                    close_requested = True
                else:
                    close_requested = True
                    break

            if master_fd in readable:
                try:
                    chunk = os.read(master_fd, 16384)
                    if chunk:
                        to_parent.extend(chunk)
                    else:
                        shell_done = True
                except BlockingIOError:
                    pass
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        shell_done = True
                    elif exc.errno != errno.EBADF:
                        raise

            if master_fd in writable and to_pty:
                try:
                    count = os.write(master_fd, to_pty[:8192])
                    if count:
                        del to_pty[:count]
                except BlockingIOError:
                    pass
                except OSError as exc:
                    if exc.errno in (errno.EIO, errno.EBADF, errno.EPIPE):
                        shell_done = True
                    else:
                        raise

            if 1 in writable and to_parent:
                try:
                    count = os.write(1, to_parent[:16384])
                    if count:
                        del to_parent[:count]
                except BlockingIOError:
                    pass
                except OSError as exc:
                    if exc.errno in (errno.EPIPE, errno.EBADF):
                        close_requested = True
                    else:
                        raise

            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                child_pid = None
                exit_status = os.waitstatus_to_exitcode(status)
                shell_done = True
            if close_requested and child_pid:
                stop_child()
                deadline = time.monotonic() + 0.5
                while time.monotonic() < deadline:
                    waited, status = os.waitpid(pid, os.WNOHANG)
                    if waited:
                        child_pid = None
                        exit_status = os.waitstatus_to_exitcode(status)
                        shell_done = True
                        break
                    time.sleep(0.02)
                if child_pid:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        _, status = os.waitpid(pid, 0)
                        exit_status = os.waitstatus_to_exitcode(status)
                    except ChildProcessError:
                        pass
                    child_pid = None
                    shell_done = True
            if shell_done and not to_parent:
                break
        return exit_status
    finally:
        if child_pid:
            stop_child()
            try:
                os.waitpid(child_pid, 0)
            except ChildProcessError:
                pass
        try:
            os.close(master_fd)
        except OSError:
            pass


if __name__ == '__main__':
    raise SystemExit(main())
