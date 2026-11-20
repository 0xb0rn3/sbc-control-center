#!/usr/bin/env python3
"""Minimal PAM authentication bridge for fresh sudo-password verification."""
from __future__ import annotations

import ctypes
import ctypes.util
from pathlib import Path

PAM_SUCCESS = 0
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_ERROR_MSG = 3
PAM_TEXT_INFO = 4
PAM_CONV_ERR = 19


class _PamMessage(ctypes.Structure):
    _fields_ = [('msg_style', ctypes.c_int), ('msg', ctypes.c_char_p)]


class _PamResponse(ctypes.Structure):
    _fields_ = [('resp', ctypes.c_void_p), ('resp_retcode', ctypes.c_int)]


_CONV = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(_PamMessage)),
    ctypes.POINTER(ctypes.POINTER(_PamResponse)), ctypes.c_void_p,
)


class _PamConv(ctypes.Structure):
    _fields_ = [('conv', _CONV), ('appdata_ptr', ctypes.c_void_p)]



def pam_stack_uses_rootok(service: str = 'sudo', pam_dir: str | Path = '/etc/pam.d') -> bool:
    """Conservatively detect pam_rootok in a PAM include/substack graph.

    If the stack cannot be read, authentication fails closed. This prevents a
    root-running agent from accepting a PAM success shortcut intended for root.
    """
    if service != 'sudo' or not service.replace('-', '').replace('_', '').isalnum():
        return True
    base = Path(pam_dir)
    visited: set[Path] = set()

    def scan(name: str, depth: int = 0) -> bool:
        if depth > 12 or not name or '/' in name or name in {'.', '..'}:
            return True
        path = base / name
        try:
            resolved = path.resolve(strict=True)
            if resolved in visited:
                return False
            visited.add(resolved)
            lines = resolved.read_text(encoding='utf-8', errors='strict').splitlines()
        except (OSError, UnicodeError):
            return True
        for raw in lines:
            line = raw.split('#', 1)[0].strip()
            if not line:
                continue
            fields = line.split()
            if fields[0] == '@include' and len(fields) >= 2:
                if scan(fields[1], depth + 1):
                    return True
                continue
            if fields[0] not in {'auth', 'account', 'password', 'session'} or len(fields) < 3:
                continue
            if fields[1] in {'include', 'substack'}:
                if scan(fields[2], depth + 1):
                    return True
                continue
            module = fields[2].rsplit('/', 1)[-1]
            if module == 'pam_rootok.so':
                return True
        return False

    return scan(service)


def authenticate(username: str, password: str, service: str = 'sudo') -> bool:
    """Authenticate with the system PAM stack; never invokes a shell or sudo command."""
    if (not isinstance(username, str) or not username or len(username) > 64
            or not username.replace('_', 'a').replace('-', 'a').isalnum()
            or not isinstance(password, str) or not password or len(password.encode('utf-8')) > 512
            or '\x00' in password or service not in {'sudo'}):
        return False
    # A root-owned agent must never authenticate through pam_rootok's root bypass.
    if pam_stack_uses_rootok(service):
        return False
    library = ctypes.util.find_library('pam')
    if not library:
        return False
    try:
        pam = ctypes.CDLL(library)
        libc = ctypes.CDLL(ctypes.util.find_library('c') or None)
        libc.malloc.argtypes = [ctypes.c_size_t]
        libc.malloc.restype = ctypes.c_void_p
        libc.memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        libc.memcpy.restype = ctypes.c_void_p
        libc.memmove.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        libc.memmove.restype = ctypes.c_void_p
        libc.memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
        libc.memset.restype = ctypes.c_void_p
        libc.free.argtypes = [ctypes.c_void_p]
        pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(_PamConv), ctypes.POINTER(ctypes.c_void_p)]
        pam.pam_start.restype = ctypes.c_int
        pam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
        pam.pam_authenticate.restype = ctypes.c_int
        pam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
        pam.pam_acct_mgmt.restype = ctypes.c_int
        pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
        pam.pam_end.restype = ctypes.c_int
    except Exception:
        return False

    # Keep a mutable copy so it can be cleared once PAM has completed.
    secret = bytearray(password.encode('utf-8'))

    @_CONV
    def conversation(count, messages, response_out, _appdata):
        if count < 1 or count > 8:
            return PAM_CONV_ERR
        raw = libc.malloc(ctypes.sizeof(_PamResponse) * count)
        if not raw:
            return PAM_CONV_ERR
        response_array = ctypes.cast(raw, ctypes.POINTER(_PamResponse))
        ctypes.memset(raw, 0, ctypes.sizeof(_PamResponse) * count)
        for index in range(count):
            style = messages[index].contents.msg_style
            if style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                answer = secret if style == PAM_PROMPT_ECHO_OFF else username.encode('utf-8')
                buf = libc.malloc(len(answer) + 1)
                if not buf:
                    for prior in range(index):
                        if response_array[prior].resp:
                            libc.free(response_array[prior].resp)
                    libc.free(raw)
                    return PAM_CONV_ERR
                if style == PAM_PROMPT_ECHO_OFF and secret:
                    ctypes.memmove(buf, ctypes.addressof(ctypes.c_char.from_buffer(secret)), len(secret))
                elif answer:
                    temporary = ctypes.create_string_buffer(answer)
                    ctypes.memmove(buf, ctypes.addressof(temporary), len(answer))
                ctypes.memset(buf + len(answer), 0, 1)
                response_array[index].resp = buf
                response_array[index].resp_retcode = 0
            elif style in (PAM_ERROR_MSG, PAM_TEXT_INFO):
                response_array[index].resp = None
                response_array[index].resp_retcode = 0
            else:
                for prior in range(index):
                    if response_array[prior].resp:
                        libc.free(response_array[prior].resp)
                libc.free(raw)
                return PAM_CONV_ERR
        response_out[0] = response_array
        return PAM_SUCCESS

    conv = _PamConv(conversation, None)
    handle = ctypes.c_void_p()
    status = pam.pam_start(service.encode('ascii'), username.encode('utf-8'), ctypes.byref(conv), ctypes.byref(handle))
    try:
        if status != PAM_SUCCESS or not handle:
            return False
        status = pam.pam_authenticate(handle, 0)
        if status == PAM_SUCCESS:
            status = pam.pam_acct_mgmt(handle, 0)
        return status == PAM_SUCCESS
    except Exception:
        return False
    finally:
        if handle:
            try:
                pam.pam_end(handle, status)
            except Exception:
                pass
        for index in range(len(secret)):
            secret[index] = 0
