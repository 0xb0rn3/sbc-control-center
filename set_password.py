#!/usr/bin/env python3
"""Create or replace the local Control Center administrator password."""
from __future__ import annotations
import getpass
import hashlib
import json
import os
import secrets
import tempfile
from pathlib import Path

AUTH = Path('/etc/sbc-control-center/auth.json')
ROUNDS = 600_000
MIN_CHARS = 15
MAX_BYTES = 1024

if os.geteuid() != 0:
    raise SystemExit('Run as root: python3 set_password.py')

existing = {}
if AUTH.exists():
    try:
        existing = json.loads(AUTH.read_text())
    except Exception:
        raise SystemExit('Existing auth file cannot be read; refusing to overwrite it.')

while True:
    first = getpass.getpass(f'New Control Center password (minimum {MIN_CHARS} characters): ')
    if len(first) < MIN_CHARS:
        print(f'Use at least {MIN_CHARS} characters.')
        continue
    if len(first.encode('utf-8')) > MAX_BYTES:
        print(f'Password is too long (maximum {MAX_BYTES} UTF-8 bytes).')
        continue
    second = getpass.getpass('Repeat password: ')
    if first != second:
        print('Passwords do not match. Try again.')
        continue
    break

salt = secrets.token_bytes(32)
digest = hashlib.pbkdf2_hmac('sha256', first.encode('utf-8'), salt, ROUNDS, dklen=32)
result = {'algorithm': 'pbkdf2_sha256', 'iterations': ROUNDS,
          'salt': salt.hex(), 'hash': digest.hex()}
# Password rotation must not silently remove the enrolled second factor.
if existing.get('totp_secret'):
    result['totp_secret'] = existing['totp_secret']
AUTH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
fd, tmp_name = tempfile.mkstemp(prefix='.auth.', dir=str(AUTH.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(result, handle, separators=(',', ':'))
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp_name, 0o640)
    try:
        import grp
        os.chown(tmp_name, 0, grp.getgrnam('sbc-control-center').gr_gid)
    except (ImportError, KeyError, PermissionError):
        pass
    os.replace(tmp_name, AUTH)
finally:
    try:
        os.unlink(tmp_name)
    except FileNotFoundError:
        pass
print('Administrator password saved using PBKDF2-HMAC-SHA256 (600,000 iterations).')
if result.get('totp_secret'):
    print('Existing TOTP MFA enrollment was preserved.')
