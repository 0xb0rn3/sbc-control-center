#!/usr/bin/env python3
"""Enable or disable TOTP multi-factor authentication for SBC Control Center."""
from __future__ import annotations
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import pwd
import time
from pathlib import Path
from urllib.parse import quote

AUTH = Path('/etc/sbc-control-center/auth.json')
MFA_STATE = Path('/var/lib/sbc-control-center-web/totp-last-step')


def totp_counter(secret: str, code: str, now: float | None = None) -> int | None:
    if len(code) != 6 or not code.isdigit():
        return None
    try:
        padded = secret + ('=' * ((8 - len(secret) % 8) % 8))
        key = base64.b32decode(padded, casefold=True)
    except Exception:
        return None
    count = int((time.time() if now is None else now) // 30)
    for step in (count - 1, count, count + 1):
        if step < 0:
            continue
        digest = hmac.new(key, step.to_bytes(8, 'big'), hashlib.sha1).digest()
        offset = digest[-1] & 15
        number = (int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff) % 1_000_000
        if hmac.compare_digest(f'{number:06d}', code):
            return step
    return None


def save_auth(data: dict) -> None:
    AUTH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix='.auth.', dir=str(AUTH.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, separators=(',', ':'))
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


def save_last_step(step: int) -> None:
    MFA_STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix='.totp-step.', dir=str(MFA_STATE.parent))
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as handle:
            handle.write(str(step) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        try:
            account = pwd.getpwnam('sbc-control-center')
            os.chown(tmp_name, account.pw_uid, account.pw_gid)
        except KeyError:
            pass
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, MFA_STATE)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description='Configure TOTP MFA for SBC Control Center')
    parser.add_argument('--disable', action='store_true', help='disable MFA (requires root console or SSH access)')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root: python3 configure_mfa.py')
    if not AUTH.is_file():
        raise SystemExit('Portal auth file not found. Is SBC Control Center installed?')
    data = json.loads(AUTH.read_text())
    if args.disable:
        if not data.get('totp_secret'):
            print('MFA is already disabled.')
            return 0
        confirm = input('Type DISABLE MFA to remove the second factor: ').strip()
        if confirm != 'DISABLE MFA':
            print('No changes made.')
            return 1
        data.pop('totp_secret', None)
        save_auth(data)
        print('MFA disabled. Password sign-in is now active.')
        return 0
    if data.get('totp_secret'):
        raise SystemExit('MFA is already enabled. Use --disable first if you need to replace the authenticator.')
    secret = base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')
    uri = f'otpauth://totp/{quote("SBC Control Center:admin")}?secret={secret}&issuer={quote("SBC Control Center")}&algorithm=SHA1&digits=6&period=30'
    print('\nAdd a new TOTP account in your authenticator app.')
    print('Account: SBC Control Center (admin)')
    print('Type: time-based, 6 digits, 30-second period')
    print('\nSecret (enter manually):')
    print(secret)
    print('\nProvisioning URI (keep private):')
    print(uri)
    print('\nDo not send or photograph this secret. Keep a secure offline copy for recovery.')
    code = getpass.getpass('\nEnter the current 6-digit code from your authenticator to confirm setup: ').strip()
    accepted_step = totp_counter(secret, code)
    if accepted_step is None:
        print('Code not accepted. MFA was not enabled; check device time and try again.')
        return 1
    save_last_step(accepted_step)
    data['totp_secret'] = secret
    save_auth(data)
    print('\nTOTP MFA enabled successfully.')
    print('Future sign-ins require both your administrator password and a fresh authenticator code.')
    print('The enrollment code has been marked used. Wait for the next 30-second code before signing in.')
    print('Keep SSH/local-console access available. To recover if your authenticator is lost:')
    print('  python3 /opt/sbc-control-center/configure_mfa.py --disable')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
