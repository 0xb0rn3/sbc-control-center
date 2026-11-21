#!/usr/bin/env python3
"""Optional read-only AdGuard Home health and query-log integration."""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

CONFIG_PATH = Path('/etc/sbc-control-center/dns.json')
MAX_RESPONSE = 512 * 1024


def _config() -> dict[str, Any] | None:
    try:
        info = CONFIG_PATH.lstat()
        if CONFIG_PATH.is_symlink() or not CONFIG_PATH.is_file() or info.st_uid != 0 or info.st_mode & 0o077:
            return None
        data = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    base = data.get('url', 'http://127.0.0.1:3000')
    try:
        parsed = urllib.parse.urlsplit(base)
        if (parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', '::1', 'localhost'}
                or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
            return None
        _ = parsed.port or 80
    except ValueError:
        return None
    username, password = data.get('username', ''), data.get('password', '')
    if not isinstance(username, str) or len(username) > 128 or not isinstance(password, str) or len(password) > 512:
        return None
    return {'url': base.rstrip('/'), 'username': username, 'password': password}


def _get(path: str, limit: int = MAX_RESPONSE) -> Any:
    config = _config()
    if not config or not path.startswith('/control/') or '..' in path or len(path) > 256:
        raise RuntimeError('AdGuard Home is not configured safely or the API path is invalid.')
    headers = {'Accept': 'application/json', 'User-Agent': 'SBC-Control-Center'}
    if config['username'] or config['password']:
        token = base64.b64encode(f"{config['username']}:{config['password']}".encode()).decode('ascii')
        headers['Authorization'] = 'Basic ' + token
    request = urllib.request.Request(config['url'] + path, headers=headers, method='GET')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=3) as response:
            payload = response.read(limit + 1)
            if len(payload) > limit:
                raise RuntimeError('AdGuard response exceeded the size limit.')
            return json.loads(payload.decode('utf-8'))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise RuntimeError(f'AdGuard API unavailable: {type(exc).__name__}') from exc


def status() -> dict[str, Any]:
    if not _config():
        return {'ok': True, 'configured': False, 'available': False,
                'message': 'Optional AdGuard Home integration is not configured.'}
    try:
        data = _get('/control/status', 64 * 1024)
        if not isinstance(data, dict):
            raise RuntimeError('Unexpected AdGuard status payload.')
        return {'ok': True, 'configured': True, 'available': True,
                'protection_enabled': bool(data.get('protection_enabled')),
                'running': bool(data.get('running')),
                'version': str(data.get('version') or '')[:64] or None,
                'query_log_available': True}
    except Exception as exc:
        return {'ok': True, 'configured': True, 'available': False, 'error': str(exc)[:240]}


def query_log(limit: int = 50) -> dict[str, Any]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError('Query-log limit must be between 1 and 100.')
    rows = _get('/control/querylog?' + urllib.parse.urlencode({'limit': limit}), MAX_RESPONSE)
    if isinstance(rows, dict):
        rows = rows.get('data', [])
    if not isinstance(rows, list):
        raise RuntimeError('Unexpected AdGuard query-log payload.')
    entries = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        question = row.get('question') if isinstance(row.get('question'), dict) else {}
        entries.append({'domain': str(question.get('name') or row.get('domain') or '')[:253],
                        'client': str(row.get('client') or row.get('client_ip') or '')[:64],
                        'reason': str(row.get('reason') or '')[:64], 'status': str(row.get('status') or '')[:32],
                        'time': str(row.get('time') or '')[:64]})
    return {'ok': True, 'count': len(entries), 'entries': entries}


__all__ = ['status', 'query_log']
