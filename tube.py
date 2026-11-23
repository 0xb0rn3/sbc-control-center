"""Ad-free YouTube for the TV: search, channels and playback streams, served to the /tv page.

Runs as its own unprivileged account whose traffic the board routes only into the main VPN
tunnel (a uidrange rule to the tunnel's table, which falls back to unreachable): YouTube ties
each stream address to the address that asked for it, and the TV plays through the same
tunnel, so the streams play. No account, no cookies, no ads: the page plays YouTube's own HLS
streams directly. yt-dlp (with deno for YouTube's JavaScript challenges) does the extraction
and is updated daily, because YouTube changes often.

  python3 tube.py serve           # the service (127.0.0.1:8891), started by systemd
  python3 tube.py install-units   # root: account, routing rule, service, daily yt-dlp update
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sbc_site  # noqa: E402

TUBE_DIR = Path('/opt') / f'{sbc_site.PREFIX}-tube'
YTDLP = TUBE_DIR / 'venv' / 'bin' / 'yt-dlp'
DENO = TUBE_DIR / 'deno'
STATE = Path('/var/lib') / f'{sbc_site.PREFIX}-tube'
USER = f'{sbc_site.PREFIX}-tube'
UNIT = f'{sbc_site.PREFIX}-tube'
PORT = 8891
VIDEO_ID = re.compile(r'[A-Za-z0-9_-]{11}')
CHANNEL_ID = re.compile(r'UC[A-Za-z0-9_-]{22}')
_cache: dict[str, tuple[float, Any]] = {}
_lock = threading.Lock()
_slots = threading.BoundedSemaphore(3)   # at most three extractions at once on a small board
_background = threading.BoundedSemaphore(2)   # home-page topic rows use two of them at most: one stays free for you
_caption_urls: dict[str, dict[tuple[str, bool], str]] = {}
COOKIES = STATE / 'cookies.txt'
ACCOUNT_FEEDS = {'subs': ':ytsubs', 'rec': ':ytrec', 'later': ':ytwatchlater', 'history': ':ythistory'}
COOKIE_DOMAINS = ('.youtube.com', 'youtube.com', '.google.com', 'accounts.google.com', '.googleapis.com')
LIST_LIMIT = 300


def _cached(key: str, ttl: float, make):
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
    value = make()
    with _lock:
        _cache[key] = (time.time(), value)
        if len(_cache) > 500:
            for k in sorted(_cache, key=lambda k: _cache[k][0])[:100]:
                _cache.pop(k, None)
    return value


def _ytdlp(args: list[str], timeout: float = 40) -> dict[str, Any]:
    if not _slots.acquire(timeout=20):
        raise RuntimeError('busy: try again in a moment')
    try:
        account = ['--cookies', str(COOKIES)] if COOKIES.exists() else []
        cp = subprocess.run([str(YTDLP), '--no-cache-dir', '--no-warnings', '--js-runtimes', f'deno:{DENO}', *account, '-J', *args],
                            capture_output=True, text=True, timeout=timeout, env={'HOME': str(STATE), 'PATH': '/usr/bin:/bin'})
    finally:
        _slots.release()
    if cp.returncode != 0:
        raise RuntimeError((cp.stderr.strip().splitlines() or ['extraction failed'])[-1][:300])
    return json.loads(cp.stdout)


def _durable_write(path: Path, text: str) -> None:
    """Write, flush to the flash and rename: a power cut leaves the old file or the new one, never an empty one."""
    tmp = path.with_name('.' + path.name)
    with open(tmp, 'w', encoding='utf-8') as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _thumb(video_id: str) -> str:
    return f'https://i.ytimg.com/vi/{video_id}/hqdefault.jpg'


def search(query: str, count: int = 24, ttl: float = 600, background: bool = False) -> list[dict[str, Any]]:
    query = query.strip()[:120]
    if not query:
        return []
    def make():
        if background:
            with _background:
                data = _ytdlp([f'ytsearch{count}:{query}', '--flat-playlist'])
        else:
            data = _ytdlp([f'ytsearch{count}:{query}', '--flat-playlist'])
        out = []
        for e in data.get('entries') or []:
            vid = e.get('id') or ''
            if VIDEO_ID.fullmatch(vid):
                out.append({'id': vid, 'title': str(e.get('title') or '')[:200], 'channel': str(e.get('channel') or e.get('uploader') or '')[:80],
                            'channel_id': e.get('channel_id') if CHANNEL_ID.fullmatch(str(e.get('channel_id') or '')) else None,
                            'duration': e.get('duration'), 'views': e.get('view_count'), 'thumb': _thumb(vid)})
        return out
    return _cached(f's:{query}:{count}', ttl, make)


def video(video_id: str) -> dict[str, Any]:
    if not VIDEO_ID.fullmatch(video_id or ''):
        raise ValueError('not a video id')
    def make():
        d = _ytdlp([f'https://www.youtube.com/watch?v={video_id}'])
        formats = d.get('formats') or []
        hls = [f for f in formats if str(f.get('protocol', '')).startswith('m3u8')]
        master = next((f.get('manifest_url') for f in hls if f.get('manifest_url')), None)
        best = max(hls, key=lambda f: (f.get('height') or 0, f.get('tbr') or 0), default=None)
        subs = []
        for source, auto in ((d.get('subtitles') or {}, False), (d.get('automatic_captions') or {}, True)):
            for lang, tracks in source.items():
                if auto and lang not in ('en', d.get('language') or ''):
                    continue   # automatic captions: English and the video's own language only
                if any(t.get('ext') == 'vtt' for t in tracks) and len(subs) < 40:
                    subs.append({'lang': lang, 'name': (tracks[0].get('name') or lang)[:40] + (' (auto)' if auto else ''), 'auto': auto})
        _caption_urls[video_id] = {(s['lang'], s['auto']): next(t['url'] for t in (d.get('automatic_captions' if s['auto'] else 'subtitles') or {})[s['lang']] if t.get('ext') == 'vtt') for s in subs}
        chapters = [{'start': c.get('start_time'), 'title': str(c.get('title') or '')[:80]} for c in (d.get('chapters') or [])][:100]
        return {'id': video_id, 'title': d.get('title'), 'channel': d.get('channel') or d.get('uploader'),
                'subtitles': subs, 'chapters': chapters, 'views': d.get('view_count'), 'upload_date': d.get('upload_date'),
                'channel_id': d.get('channel_id'), 'duration': d.get('duration'), 'thumb': _thumb(video_id),
                'hls': master or (best or {}).get('url'), 'live': bool(d.get('is_live')),
                'description': str(d.get('description') or '')[:600]}
    # stream addresses stay valid for a few hours; keep them two
    return _cached(f'v:{video_id}', 7200, make)


def channel(channel_id: str) -> list[dict[str, Any]]:
    """A channel's latest videos from its public feed (no API key)."""
    if not CHANNEL_ID.fullmatch(channel_id or ''):
        raise ValueError('not a channel id')
    def make():
        url = f'https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        raw = urllib.request.urlopen(req, timeout=20).read(2_000_000)
        ns = {'a': 'http://www.w3.org/2005/Atom', 'yt': 'http://www.youtube.com/xml/schemas/2015', 'media': 'http://search.yahoo.com/mrss/'}
        root = ET.fromstring(raw)
        name = root.findtext('a:title', default='', namespaces=ns)
        out = []
        for e in root.findall('a:entry', ns)[:15]:
            vid = e.findtext('yt:videoId', default='', namespaces=ns)
            if VIDEO_ID.fullmatch(vid):
                out.append({'id': vid, 'title': e.findtext('a:title', default='', namespaces=ns)[:200], 'channel': name,
                            'channel_id': channel_id, 'published': e.findtext('a:published', default='', namespaces=ns),
                            'thumb': _thumb(vid)})
        return out
    return _cached(f'c:{channel_id}', 900, make)


def captions(video_id: str, lang: str, auto: bool) -> str:
    """A subtitle track as WebVTT, fetched through the tunnel (the page cannot reach it directly)."""
    if not VIDEO_ID.fullmatch(video_id or '') or not re.fullmatch(r'[A-Za-z0-9_-]{1,20}', lang or ''):
        raise ValueError('bad caption request')
    if video_id not in _caption_urls:
        video(video_id)
    url = _caption_urls.get(video_id, {}).get((lang, auto))
    if not url:
        raise ValueError('no such caption track')
    def make():
        raw = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'}), timeout=20).read(3_000_000)
        return raw.decode('utf-8', 'replace')
    return _cached(f'cc:{video_id}:{lang}:{auto}', 7200, make)


def _list_path(name: str) -> Path:
    return STATE / f'{name}.json'


def get_list(name: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(_list_path(name).read_text())
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def put_item(name: str, item: dict[str, Any], remove: bool = False) -> list[dict[str, Any]]:
    """history (newest first, with the position reached) and later (Watch Later)."""
    vid = str(item.get('id', ''))
    if name not in ('history', 'later') or not VIDEO_ID.fullmatch(vid):
        raise ValueError('bad list item')
    items = [i for i in get_list(name) if i.get('id') != vid]
    if not remove:
        clean = {'id': vid, 'title': str(item.get('title') or '')[:200], 'channel': str(item.get('channel') or '')[:80],
                 'channel_id': item.get('channel_id') if CHANNEL_ID.fullmatch(str(item.get('channel_id') or '')) else None,
                 'thumb': _thumb(vid), 'at': int(time.time())}
        for key in ('position', 'duration'):
            if isinstance(item.get(key), (int, float)) and 0 <= item[key] < 10**6:
                clean[key] = round(float(item[key]), 1)
        items.insert(0, clean)
    STATE.mkdir(parents=True, exist_ok=True)
    _durable_write(_list_path(name), json.dumps(items[:LIST_LIMIT]))
    return items[:LIST_LIMIT]


def import_takeout(csv_text: str) -> list[dict[str, str]]:
    """Subscriptions from a Google Takeout subscriptions.csv (Channel Id, Channel Url, Channel Title)."""
    added = 0
    for line in csv_text.splitlines()[1:2000]:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 3 and CHANNEL_ID.fullmatch(parts[0]):
            subscribe(parts[0], ','.join(parts[2:]), True)
            added += 1
    return subscriptions()


def set_cookies(text: str) -> dict[str, Any]:
    """A Netscape cookies.txt exported from a private window: only YouTube and Google cookies are kept."""
    kept = []
    for line in str(text).splitlines()[:5000]:
        fields = line.split('\t')
        if len(fields) == 7 and fields[0].removeprefix('#HttpOnly_').endswith(COOKIE_DOMAINS):
            kept.append(line)
    if not any('youtube.com' in l for l in kept) or not any(l.split('\t')[5] in ('SAPISID', '__Secure-3PAPISID', 'LOGIN_INFO') for l in kept):
        raise ValueError('These are not signed-in YouTube cookies (export them from youtube.com while signed in).')
    STATE.mkdir(parents=True, exist_ok=True)
    _durable_write(COOKIES, '# Netscape HTTP Cookie File\n' + '\n'.join(kept) + '\n')
    os.chmod(COOKIES, 0o600)
    _cache.clear()
    return {'connected': True, 'cookies': len(kept)}


def clear_cookies() -> dict[str, Any]:
    COOKIES.unlink(missing_ok=True)
    _cache.clear()
    return {'connected': False}


def account_feed(name: str, count: int = 40) -> list[dict[str, Any]]:
    if name not in ACCOUNT_FEEDS:
        raise ValueError('unknown feed')
    if not COOKIES.exists():
        raise ValueError('No YouTube account is connected.')
    def make():
        data = _ytdlp([ACCOUNT_FEEDS[name], '--flat-playlist', '-I', f'1:{count}'], timeout=90)
        out = []
        for e in data.get('entries') or []:
            vid = e.get('id') or ''
            if VIDEO_ID.fullmatch(vid):
                out.append({'id': vid, 'title': str(e.get('title') or '')[:200], 'channel': str(e.get('channel') or e.get('uploader') or '')[:80],
                            'channel_id': e.get('channel_id') if CHANNEL_ID.fullmatch(str(e.get('channel_id') or '')) else None,
                            'duration': e.get('duration'), 'thumb': _thumb(vid)})
        return out
    return _cached(f'a:{name}', 900, make)


def subscriptions() -> list[dict[str, str]]:
    try:
        data = json.loads((STATE / 'channels.json').read_text())
        return [c for c in data if isinstance(c, dict) and CHANNEL_ID.fullmatch(str(c.get('id', '')))][:100]
    except (OSError, ValueError):
        return []


def subscribe(channel_id: str, name: str, add: bool) -> list[dict[str, str]]:
    if not CHANNEL_ID.fullmatch(channel_id or ''):
        raise ValueError('not a channel id')
    subs = [c for c in subscriptions() if c['id'] != channel_id]
    if add:
        subs.append({'id': channel_id, 'name': str(name)[:80]})
    STATE.mkdir(parents=True, exist_ok=True)
    _durable_write(STATE / 'channels.json', json.dumps(subs))
    return subs


def home() -> list[dict[str, Any]]:
    """The newest videos across subscribed channels."""
    items = []
    for c in subscriptions()[:30]:
        try:
            items += channel(c['id'])[:6]
        except Exception:
            continue
    items.sort(key=lambda v: v.get('published', ''), reverse=True)
    return items[:48]


class Handler(BaseHTTPRequestHandler):
    server_version = 'tube'

    def log_message(self, fmt, *args):  # quiet: no viewing history in the journal
        pass

    def reply(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        url = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        try:
            if url.path == '/search':
                # the home page's topic rows change slowly: keep them an hour
                self.reply(200, {'ok': True, 'items': search(q.get('q', ''), ttl=3600 if q.get('topic') == '1' else 600, background=q.get('topic') == '1')})
            elif url.path == '/diag':
                self.reply(200, {'ok': True, 'reports': get_list('diag')})
            elif url.path == '/video':
                self.reply(200, {'ok': True, **video(q.get('id', ''))})
            elif url.path == '/channel':
                self.reply(200, {'ok': True, 'items': channel(q.get('id', ''))})
            elif url.path == '/home':
                self.reply(200, {'ok': True, 'items': home(), 'subscriptions': subscriptions()})
            elif url.path in ('/history', '/later'):
                self.reply(200, {'ok': True, 'items': get_list(url.path[1:])})
            elif url.path == '/account':
                self.reply(200, {'ok': True, 'connected': COOKIES.exists()})
            elif url.path == '/feed':
                self.reply(200, {'ok': True, 'items': account_feed(q.get('name', ''))})
            elif url.path == '/captions':
                body = captions(q.get('id', ''), q.get('lang', ''), q.get('auto') == '1').encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/vtt; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.reply(404, {'ok': False, 'error': 'not found'})
        except Exception as exc:
            self.reply(502, {'ok': False, 'error': str(exc)[:300]})

    def do_POST(self) -> None:
        url = urllib.parse.urlparse(self.path)
        try:
            length = min(int(self.headers.get('Content-Length', '0')), 256_000)
            data = json.loads(self.rfile.read(length) or b'{}')
            if url.path == '/subscribe':
                self.reply(200, {'ok': True, 'subscriptions': subscribe(data.get('id', ''), data.get('name', ''), bool(data.get('add', True)))})
            elif url.path in ('/history', '/later'):
                self.reply(200, {'ok': True, 'items': put_item(url.path[1:], data.get('item') or {}, bool(data.get('remove')))})
            elif url.path == '/cookies':
                self.reply(200, {'ok': True, **(clear_cookies() if data.get('clear') else set_cookies(data.get('text', '')))})
            elif url.path == '/diag':
                # what a TV's browser can do (function names, screen, codecs): kept for diagnosis, last 5
                clean = {k: data.get(k) for k in ('ua', 'w', 'h', 'dpr', 'sw', 'sh', 'names', 'mse', 'hlsNative', 'hlsjs', 'sw_api', 'codecs')}
                clean['at'] = int(time.time())
                items = [clean] + get_list('diag')[:4]
                _durable_write(_list_path('diag'), json.dumps(items)[:60000])
                self.reply(200, {'ok': True})
            elif url.path == '/takeout':
                self.reply(200, {'ok': True, 'subscriptions': import_takeout(str(data.get('csv', ''))[:200_000])})
            else:
                self.reply(404, {'ok': False, 'error': 'not found'})
        except Exception as exc:
            self.reply(400, {'ok': False, 'error': str(exc)[:300]})


def serve() -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()


def install_units() -> None:
    if os.geteuid() != 0:
        raise SystemExit('run as root')
    subprocess.run(['sh', '-c', f'getent passwd {USER} >/dev/null || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin {USER}'], check=True)
    uid = int(subprocess.run(['id', '-u', USER], capture_output=True, text=True, check=True).stdout)
    # the service account cannot read the Control Center's folder: it runs from its own copy
    here = Path(os.path.dirname(os.path.abspath(__file__)))
    for name in ('tube.py', 'sbc_site.py'):
        subprocess.run(['install', '-o', 'root', '-g', 'root', '-m', '0644', str(here / name), str(TUBE_DIR / name)], check=True)
    cfg = sbc_site.ETC_DIR / 'config.json'
    if cfg.exists():   # the board's settings, for the copy (readable by the service, no secrets in it)
        subprocess.run(['install', '-d', '-m', '0755', str(Path('/etc') / f'{sbc_site.PREFIX}-tube')], check=True)
        subprocess.run(['install', '-o', 'root', '-g', 'root', '-m', '0644', str(cfg), str(Path('/etc') / f'{sbc_site.PREFIX}-tube' / 'config.json')], check=True)
    table = 200
    service = f"""[Unit]
Description=Ad-free YouTube for the TV (search and streams through the VPN tunnel)
After=network-online.target {sbc_site.load()['vpn_unit']}.service
Wants=network-online.target

[Service]
User={USER}
Group={USER}
# the account's traffic may only use the tunnel's table (which falls back to unreachable)
ExecStartPre=+/bin/sh -c 'ip -4 rule show | grep -q "uidrange {uid}-{uid} lookup {table}" || ip -4 rule add pref 91 uidrange {uid}-{uid} lookup {table}'
ExecStart={TUBE_DIR}/venv/bin/python -I {TUBE_DIR}/tube.py serve
StateDirectory={USER}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=768M
Nice=5

[Install]
WantedBy=multi-user.target
"""
    update = f"""[Unit]
Description=Update yt-dlp for the TV YouTube service

[Service]
Type=oneshot
ExecStart={TUBE_DIR}/venv/bin/pip install --quiet --upgrade "yt-dlp[default]"
ExecStartPost=-/usr/bin/systemctl try-restart {UNIT}.service
Nice=15
"""
    timer = """[Unit]
Description=Daily yt-dlp update

[Timer]
OnCalendar=*-*-* 05:10
RandomizedDelaySec=40min
Persistent=true

[Install]
WantedBy=timers.target
"""
    Path(f'/etc/systemd/system/{UNIT}.service').write_text(service)
    Path(f'/etc/systemd/system/{UNIT}-update.service').write_text(update)
    Path(f'/etc/systemd/system/{UNIT}-update.timer').write_text(timer)
    os.sync()
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', f'{UNIT}.service', f'{UNIT}-update.timer'], check=True)
    print(f'{UNIT} on 127.0.0.1:{PORT}, traffic only through table {table}')


if __name__ == '__main__':
    command = (sys.argv[1:] or [''])[0]
    if command == 'serve':
        serve()
    elif command == 'install-units':
        install_units()
    else:
        raise SystemExit(__doc__)
