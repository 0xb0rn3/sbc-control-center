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

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
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


UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36'
INNERTUBE_CLIENT = {'clientName': 'WEB', 'clientVersion': '2.20251120.01.00', 'hl': 'en', 'gl': 'US'}
_conns: dict[str, http.client.HTTPSConnection] = {}
_conn_locks: dict[str, threading.Lock] = {}


def _https(host: str, method: str, path: str, body: bytes | None = None, headers: dict | None = None, timeout: float = 15) -> bytes:
    """One kept-open HTTPS connection per host: through a far VPN exit each new TLS handshake costs
    several round trips, so reusing the connection is most of the speed."""
    lock = _conn_locks.setdefault(host, threading.Lock())
    with lock:
        for attempt in (1, 2):
            conn = _conns.get(host)
            if conn is None:
                conn = _conns[host] = http.client.HTTPSConnection(host, timeout=timeout)
            try:
                conn.request(method, path, body=body, headers={'User-Agent': UA, **(headers or {})})
                resp = conn.getresponse()
                data = resp.read(4_000_000)
                if resp.status >= 400:
                    raise RuntimeError(f'{host} answered {resp.status}')
                return data
            except (http.client.HTTPException, OSError):
                conn.close()
                _conns.pop(host, None)
                if attempt == 2:
                    raise
    raise RuntimeError('unreachable')


def _walk(node: Any, key: str, out: list, limit: int = 80) -> None:
    if len(out) >= limit:
        return
    if isinstance(node, dict):
        if key in node:
            out.append(node[key])
        for v in node.values():
            _walk(v, key, out, limit)
    elif isinstance(node, list):
        for v in node:
            _walk(v, key, out, limit)


def _text(obj: Any) -> str:
    if not isinstance(obj, dict):
        return ''
    if 'simpleText' in obj:
        return str(obj['simpleText'])
    return ''.join(str(r.get('text', '')) for r in obj.get('runs', []) if isinstance(r, dict))


def _duration_seconds(text: str) -> int | None:
    try:
        parts = [int(p) for p in text.split(':')]
    except ValueError:
        return None
    total = 0
    for p in parts:
        total = total * 60 + p
    return total


def _thumb(video_id: str) -> str:
    return f'https://i.ytimg.com/vi/{video_id}/hqdefault.jpg'


def search_direct(query: str, count: int) -> list[dict[str, Any]]:
    """YouTube's own search endpoint (the same one its web page uses): about a second, versus
    several for a yt-dlp subprocess. Only video results are kept."""
    body = json.dumps({'context': {'client': INNERTUBE_CLIENT}, 'query': query}).encode()
    data = json.loads(_https('www.youtube.com', 'POST', '/youtubei/v1/search?prettyPrint=false',
                             body, {'Content-Type': 'application/json'}))
    found: list = []
    _walk(data, 'videoRenderer', found, limit=count * 2)
    out = []
    for v in found:
        vid = v.get('videoId') or ''
        if not VIDEO_ID.fullmatch(vid):
            continue
        owner = (v.get('ownerText') or v.get('longBylineText') or {}).get('runs') or [{}]
        cid = ((owner[0].get('navigationEndpoint') or {}).get('browseEndpoint') or {}).get('browseId')
        length = _text(v.get('lengthText'))
        out.append({'id': vid, 'title': _text(v.get('title'))[:200],
                    'channel': str(owner[0].get('text') or '')[:80],
                    'channel_id': cid if CHANNEL_ID.fullmatch(str(cid or '')) else None,
                    'duration': _duration_seconds(length) if length else None,
                    'views': _text(v.get('viewCountText'))[:40],
                    'thumb': _thumb(vid)})
        if len(out) >= count:
            break
    return out


def search(query: str, count: int = 24, ttl: float = 600, background: bool = False) -> list[dict[str, Any]]:
    query = query.strip()[:120]
    if not query:
        return []
    def make():
        try:   # YouTube's search endpoint first: about a second
            direct = search_direct(query, count)
            if direct:
                return direct
        except Exception:
            pass   # fall back to yt-dlp, slower but maintained against YouTube's changes
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


# ---- stream relay
# googlevideo sends no CORS headers, so a page served by this board cannot read the playlists or
# segments itself (hls.js then shows a black picture). The portal relays them instead: every address
# handed to the TV is a signed /api/tv/hls link, fetched here through the tunnel (the IP the stream
# is bound to), and nothing else can be fetched through it.
RELAY_PATH = '/api/tv/hls'
RELAY_HOST = re.compile(r'(?:[a-z0-9-]+\.)+googlevideo\.com')
_URI_ATTR = re.compile(r'URI="([^"]+)"')
_relay_key: bytes | None = None


def _key() -> bytes:
    """Signing key for relay links, kept across restarts so a playing video survives one."""
    global _relay_key
    if _relay_key is None:
        path = STATE / 'relay.key'
        try:
            key = path.read_bytes()
        except OSError:
            key = b''
        if len(key) != 32:
            key = secrets.token_bytes(32)
            STATE.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name('.relay.key')
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        _relay_key = key
    return _relay_key


def _sign(url: str) -> str:
    return hmac.new(_key(), url.encode(), hashlib.sha256).hexdigest()[:32]


def relay_link(url: str) -> str:
    token = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    return f'{RELAY_PATH}?u={token}&s={_sign(url)}'


def relay_target(token: str, signature: str) -> str:
    """The stream address behind a relay link, only if this service signed it and it is googlevideo."""
    try:
        url = base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)).decode()
    except (ValueError, UnicodeDecodeError):
        raise ValueError('bad relay link') from None
    if not hmac.compare_digest(_sign(url), signature or ''):
        raise ValueError('bad relay link')
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'https' or not RELAY_HOST.fullmatch(parts.hostname or ''):
        raise ValueError('not a stream address')
    return url


def rewrite_playlist(text: str, base: str, h264_only: bool = False) -> str:
    """Point every address in an HLS playlist at the relay. With h264_only, a master playlist keeps
    only its H.264 variants (when it has any): smart-TV browsers often cannot decode VP9."""
    lines = [line.strip() for line in text.splitlines()]
    keep_avc = h264_only and any(l.startswith('#EXT-X-STREAM-INF') and 'avc1' in l for l in lines)
    out: list[str] = []
    skip_uri = False
    for line in lines:
        if not line:
            continue
        if line.startswith('#'):
            if keep_avc and line.startswith(('#EXT-X-STREAM-INF', '#EXT-X-I-FRAME-STREAM-INF')) and 'avc1' not in line:
                skip_uri = line.startswith('#EXT-X-STREAM-INF')
                continue
            out.append(_URI_ATTR.sub(lambda m: f'URI="{relay_link(urllib.parse.urljoin(base, m.group(1)))}"', line))
        elif skip_uri:
            skip_uri = False
        else:
            out.append(relay_link(urllib.parse.urljoin(base, line)))
    return '\n'.join(out) + '\n'


SEG_CACHE_BYTES = 96_000_000   # about 20 segments at 1080p: what is fetched ahead and not yet played
SEG_CACHE_TTL = 180
PREFETCH_AHEAD = 2             # segments fetched while the TV plays the current one
_REDIRECTS = (301, 302, 303, 307, 308)
_idle: dict[str, list[http.client.HTTPSConnection]] = {}
_idle_lock = threading.Lock()
_seg_cache: dict[str, tuple[float, int, dict[str, str], bytes]] = {}
_seg_bytes = 0
_inflight: dict[str, threading.Event] = {}
_next_seg: dict[str, str] = {}
_seg_lock = threading.Lock()


def _stream_get(url: str, range_header: str | None = None) -> tuple[int, dict[str, str], bytes, str]:
    """GET a googlevideo address over a kept-open connection: through a far tunnel exit a new
    TCP+TLS connection costs about a second, and a warm one also runs about twice as fast.
    Returns status, the headers worth passing on, the body, and the final address."""
    headers = {'User-Agent': UA}
    if range_header and re.fullmatch(r'bytes=\d{0,15}-\d{0,15}', range_header):
        headers['Range'] = range_header
    for _hop in range(4):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != 'https' or not RELAY_HOST.fullmatch(parts.hostname or ''):
            raise ValueError('stream address off googlevideo')
        host, path = parts.hostname, parts.path + ('?' + parts.query if parts.query else '')
        for attempt in (1, 2):
            with _idle_lock:
                pool = _idle.get(host) or []
                conn = pool.pop() if pool else None
            reused = conn is not None
            conn = conn or http.client.HTTPSConnection(host, timeout=30)
            try:
                conn.request('GET', path, headers=headers)
                resp = conn.getresponse()
                if int(resp.getheader('Content-Length') or 0) > 64_000_000:
                    raise ValueError('stream part too large')
                body = resp.read()
                break
            except (http.client.HTTPException, OSError):
                conn.close()
                if not reused or attempt == 2:   # a kept connection may have timed out: one retry on a new one
                    raise
        kept = {name: resp.getheader(name) for name in ('Content-Type', 'Content-Range', 'Accept-Ranges', 'Location') if resp.getheader(name)}
        if resp.will_close:
            conn.close()
        else:
            with _idle_lock:
                pool = _idle.setdefault(host, [])
                if len(pool) < 6:
                    pool.append(conn)
                else:
                    conn.close()
        if resp.status in _REDIRECTS and kept.get('Location'):
            url = urllib.parse.urljoin(url, kept['Location'])
            continue
        kept.pop('Location', None)
        return resp.status, kept, body, url
    raise ValueError('too many redirects')


def _remember_order(urls: list[str]) -> None:
    """A media playlist's segment order, so each request can start fetching the ones after it."""
    with _seg_lock:
        for a, b in zip(urls, urls[1:]):
            _next_seg[a] = b
        while len(_next_seg) > 20000:
            _next_seg.pop(next(iter(_next_seg)))


def _store(url: str, entry: tuple[float, int, dict[str, str], bytes]) -> None:
    global _seg_bytes
    with _seg_lock:
        old = _seg_cache.pop(url, None)
        if old:
            _seg_bytes -= len(old[3])
        _seg_cache[url] = entry
        _seg_bytes += len(entry[3])
        while _seg_bytes > SEG_CACHE_BYTES and _seg_cache:
            _seg_bytes -= len(_seg_cache.pop(next(iter(_seg_cache)))[3])


def _take(url: str) -> tuple[float, int, dict[str, str], bytes] | None:
    global _seg_bytes
    with _seg_lock:
        hit = _seg_cache.pop(url, None)   # each segment is played once: hand it over and free the memory
        if hit:
            _seg_bytes -= len(hit[3])
    return hit if hit and time.time() - hit[0] < SEG_CACHE_TTL else None


def _prefetch(url: str) -> None:
    with _seg_lock:
        if url in _seg_cache or url in _inflight:
            return
        done = _inflight[url] = threading.Event()
    def work():
        try:
            status, headers, body, _final = _stream_get(url)
            if status == 200:
                _store(url, (time.time(), status, headers, body))
        except Exception:
            pass   # the TV's own request will fetch it and report any error
        finally:
            with _seg_lock:
                _inflight.pop(url, None)
            done.set()
    threading.Thread(target=work, daemon=True).start()


def _prefetch_after(url: str, count: int = PREFETCH_AHEAD) -> None:
    with _seg_lock:
        ahead, cur = [], url
        for _ in range(count):
            cur = _next_seg.get(cur)
            if not cur:
                break
            ahead.append(cur)
    for nxt in ahead:
        _prefetch(nxt)


def segment(url: str, range_header: str | None = None) -> tuple[int, dict[str, str], bytes, str]:
    """A segment for the TV: from what was fetched ahead when possible, then start on the next ones."""
    if range_header:
        return _stream_get(url, range_header)
    with _seg_lock:
        waiting = _inflight.get(url)
    if waiting:
        waiting.wait(45)
    hit = _take(url)
    result = (hit[1], hit[2], hit[3], url) if hit else _stream_get(url)
    _prefetch_after(url)
    return result


def stream_master(video_id: str) -> str:
    """The video's HLS master playlist, H.264 only, every address through the relay."""
    master = video(video_id).get('hls')
    if not master:
        raise ValueError('No playable stream for this video.')
    status, _headers, body, final = _stream_get(master)
    if status != 200:
        raise ValueError(f'YouTube answered {status} for the stream list')
    return rewrite_playlist(body.decode('utf-8', 'replace'), final, h264_only=True)


def _is_playlist(headers: dict[str, str], url: str) -> bool:
    ctype = (headers.get('Content-Type') or '').lower()
    return 'mpegurl' in ctype or urllib.parse.urlsplit(url).path.endswith('.m3u8')



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


def _timedtext_to_vtt(xml: bytes) -> str:
    """YouTube timedtext XML -> WebVTT. Both forms become cues: <text start dur> in seconds
    (the classic transcript) and <p t d> in milliseconds (timedtext format 3)."""
    import html
    cues = ['WEBVTT', '']
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return 'WEBVTT\n'
    def ts(s: float) -> str:
        h, s = divmod(s, 3600); m, s = divmod(s, 60)
        return f'{int(h):02d}:{int(m):02d}:{s:06.3f}'
    for t in root.iter():
        if t.tag == 'text':
            start_raw, dur_raw, scale = t.get('start'), t.get('dur'), 1.0
        elif t.tag == 'p':
            start_raw, dur_raw, scale = t.get('t'), t.get('d'), 1000.0
        else:
            continue
        try:
            start = float(start_raw or 0) / scale
            dur = float(dur_raw) / scale if dur_raw else 2.0
        except ValueError:
            continue
        text = html.unescape(''.join(t.itertext())).replace('\n', ' ').strip()
        if not text:
            continue
        cues.append(f'{ts(start)} --> {ts(start + dur)}')
        cues.append(text)
        cues.append('')
    return '\n'.join(cues)


def captions(video_id: str, lang: str, auto: bool) -> str:
    """A subtitle track as WebVTT, fetched through the tunnel (the page cannot reach it directly).
    YouTube serves captions as timedtext XML for TV clients, so we convert to VTT here."""
    if not VIDEO_ID.fullmatch(video_id or '') or not re.fullmatch(r'[A-Za-z0-9_-]{1,20}', lang or ''):
        raise ValueError('bad caption request')
    if video_id not in _caption_urls:
        video(video_id)
    url = _caption_urls.get(video_id, {}).get((lang, auto))
    if not url:
        raise ValueError('no such caption track')
    def make():
        raw = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'}), timeout=20).read(3_000_000)
        if raw.lstrip().startswith(b'WEBVTT'):
            return raw.decode('utf-8', 'replace')
        # timedtext XML: what the caption addresses of the TV player return
        if raw.lstrip().startswith(b'<'):
            return _timedtext_to_vtt(raw)
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

    def send_bytes(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def relay(self, target: str) -> None:
        """A playlist comes back rewritten (a media playlist also starts the first segments on their
        way); a segment comes from what was fetched ahead, or straight from YouTube."""
        if not _is_playlist({}, target) and '/videoplayback' in target:
            status, headers, body, final = segment(target, self.headers.get('Range'))
        else:
            status, headers, body, final = _stream_get(target, self.headers.get('Range'))
        if status == 200 and (_is_playlist(headers, final) or body.lstrip().startswith(b'#EXTM3U')):
            text = body.decode('utf-8', 'replace')
            if '#EXTINF' in text:
                urls = [urllib.parse.urljoin(final, l.strip()) for l in text.splitlines() if l.strip() and not l.startswith('#')]
                _remember_order(urls)
                for first in urls[:PREFETCH_AHEAD]:
                    _prefetch(first)
            self.send_bytes(200, rewrite_playlist(text, final).encode(), 'application/vnd.apple.mpegurl')
            return
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass   # the TV skipped ahead or closed the video

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
                v = video(q.get('id', ''))
                # the TV gets the relay's playlist, never the googlevideo address (which it cannot read)
                relay = f"/api/tv/stream?id={v['id']}" if v.get('hls') else None
                self.reply(200, {'ok': True, **v, 'hls': relay})
            elif url.path == '/stream':
                self.send_bytes(200, stream_master(q.get('id', '')).encode(), 'application/vnd.apple.mpegurl')
            elif url.path == '/hls':
                self.relay(relay_target(q.get('u', ''), q.get('s', '')))
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
