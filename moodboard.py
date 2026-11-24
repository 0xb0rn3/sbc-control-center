"""Pinterest mood board for the living room: the board's public feed, pictures kept on the board.

A public Pinterest board has an RSS feed (https://www.pinterest.com/<user>/<board>.rss) listing
its newest pins. Once a day (and on demand) this reads the feed through the VPN tunnel, fetches
each pin's full-size picture, and keeps it in <state>/moodboard. The feed only lists the newest
pins, so the collection grows as pins are added; nothing is deleted unless the board is
changed. The living room shows these pictures whole over a blurred copy of themselves (pins are
mostly portrait), while the dashboard background keeps the wallpapers.

The feed address is the board's own setting (moodboard_feed in config.json), never in the code.
  python3 moodboard.py refresh
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sbc_site  # noqa: E402

SITE = sbc_site.load()
DIR = sbc_site.STATE_DIR / 'moodboard'
CURL = '/usr/bin/curl'
MAX_IMAGE = 15 * 1024 * 1024
MAX_IMAGES = 500
FEED = re.compile(r'https://(?:[a-z]{2,3}\.)?pinterest\.[a-z.]{2,8}/[A-Za-z0-9_.-]{1,60}/[A-Za-z0-9_.-]{1,100}\.rss')
PIN_IMAGE = re.compile(r'https://i\.pinimg\.com/[0-9a-z]+x?/[0-9a-f/]+\.(?:jpg|jpeg|png|webp)')


def _fetch(url: str, limit: int) -> bytes | None:
    try:
        cp = subprocess.run([CURL, '-fsSL', '--max-time', '40', '--max-filesize', str(limit), *sbc_site.through_vpn(SITE),
                             '-A', 'Mozilla/5.0', url], capture_output=True, timeout=50)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return cp.stdout if cp.returncode == 0 and cp.stdout else None


def feed_url() -> str | None:
    url = SITE.get('moodboard_feed', '')
    return url if FEED.fullmatch(url or '') else None


def pins(raw: bytes) -> list[str]:
    """Picture addresses from the feed, upgraded from the 236-pixel preview to the original."""
    root = ET.fromstring(raw)
    out = []
    for item in root.findall('./channel/item'):
        for url in re.findall(r'src="([^"]+)"', item.findtext('description') or ''):
            if PIN_IMAGE.fullmatch(url):
                out.append(re.sub(r'^(https://i\.pinimg\.com/)[0-9a-z]+x?/', r'\1originals/', url))
    return list(dict.fromkeys(out))


def _is_image(data: bytes) -> str | None:
    if data[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return 'webp'
    return None


def refresh() -> dict[str, Any]:
    url = feed_url()
    if not url:
        return {'ok': False, 'error': 'No Pinterest board is set (moodboard_feed in config.json).'}
    raw = _fetch(url, 2_000_000)
    if raw is None:
        return {'ok': False, 'error': 'The board feed did not answer.'}
    try:
        found = pins(raw)
    except ET.ParseError:
        return {'ok': False, 'error': 'The board feed is not RSS (is the board public?).'}
    DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    added = 0
    for image_url in found:
        name = 'mb-' + hashlib.sha256(image_url.encode()).hexdigest()[:16]
        if any((DIR / f'{name}.{ext}').exists() for ext in ('jpg', 'png', 'webp')):
            continue
        data = None
        for size in ('originals', '1200x', '736x'):
            data = _fetch(re.sub(r'^(https://i\.pinimg\.com/)[0-9a-z]+x?/', rf'\1{size}/', image_url), MAX_IMAGE)
            if data and _is_image(data):
                break
        ext = _is_image(data or b'')
        if not ext:
            continue
        tmp = DIR / f'.{name}'
        with open(tmp, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, DIR / f'{name}.{ext}')
        added += 1
    pictures = sorted(DIR.glob('mb-*'), key=lambda p: p.stat().st_mtime)
    for old in pictures[:-MAX_IMAGES]:
        old.unlink(missing_ok=True)
    state = {'feed': url, 'checked': int(time.time()), 'in_feed': len(found), 'added': added, 'total': min(len(pictures), MAX_IMAGES)}
    (DIR / 'state.json').write_text(json.dumps(state))
    return {'ok': True, **state, 'message': f'{added} new picture(s); {state["total"]} on the mood board.'}


if __name__ == '__main__':
    if (sys.argv[1:] or [''])[0] == 'refresh':
        print(json.dumps(refresh()))
    else:
        raise SystemExit(__doc__)
