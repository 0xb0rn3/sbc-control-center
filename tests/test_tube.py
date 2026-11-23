import io
import json
import re
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

import tube


class TubeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.p = mock.patch.object(tube, 'STATE', self.tmp)
        self.p.start()
        tube._cache.clear()

    def tearDown(self):
        self.p.stop()
        shutil.rmtree(self.tmp)

    def test_search_keeps_valid_entries(self):
        fake = {'entries': [{'id': 'jNQXAC9IVRw', 'title': 'Me at the zoo', 'channel': 'jawed', 'channel_id': 'UC4QobU6STFB0P71PMvOGN5A', 'duration': 19},
                            {'id': 'bad id', 'title': 'x'}, {'id': 'abcdefghijk', 'channel_id': 'not-a-channel'}]}
        with mock.patch.object(tube, '_ytdlp', return_value=fake):
            items = tube.search('zoo')
        self.assertEqual([i['id'] for i in items], ['jNQXAC9IVRw', 'abcdefghijk'])
        self.assertIsNone(items[1]['channel_id'])
        self.assertEqual(tube.search('   '), [])

    def test_video_picks_the_hls_master(self):
        fake = {'title': 't', 'channel': 'c', 'channel_id': 'UC4QobU6STFB0P71PMvOGN5A', 'duration': 10,
                'formats': [{'protocol': 'https', 'url': 'https://x/a'}, {'protocol': 'm3u8_native', 'url': 'https://x/v.m3u8', 'manifest_url': 'https://x/master.m3u8', 'height': 720}],
                'subtitles': {'de': [{'ext': 'vtt', 'url': 'https://x/de.vtt', 'name': 'German'}]},
                'automatic_captions': {'en': [{'ext': 'vtt', 'url': 'https://x/en.vtt'}], 'fr': [{'ext': 'vtt', 'url': 'https://x/fr.vtt'}]}}
        with mock.patch.object(tube, '_ytdlp', return_value=fake):
            v = tube.video('jNQXAC9IVRw')
        self.assertEqual(v['hls'], 'https://x/master.m3u8')
        self.assertEqual(sorted(s['lang'] for s in v['subtitles']), ['de', 'en'])   # auto captions: English only here
        with self.assertRaises(ValueError):
            tube.video('../etc/passwd')

    def test_lists_and_takeout(self):
        tube.put_item('history', {'id': 'jNQXAC9IVRw', 'title': 'zoo', 'position': 12.5, 'duration': 19})
        tube.put_item('history', {'id': 'jNQXAC9IVRw', 'title': 'zoo', 'position': 15, 'duration': 19})
        self.assertEqual(len(tube.get_list('history')), 1)
        self.assertEqual(tube.get_list('history')[0]['position'], 15.0)
        with self.assertRaises(ValueError):
            tube.put_item('secrets', {'id': 'jNQXAC9IVRw'})
        subs = tube.import_takeout('Channel Id,Channel Url,Channel Title\nUC4QobU6STFB0P71PMvOGN5A,http://www.youtube.com/channel/UC4QobU6STFB0P71PMvOGN5A,jawed\nbad,row,x\n')
        self.assertEqual(subs, [{'id': 'UC4QobU6STFB0P71PMvOGN5A', 'name': 'jawed'}])


    def test_cookies_keep_only_youtube_and_google(self):
        with mock.patch.object(tube, 'COOKIES', self.tmp / 'cookies.txt'):
            text = "\n".join([
                "# Netscape HTTP Cookie File",
                ".youtube.com\tTRUE\t/\tTRUE\t1999999999\tSAPISID\tabc",
                "#HttpOnly_.youtube.com\tTRUE\t/\tTRUE\t1999999999\tLOGIN_INFO\txyz",
                ".bank.example\tTRUE\t/\tTRUE\t1999999999\tsession\tsecret",
            ])
            result = tube.set_cookies(text)
            saved = (self.tmp / 'cookies.txt').read_text()
            self.assertEqual(result['cookies'], 2)
            self.assertNotIn('bank.example', saved)
            self.assertEqual((self.tmp / 'cookies.txt').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                tube.set_cookies(".youtube.com\tTRUE\t/\tTRUE\t1999999999\tPREF\tf6=40000000")
            tube.clear_cookies()
            self.assertFalse((self.tmp / 'cookies.txt').exists())

    def test_timedtext_becomes_webvtt(self):
        xml = b'<?xml version="1.0"?><transcript><text start="0.5" dur="2">Hello &amp;amp; welcome</text>' \
              b'<text start="3661.25" dur="1.5">late\nline</text><text start="x">bad</text><text start="9" dur="1"> </text></transcript>'
        self.assertEqual(tube._timedtext_to_vtt(xml),
                         'WEBVTT\n\n00:00:00.500 --> 00:00:02.500\nHello & welcome\n\n01:01:01.250 --> 01:01:02.750\nlate line\n')
        self.assertEqual(tube._timedtext_to_vtt(b'not xml <'), 'WEBVTT\n')
        srv3 = b'<?xml version="1.0" encoding="utf-8" ?><timedtext format="3"><body>' \
               b'<p t="1500" d="2250"><s>two</s><s> words</s></p><p t="4000">no duration</p></body></timedtext>'
        self.assertEqual(tube._timedtext_to_vtt(srv3),
                         'WEBVTT\n\n00:00:01.500 --> 00:00:03.750\ntwo words\n\n00:00:04.000 --> 00:00:06.000\nno duration\n')

    def test_captions_convert_xml_and_pass_vtt_through(self):
        tube._caption_urls['jNQXAC9IVRw'] = {('en', False): 'https://x/en', ('de', False): 'https://x/de'}
        bodies = {'https://x/en': b'<transcript><text start="1" dur="1">hi</text></transcript>',
                  'https://x/de': b'WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhallo\n'}
        def fake_urlopen(req, timeout=None):
            return io.BytesIO(bodies[req.full_url])
        with mock.patch.object(tube.urllib.request, 'urlopen', fake_urlopen):
            self.assertEqual(tube.captions('jNQXAC9IVRw', 'en', False), 'WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhi\n')
            self.assertTrue(tube.captions('jNQXAC9IVRw', 'de', False).startswith('WEBVTT\n\n00:00:01.000'))

    def test_cached_makes_a_value_once_for_concurrent_requests(self):
        made = []
        def make():
            made.append(1); time.sleep(0.2); return 'v'
        results = []
        threads = [threading.Thread(target=lambda: results.append(tube._cached('k:x', 60, make))) for _ in range(3)]
        [t.start() for t in threads]; [t.join() for t in threads]
        self.assertEqual((len(made), results), (1, ['v', 'v', 'v']))

    def test_warm_looks_up_once_in_the_background_at_low_priority(self):
        calls = []
        def fake_ytdlp(args, timeout=40, nice=0):
            calls.append(nice); time.sleep(0.3)
            return {'title': 't', 'formats': [{'protocol': 'm3u8_native', 'url': 'https://x/v.m3u8', 'manifest_url': 'https://x/m.m3u8'}]}
        with mock.patch.object(tube, '_ytdlp', side_effect=fake_ytdlp):
            self.assertEqual(tube.warm('jNQXAC9IVRw'), 'started')
            for _ in range(50):
                if 'v:jNQXAC9IVRw' in tube._making: break
                time.sleep(0.01)
            self.assertEqual(tube.warm('jNQXAC9IVRw'), 'busy')
            self.assertEqual(tube.video('jNQXAC9IVRw')['hls'], 'https://x/m.m3u8')   # OK pressed meanwhile: waits, no second lookup
            for _ in range(100):
                if not tube._warm_busy: break
                time.sleep(0.01)
            self.assertEqual(tube.warm('jNQXAC9IVRw'), 'ready')
        self.assertEqual(calls, [10])
        with self.assertRaises(ValueError):
            tube.warm('../x')

    def test_related_reads_watch_next_videos_only(self):
        def lockup(vid, kind='LOCKUP_CONTENT_TYPE_VIDEO', title='A title', badge='12:34', channel='Chan'):
            return {'lockupViewModel': {'contentId': vid, 'contentType': kind,
                    'contentImage': {'thumbnailViewModel': {'overlays': [{'thumbnailOverlayBadgeViewModel': {'thumbnailBadges': [{'thumbnailBadgeViewModel': {'text': badge}}]}}]}},
                    'metadata': {'lockupMetadataViewModel': {'title': {'content': title}, 'metadata': {'contentMetadataViewModel': {
                        'metadataRows': [{'metadataParts': [{'text': {'content': channel}}]}, {'metadataParts': [{'text': {'content': '1M'}}]}]}}}}}}
        page = {'contents': {'twoColumnWatchNextResults': {'secondaryResults': {'secondaryResults': {'results': [
            lockup('aaaaaaaaaaa'), lockup('bbbbbbbbbbb', badge='LIVE'), lockup('RDaaaaaaaaaaa', kind='LOCKUP_CONTENT_TYPE_PLAYLIST'),
            lockup('jNQXAC9IVRw'), lockup('bad id'), lockup('aaaaaaaaaaa'), lockup('ccccccccccc', title='')]}}}}}
        with mock.patch.object(tube, '_https', return_value=json.dumps(page).encode()) as call:
            items = tube.related('jNQXAC9IVRw')
            tube.related('jNQXAC9IVRw')
        self.assertEqual(call.call_count, 1)   # cached
        self.assertEqual([i['id'] for i in items], ['aaaaaaaaaaa', 'bbbbbbbbbbb'])
        self.assertEqual((items[0]['duration'], items[0]['channel'], items[0]['live']), (754, 'Chan', False))
        self.assertTrue(items[1]['live'])
        with self.assertRaises(ValueError):
            tube.related('nope')

    def test_playlist_reads_a_mix_as_a_queue(self):
        def entry(vid, title, by, length):
            return {'playlistPanelVideoRenderer': {'videoId': vid, 'title': {'simpleText': title},
                    'shortBylineText': {'runs': [{'text': by}]}, 'lengthText': {'simpleText': length}}}
        page = {'contents': {'twoColumnWatchNextResults': {'playlist': {'playlist': {'title': 'Mix - Zoo', 'contents': [
            entry('jNQXAC9IVRw', 'Me at the zoo', 'jawed', '0:19'), entry('aaaaaaaaaaa', 'Next one', 'Chan', '1:02:03'),
            entry('jNQXAC9IVRw', 'dup', 'x', '0:01'), entry('bad', 'x', 'x', '0:01'), {'automixPreviewVideoRenderer': {}}]}}}}}
        with mock.patch.object(tube, '_https', return_value=json.dumps(page).encode()) as call:
            q = tube.playlist('RDjNQXAC9IVRw')
        sent = json.loads(call.call_args[0][3])
        self.assertEqual((sent['playlistId'], sent['videoId']), ('RDjNQXAC9IVRw', 'jNQXAC9IVRw'))   # a mix starts from its video
        self.assertEqual(q['title'], 'Mix - Zoo')
        self.assertEqual([(i['id'], i['duration'], i['channel']) for i in q['items']], [('jNQXAC9IVRw', 19, 'jawed'), ('aaaaaaaaaaa', 3723, 'Chan')])
        for bad in (('nope', ''), ('PL' + 'x' * 70, ''), ('RDjNQXAC9IVRw', '../x')):
            with self.assertRaises(ValueError):
                tube.playlist(*bad)


MASTER = """#EXTM3U
#EXT-X-INDEPENDENT-SEGMENTS
#EXT-X-STREAM-INF:BANDWIDTH=9000000,CODECS="vp09.00.51.08,mp4a.40.2",RESOLUTION=3840x2160
https://manifest.googlevideo.com/api/manifest/hls_playlist/itag/315/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=4500000,CODECS="avc1.640028,mp4a.40.2",RESOLUTION=1920x1080
https://manifest.googlevideo.com/api/manifest/hls_playlist/itag/96/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=1500000,CODECS="avc1.4d401f,mp4a.40.2",RESOLUTION=1280x720
https://manifest.googlevideo.com/api/manifest/hls_playlist/itag/95/index.m3u8
"""
VARIANT = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:6
#EXT-X-MAP:URI="init.mp4"
#EXTINF:5.0,
https://rr2---sn-abc.googlevideo.com/videoplayback/id/1/sq/0/file/seg.ts
#EXTINF:5.0,
seg1.ts
#EXT-X-ENDLIST
"""


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.p = mock.patch.object(tube, 'STATE', self.tmp)
        self.p.start()
        tube._relay_key = None
        tube._cache.clear()
        tube._seg_cache.clear()
        tube._next_seg.clear()
        tube._seg_bytes = 0

    def tearDown(self):
        self.p.stop()
        tube._relay_key = None
        shutil.rmtree(self.tmp)

    def _target(self, link):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
        return tube.relay_target(q['u'][0], q['s'][0])

    def test_links_round_trip_and_reject_tampering(self):
        url = 'https://rr2---sn-abc.googlevideo.com/videoplayback?id=1&itag=96'
        link = tube.relay_link(url)
        self.assertTrue(link.startswith('/api/tv/hls?u='))
        self.assertEqual(self._target(link), url)
        self.assertEqual((self.tmp / 'relay.key').stat().st_mode & 0o777, 0o600)
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
        with self.assertRaises(ValueError):
            tube.relay_target(q['u'][0], '0' * 32)                       # forged signature
        with self.assertRaises(ValueError):
            self._target(tube.relay_link('https://evil.example/x'))      # signed but not googlevideo
        with self.assertRaises(ValueError):
            self._target(tube.relay_link('http://rr1.googlevideo.com/x'))  # not https
        with self.assertRaises(ValueError):
            tube.relay_target('!!!', 'x')

    def test_master_keeps_h264_only_and_relays_every_address(self):
        out = tube.rewrite_playlist(MASTER, 'https://manifest.googlevideo.com/api/manifest/hls_variant/x', h264_only=True)
        self.assertNotIn('vp09', out)
        self.assertEqual(out.count('#EXT-X-STREAM-INF'), 2)
        self.assertNotIn('googlevideo', out)
        uris = [l for l in out.splitlines() if not l.startswith('#')]
        self.assertEqual([self._target(u).split('/itag/')[1] for u in uris], ['96/index.m3u8', '95/index.m3u8'])
        # without any H.264 variant the master is kept whole rather than emptied
        vp9_only = MASTER.split('#EXT-X-STREAM-INF:BANDWIDTH=4500000')[0]
        self.assertEqual(tube.rewrite_playlist(vp9_only, 'https://manifest.googlevideo.com/', h264_only=True).count('#EXT-X-STREAM-INF'), 1)

    def test_variant_relative_and_attribute_addresses(self):
        base = 'https://rr2---sn-abc.googlevideo.com/videoplayback/id/1/index.m3u8'
        out = tube.rewrite_playlist(VARIANT, base)
        self.assertIn('#EXT-X-ENDLIST', out)
        m = re.search(r'URI="([^"]+)"', out)
        self.assertEqual(self._target(m.group(1)), 'https://rr2---sn-abc.googlevideo.com/videoplayback/id/1/init.mp4')
        segs = [self._target(l) for l in out.splitlines() if not l.startswith('#')]
        self.assertEqual(segs, ['https://rr2---sn-abc.googlevideo.com/videoplayback/id/1/sq/0/file/seg.ts',
                                'https://rr2---sn-abc.googlevideo.com/videoplayback/id/1/seg1.ts'])

    def test_handler_serves_relay_end_to_end(self):
        master_url = 'https://manifest.googlevideo.com/api/manifest/hls_variant/id/1'
        segment = b'\x47' + b'\x00' * 187 * 3
        seg_url = 'https://rr2---sn-abc.googlevideo.com/videoplayback/sq/0/file/seg.ts'
        def fake_get(url, range_header=None):
            if url == master_url:
                return 200, {'Content-Type': 'application/vnd.apple.mpegurl'}, MASTER.encode(), url
            if url == seg_url:
                return 200, {'Content-Type': 'application/octet-stream'}, segment, url
            raise AssertionError(url)
        server = tube.ThreadingHTTPServer(('127.0.0.1', 0), tube.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f'http://127.0.0.1:{server.server_address[1]}'
        get = lambda path: urllib.request.build_opener(urllib.request.ProxyHandler({})).open(base + path, timeout=10)
        try:
            with mock.patch.object(tube, 'video', return_value={'id': 'jNQXAC9IVRw', 'hls': master_url, 'title': 't'}), \
                 mock.patch.object(tube, '_stream_get', side_effect=fake_get):
                v = json.loads(get('/video?id=jNQXAC9IVRw').read())
                self.assertEqual(v['hls'], '/api/tv/stream?id=jNQXAC9IVRw')          # the TV never sees googlevideo
                with get('/stream?id=jNQXAC9IVRw') as r:
                    self.assertEqual(r.headers['Content-Type'], 'application/vnd.apple.mpegurl')
                    body = r.read().decode()
                self.assertNotIn('vp09', body)
                link = tube.relay_link(seg_url)
                with get(link[len('/api/tv'):]) as r:
                    self.assertEqual(r.read(), segment)
                with self.assertRaises(urllib.error.HTTPError) as bad:
                    get('/hls?u=' + link.split('u=')[1].split('&')[0] + '&s=' + '0' * 32)
                self.assertEqual(bad.exception.code, 502)
        finally:
            server.shutdown()
            server.server_close()

    def test_segments_are_fetched_ahead_once(self):
        base = 'https://rr2---sn-abc.googlevideo.com/videoplayback/id/1/'
        playlist = '#EXTM3U\n' + ''.join(f'#EXTINF:5.0,\n{base}sq/{i}/file/seg.ts\n' for i in range(5)) + '#EXT-X-ENDLIST\n'
        calls = []
        lock = threading.Lock()
        def fake_get(url, range_header=None):
            with lock:
                calls.append(url)
            if url.endswith('index.m3u8'):
                return 200, {'Content-Type': 'application/vnd.apple.mpegurl'}, playlist.encode(), url
            return 200, {'Content-Type': 'video/mp2t'}, url.encode(), url
        server = tube.ThreadingHTTPServer(('127.0.0.1', 0), tube.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        get = lambda link: urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            f'http://127.0.0.1:{server.server_address[1]}' + link[len('/api/tv'):], timeout=10).read()
        def settle():
            for _ in range(100):
                with tube._seg_lock:
                    if not tube._inflight:
                        return
                time.sleep(0.02)
        try:
            with mock.patch.object(tube, '_stream_get', side_effect=fake_get):
                text = get(tube.relay_link(base + 'index.m3u8')).decode()
                links = [l for l in text.splitlines() if l.startswith('/api/tv/hls')]
                self.assertEqual(len(links), 5)
                settle()
                self.assertEqual(sorted(calls[1:]), [base + 'sq/0/file/seg.ts', base + 'sq/1/file/seg.ts'])   # started with the playlist
                for i, link in enumerate(links):
                    self.assertEqual(get(link), f'{base}sq/{i}/file/seg.ts'.encode())
                    settle()
                segs = [c for c in calls if c.endswith('seg.ts')]
                self.assertEqual(sorted(segs), sorted(f'{base}sq/{i}/file/seg.ts' for i in range(5)))   # each fetched exactly once
                self.assertEqual(tube._seg_bytes, 0)   # everything fetched ahead was played and freed
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
