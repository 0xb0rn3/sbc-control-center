import io
import json
import shutil
import tempfile
import unittest
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
        with mock.patch.object(tube, 'video_direct', return_value=None), mock.patch.object(tube, '_ytdlp', return_value=fake):
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

    def test_video_prefers_the_tv_client(self):
        player = {'streamingData': {'hlsManifestUrl': 'https://x/tv/master.m3u8'},
                  'videoDetails': {'title': 'Me at the zoo', 'author': 'jawed', 'channelId': 'UC4QobU6STFB0P71PMvOGN5A',
                                   'lengthSeconds': '19', 'viewCount': '1000'},
                  'captions': {'playerCaptionsTracklistRenderer': {'captionTracks': [
                      {'languageCode': 'en', 'name': {'simpleText': 'English'}, 'kind': 'asr', 'baseUrl': 'https://x/tt?lang=en'},
                      {'languageCode': '../x', 'baseUrl': 'https://x/bad'}]}}}
        ytdlp = mock.Mock(side_effect=AssertionError('yt-dlp must not run when the TV client answers'))
        with mock.patch.object(tube, '_https', return_value=json.dumps(player).encode()), mock.patch.object(tube, '_ytdlp', ytdlp):
            v = tube.video('jNQXAC9IVRw')
        self.assertEqual(v['hls'], 'https://x/tv/master.m3u8')
        self.assertEqual((v['duration'], v['views'], v['channel']), (19, 1000, 'jawed'))
        self.assertEqual(v['subtitles'], [{'lang': 'en', 'name': 'English (auto)', 'auto': True}])   # no private URL leaks
        self.assertEqual(tube._caption_urls['jNQXAC9IVRw'], {('en', True): 'https://x/tt?lang=en'})

    def test_video_falls_back_to_ytdlp_without_tv_hls(self):
        fake = {'title': 't', 'formats': [{'protocol': 'm3u8_native', 'url': 'https://x/v.m3u8', 'manifest_url': 'https://x/master.m3u8'}]}
        with mock.patch.object(tube, '_https', side_effect=OSError('offline')), mock.patch.object(tube, '_ytdlp', return_value=fake):
            self.assertEqual(tube.video('jNQXAC9IVRw')['hls'], 'https://x/master.m3u8')

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


if __name__ == '__main__':
    unittest.main()
