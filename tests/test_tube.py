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


if __name__ == '__main__':
    unittest.main()
