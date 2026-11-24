import unittest
from unittest import mock

import moodboard as mb

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>TV</title>
<item><title>a</title><description>&lt;a href="/pin/1/"&gt;&lt;img src="https://i.pinimg.com/236x/e7/4d/2a/e74d.jpg"&gt;&lt;/a&gt;</description></item>
<item><title>b</title><description>&lt;img src="https://evil.example/x.jpg"&gt;</description></item>
<item><title>c</title><description>&lt;img src="https://i.pinimg.com/236x/e7/4d/2a/e74d.jpg"&gt;</description></item>
</channel></rss>"""


class MoodboardTests(unittest.TestCase):
    def test_pins_are_pinterest_originals_only(self):
        self.assertEqual(mb.pins(RSS), ['https://i.pinimg.com/originals/e7/4d/2a/e74d.jpg'])

    def test_image_types(self):
        self.assertEqual(mb._is_image(b'\xff\xd8\xff\xe0rest'), 'jpg')
        self.assertEqual(mb._is_image(b'\x89PNG\r\n\x1a\nrest'), 'png')
        self.assertIsNone(mb._is_image(b'<html>'))

    def test_no_board_set(self):
        with mock.patch.object(mb, 'SITE', {**mb.SITE, 'moodboard_feed': ''}):
            self.assertFalse(mb.refresh()['ok'])
        with mock.patch.object(mb, 'SITE', {**mb.SITE, 'moodboard_feed': 'https://example.com/a.rss'}):
            self.assertIsNone(mb.feed_url())


if __name__ == '__main__':
    unittest.main()
