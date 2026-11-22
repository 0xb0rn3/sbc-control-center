import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_web():
    spec = importlib.util.spec_from_file_location('sbc_web_static', ROOT / 'web.py')
    web = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(web)
    return web


class StaticAssetTests(unittest.TestCase):
    def setUp(self):
        self.web = load_web()
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        for folder in ('vendor', 'ui', 'wallpapers'):
            (base / folder).mkdir()
        (base / 'ui' / 'slideshow.js').write_text('ok')
        (base / 'wallpapers' / 'w-abc.jpg').write_bytes(b'\xff\xd8jpeg')
        (base / 'wallpapers' / 'README.txt').write_text('x')
        (base / 'wallpapers' / '.hidden.jpg').write_bytes(b'x')
        (base / 'secret.json').write_text('{}')
        os.symlink(base / 'secret.json', base / 'ui' / 'link.json')
        self.patch = mock.patch.object(self.web, 'ASSETS_DIR', base)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_serves_only_known_folders_and_types(self):
        self.assertEqual(self.web.read_static_asset('/assets/ui/slideshow.js')[1], 'text/javascript; charset=utf-8')
        self.assertIsNotNone(self.web.read_static_asset('/assets/wallpapers/w-abc.jpg'))
        for bad in ('/assets/ui/../secret.json', '/assets/secret.json', '/assets/wallpapers/README.txt',
                    '/assets/ui/link.json', '/assets/other/slideshow.js', '/assets/ui/.hidden.js'):
            self.assertIsNone(self.web.read_static_asset(bad), bad)

    def test_wallpaper_index_lists_pictures_only(self):
        self.assertEqual(json.loads(self.web.wallpaper_index()), {'images': ['w-abc.jpg']})

    def test_standby_page_has_no_inline_script(self):
        page = (ROOT / 'standby.html').read_text()
        self.assertNotIn('<script>', page)
        self.assertIn('/assets/ui/slideshow.js', page)


if __name__ == '__main__':
    unittest.main()
