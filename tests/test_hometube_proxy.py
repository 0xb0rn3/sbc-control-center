"""The portal serves HomeTube (an optional service on this board) at /tv by passing it through."""
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import web

PAGE_CSP = "default-src 'self'; script-src 'self'"


class FakeHomeTube(BaseHTTPRequestHandler):
    seen = []
    agents = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        FakeHomeTube.seen.append(self.path)
        FakeHomeTube.agents.append(self.headers.get('User-Agent'))
        body = b'<title>HomeTube</title>' if self.path == '/tv' else b'\x47' * 188 * 4
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if self.path == '/tv' else 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Security-Policy', PAGE_CSP)
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)


class HomeTubeProxyTests(unittest.TestCase):
    def setUp(self):
        FakeHomeTube.seen = []
        FakeHomeTube.agents = []
        web._tube_hits.clear()
        self.ht = ThreadingHTTPServer(('127.0.0.1', 0), FakeHomeTube)
        threading.Thread(target=self.ht.serve_forever, daemon=True).start()
        self.p = mock.patch.object(web, 'HOMETUBE_URL', f'http://127.0.0.1:{self.ht.server_address[1]}')
        self.p.start()
        self.portal = ThreadingHTTPServer(('127.0.0.1', 0), web.Handler)
        threading.Thread(target=self.portal.serve_forever, daemon=True).start()
        self.base = f'http://127.0.0.1:{self.portal.server_address[1]}'

    def tearDown(self):
        self.p.stop()
        for s in (self.portal, self.ht):
            s.shutdown()
            s.server_close()

    def get(self, path, ua=None):
        # the portal answers only to its own address and port (a DNS-rebinding guard)
        req = urllib.request.Request(self.base + path, headers={'Host': f'127.0.0.1:{web.PORT}', **({'User-Agent': ua} if ua else {})})
        return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10)

    def test_page_comes_with_hometubes_own_policy_only(self):
        r = self.get('/tv')
        self.assertEqual(r.read(), b'<title>HomeTube</title>')
        self.assertEqual(r.headers.get_all('Content-Security-Policy'), [PAGE_CSP])   # one policy: two would combine and block the page
        self.assertEqual(FakeHomeTube.seen, ['/tv'])

    def test_the_browser_name_reaches_hometube_and_nothing_odd_does(self):
        self.get('/tv', ua='Mozilla/5.0 (Linux; VIDAA 9.6) Hisense').read()
        self.get('/tv', ua='Mozilla/5.0 \u00e9t\u00e9').read()   # not plain ASCII: not passed on
        self.assertEqual(FakeHomeTube.agents[0], 'Mozilla/5.0 (Linux; VIDAA 9.6) Hisense')
        self.assertTrue(FakeHomeTube.agents[1].startswith('Python-urllib'))

    def test_stream_and_files_pass_through(self):
        self.assertEqual(self.get('/api/tv/hls?u=abc&s=def').read(), b'\x47' * 188 * 4)
        self.get('/assets/hometube/hometube.js?v=123').read()
        self.get('/api/tv/config').read()
        self.assertEqual(FakeHomeTube.seen, ['/api/tv/hls?u=abc&s=def', '/assets/hometube/hometube.js?v=123', '/api/tv/config'])

    def test_status_is_for_the_administrator_and_unknown_paths_stay_closed(self):
        for path in ('/api/tv/status', '/api/tv/diag', '/api/tv/nothing'):
            with self.assertRaises(urllib.error.HTTPError, msg=path):
                self.get(path)
        self.assertEqual(FakeHomeTube.seen, [])

    def test_hometube_down_is_a_clear_answer(self):
        with mock.patch.object(web, 'HOMETUBE_URL', 'http://127.0.0.1:9'):
            with self.assertRaises(urllib.error.HTTPError) as err:
                self.get('/tv')
        self.assertEqual(err.exception.code, 503)


if __name__ == '__main__':
    unittest.main()
