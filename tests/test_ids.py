import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import ids


class IdsTests(unittest.TestCase):
    def test_dropin_watches_both_access_points_only(self):
        cfg = {**ids.SITE, 'ap_interface': 'wlan1', 'ap2_interface': 'wlan0', 'ap_subnet': '192.168.50.0/24', 'ap2_subnet': '192.168.60.0/24'}
        text = ids.dropin_text(cfg)
        self.assertIn('-i wlan1 -i wlan0', text)
        self.assertIn('HOME_NET=[192.168.50.0/24,192.168.60.0/24]', text)
        self.assertIn('ExecStart=\nExecStart=/usr/bin/suricata', text)   # replaces Debian's eth0 default

    def test_alerts_from_eve(self):
        now = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime())
        old = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - 3 * 86400))
        lines = [
            {'timestamp': now + '.000000+0300', 'event_type': 'alert', 'src_ip': '192.168.60.16', 'dest_ip': '8.8.4.4',
             'dest_port': 80, 'proto': 'TCP', 'alert': {'signature': 'ET POLICY test', 'category': 'Policy', 'severity': 2, 'signature_id': 1}},
            {'timestamp': now + '.000000+0300', 'event_type': 'flow', 'src_ip': '192.168.60.16'},
            {'timestamp': old + '.000000+0300', 'event_type': 'alert', 'alert': {'signature': 'too old'}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            eve = Path(tmp) / 'eve.json'
            eve.write_text('\n'.join(json.dumps(l) for l in lines) + '\nnot json\n')
            with mock.patch.object(ids, 'EVE', eve):
                found = ids.alerts()
        self.assertEqual([a['signature'] for a in found], ['ET POLICY test'])
        self.assertEqual(found[0]['dest_ip'], '8.8.4.4')


if __name__ == '__main__':
    unittest.main()
