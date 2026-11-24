import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import threat_map as tm

CONNTRACK_OUT = """ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.60.16 dst=8.8.4.4 sport=40000 dport=443 src=8.8.4.4 dst=10.66.0.2 sport=443 dport=40000 [ASSURED] mark=0 use=1
ipv4     2 udp      17 25 src=192.168.50.20 dst=9.9.9.9 sport=5000 dport=3478 src=9.9.9.9 dst=10.66.0.2 sport=3478 dport=5000 mark=0 use=1
ipv4     2 udp      17 17 src=192.168.1.161 dst=1.1.1.1 sport=51575 dport=53 src=1.1.1.1 dst=192.168.1.161 sport=53 dport=51575 mark=0 use=1
ipv4     2 tcp      6 10 TIME_WAIT src=192.168.60.16 dst=192.168.60.1 sport=1 dport=8443 src=192.168.60.1 dst=192.168.60.16 sport=8443 dport=1 mark=0 use=1
garbage line
"""


class ThreatMapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.patches = [mock.patch.object(tm, 'FEED_DIR', self.tmp), mock.patch.object(tm, 'locate', return_value=None)]
        for p in self.patches:
            p.start()
        tm._feeds.update({'ips': {}, 'nets': [], 'points': [], 'state': {}})

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp)

    def test_feed_parsers_keep_only_public_ipv4(self):
        d = tm._parse('dshield', json.dumps([{'ip': '8.8.8.8', 'attacks': 3, 'count': 9}, {'ip': '10.0.0.1'}, {'ip': 'nope'}]).encode())
        self.assertEqual([p['ip'] for p in d['points']], ['8.8.8.8'])
        f = tm._parse('feodo', json.dumps([{'ip_address': '1.0.0.1', 'port': 443, 'malware': 'QakBot'}, {'ip_address': '127.0.0.1'}]).encode())
        self.assertEqual([p['ip'] for p in f['points']], ['1.0.0.1'])
        n = tm._parse('drop', b'{"cidr":"1.10.16.0/20"}\n{"cidr":"bad"}\nnot json\n')
        self.assertEqual(n['nets'], ['1.10.16.0/20'])
        b = tm._parse('blocklist_de', b'9.9.9.9\n192.168.1.1\n<script>\n')
        self.assertEqual(b['ips'], ['9.9.9.9'])

    def test_feed_hits_by_address_and_network(self):
        for name, data in (('drop', {'nets': ['203.0.113.0/24']}), ('blocklist_de', {'ips': ['198.51.100.7']})):
            (self.tmp / f'{name}.json').write_text(json.dumps(data))
        tm._load_feeds(force=True)
        self.assertEqual(tm.feed_hits('203.0.113.9'), ['drop'])
        self.assertEqual(tm.feed_hits('198.51.100.7'), ['blocklist_de'])
        self.assertEqual(tm.feed_hits('8.8.8.8'), [])

    def test_connections_only_from_access_points_to_public_addresses(self):
        site = {**tm.SITE, 'ap_subnet': '192.168.50.0/24', 'ap2_subnet': '192.168.60.0/24', 'dhcp_lease_file': str(self.tmp / 'leases')}
        (self.tmp / 'leases').write_text('0 02:00:00:00:00:16 192.168.60.16 tv *\n')
        with mock.patch.object(tm, 'SITE', site), \
             mock.patch('subprocess.run', return_value=mock.Mock(stdout=CONNTRACK_OUT)):
            rows = tm.connections()
        ips = {r['ip']: r for r in rows}
        self.assertEqual(set(ips), {'8.8.4.4', '9.9.9.9'})
        self.assertEqual(ips['8.8.4.4']['clients'], ['tv'])
        self.assertEqual(ips['8.8.4.4']['ports'], [443])
        self.assertNotIn('1.1.1.1', ips)          # the board's own traffic, not an access point
        self.assertNotIn('192.168.60.1', ips)     # private destination

    def test_home_from_time_zone_table(self):
        zone_tab = self.tmp / 'zone.tab'
        zone_tab.write_text('TZ\t-0648+03917\tAfrica/Dar_es_Salaam\n')
        real_path = Path
        with mock.patch.object(tm, 'Path', side_effect=lambda p: zone_tab if str(p).endswith('zone.tab') else real_path(p)):
            lat, lon = tm._zone_coordinates('Africa/Dar_es_Salaam')
        self.assertAlmostEqual(lat, -6.8, places=1)
        self.assertAlmostEqual(lon, 39.283, places=2)

    def test_configured_home_wins(self):
        with mock.patch.object(tm, 'SITE', {**tm.SITE, 'home_location': '-3.37, 36.68'}):
            self.assertEqual(tm.home(), {'lat': -3.37, 'lon': 36.68, 'label': 'Home'})


if __name__ == '__main__':
    unittest.main()
