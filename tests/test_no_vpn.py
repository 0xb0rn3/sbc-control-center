"""A VPN is a layer to add, never a requirement: DNS filtering and the fetches that use the tunnel when
there is one keep working on a board without one."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dns_filter
import sbc_site


class SiteTests(unittest.TestCase):
    def test_fetches_go_direct_without_a_tunnel_and_through_it_with_one(self):
        site = dict(sbc_site.DEFAULTS, vpn_interface='wg0')
        with mock.patch.object(Path, 'is_file', return_value=False):
            self.assertFalse(sbc_site.vpn_present(site))
            self.assertEqual(sbc_site.through_vpn(site), [])
        with mock.patch.object(Path, 'is_file', return_value=True):
            self.assertEqual(sbc_site.through_vpn(site), ['--interface', 'wg0'])


class DnsWithoutVpnTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = self.tmp / 'dns-filter.json'
        self.p = mock.patch.object(dns_filter, 'DNS_CONFIG', self.cfg)
        self.p.start()
        self.integration = dict(dns_filter.AP_DEFAULTS)

    def tearDown(self):
        self.p.stop()
        shutil.rmtree(self.tmp)

    def test_no_vpn_asks_encrypted_public_resolvers(self):
        with mock.patch.object(dns_filter, 'vpn_on', return_value=False):
            self.assertEqual(dns_filter.upstream_servers(self.integration), dns_filter.DIRECT_UPSTREAMS)
        self.assertTrue(all(u.startswith('https://') for u in dns_filter.DIRECT_UPSTREAMS))

    def test_a_named_resolver_wins_with_a_vpn(self):
        self.cfg.write_text(json.dumps({'upstream': '100.64.0.23'}))
        with mock.patch.object(dns_filter, 'vpn_on', return_value=True):
            self.assertEqual(dns_filter.upstream_servers(dict(self.integration, upstream='100.64.0.23')), ['100.64.0.23'])

    def test_with_a_vpn_and_none_named_the_providers_own_resolver(self):
        conf = '[Interface]\nPrivateKey = x\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = y\n'
        with mock.patch.object(dns_filter, 'vpn_on', return_value=True), mock.patch.object(Path, 'read_text', return_value=conf):
            self.assertEqual(dns_filter.upstream_servers(self.integration), ['10.2.0.1'])

    def test_the_adguard_config_uses_them(self):
        with mock.patch.object(dns_filter, 'vpn_on', return_value=False):
            out = dns_filter._make_agh_config({'dns': {}}, 'standard', self.integration)
        self.assertEqual(out['dns']['upstream_dns'], dns_filter.DIRECT_UPSTREAMS)

    def test_no_vpn_routing_removes_a_stale_tunnel_rule_and_checks_the_direct_way(self):
        calls = []
        def run(cmd, timeout=10):
            calls.append(cmd)
            if cmd[2] == 'rule' and cmd[3] == 'del':
                return (0, '') if sum(1 for c in calls if c[3] == 'del') == 1 else (2, 'no such rule')
            if cmd[2] == 'route' and cmd[3] == 'get':
                return 0, '9.9.9.9 via 192.168.1.1 dev end0 src 192.168.1.5 uid 997'
            raise AssertionError(cmd)
        fake_pw = mock.Mock(pw_uid=997)
        with mock.patch.object(dns_filter, 'vpn_on', return_value=False), mock.patch.object(dns_filter, '_run', side_effect=run), \
             mock.patch('pwd.getpwnam', return_value=fake_pw):
            dns_filter._ensure_uid_route()
        dels = [c for c in calls if c[3] == 'del']
        self.assertEqual(len(dels), 2)                          # one rule removed, then none left
        self.assertIn('uidrange', dels[0]); self.assertIn('997-997', dels[0])
        self.assertTrue(any(c[3] == 'get' and '9.9.9.9' in c for c in calls))

    def test_no_route_at_all_is_reported_not_hidden(self):
        def run(cmd, timeout=10):
            if cmd[3] == 'del':
                return 2, ''
            return 2, 'RTNETLINK answers: Network is unreachable'
        with mock.patch.object(dns_filter, 'vpn_on', return_value=False), mock.patch.object(dns_filter, '_run', side_effect=run), \
             mock.patch('pwd.getpwnam', return_value=mock.Mock(pw_uid=997)):
            with self.assertRaises(RuntimeError):
                dns_filter._ensure_uid_route()


if __name__ == '__main__':
    unittest.main()
