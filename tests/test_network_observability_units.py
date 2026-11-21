import unittest
import dns_bypass_sensor
import network_discovery
import device_intelligence


class NetworkDiscoveryScopeTests(unittest.TestCase):
    def tearDown(self):
        network_discovery.APPROVED_NETWORKS = {}
        network_discovery.NETWORK_LABELS = {}
        network_discovery.NETWORK_GATEWAYS = {}

    def test_scope_accepts_private_network_only(self):
        network_discovery.configure_scope({'ap-test0': '10.77.0.0/24'},
                                           {'ap-test0': 'Test AP'}, {'ap-test0': '10.77.0.1'})
        self.assertEqual(network_discovery.validate_scan_interfaces(['ap-test0']), ['ap-test0'])
        self.assertIsNotNone(network_discovery.fingerprint_scope('10.77.0.22'))
        self.assertIsNone(network_discovery.fingerprint_scope('192.0.2.10'))
        self.assertIsNone(network_discovery.fingerprint_scope('10.77.0.1'))

    def test_public_duplicate_or_invalid_scope_rejected(self):
        for scope in ({'eth0;reboot': '10.77.0.0/24'}, {'ap0': '8.8.8.0/24'},
                      {'ap0': '10.77.0.0/24', 'ap1': '10.77.0.0/24'}):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                network_discovery.configure_scope(scope)
        network_discovery.configure_scope({'ap0': '10.77.0.0/24'})
        self.assertIsNone(network_discovery.validate_scan_interfaces(['eth0']))


class DnsBypassClassificationTests(unittest.TestCase):
    def setUp(self):
        self.base = {'path': 'AP · 5 GHz', 'client_ip': '10.77.0.22',
                     'destination_ip': '8.8.8.8', 'timestamp': 1700000000,
                     'interface': 'ap0'}

    def test_external_dns_is_attempt_not_verdict(self):
        event = dns_bypass_sensor.classify_event({**self.base, 'destination_port': 53,
                        'protocol': 'UDP', 'dns_query': 'example.org'})
        self.assertEqual(event['type'], 'external_dns53_attempt')
        self.assertEqual(event['enforcement_outcome'], 'unknown')
        self.assertFalse(event['packet_payload_saved'])

    def test_configured_upstream_classified_separately(self):
        event = dns_bypass_sensor.classify_event(
            {**self.base, 'destination_ip': '100.64.0.23', 'destination_port': 53,
             'protocol': 'UDP'}, configured_upstreams={'100.64.0.23'})
        self.assertEqual(event['type'], 'configured_upstream_direct_dns_attempt')

    def test_dot_doq_and_doh_are_indicators(self):
        dot = dns_bypass_sensor.classify_event({**self.base, 'destination_port': 853, 'protocol': 'TCP'})
        doq = dns_bypass_sensor.classify_event({**self.base, 'destination_port': 784, 'protocol': 'UDP'})
        doh = dns_bypass_sensor.classify_event({**self.base, 'destination_port': 443, 'protocol': 'TCP',
                                                 'tls_sni': 'cloudflare-dns.com'})
        self.assertEqual(dot['type'], 'dot_attempt')
        self.assertEqual(doq['type'], 'doq_attempt')
        self.assertEqual(doh['type'], 'known_doh_endpoint_sni')
        self.assertEqual(doh['enforcement_outcome'], 'unknown')

    def test_randomized_mac_is_not_oui_attributed(self):
        props = device_intelligence.mac_properties('7e:9a:73:cf:ae:b2')
        self.assertTrue(props['locally_administered'])
        self.assertFalse(props['oui_lookup_allowed'])
        result = device_intelligence.lookup_vendor('7e:9a:73:cf:ae:b2',
                                                    database={'7e9a73': ('Private test', 'MA-L')})
        self.assertFalse(result.get('vendor'))


if __name__ == '__main__':
    unittest.main()
