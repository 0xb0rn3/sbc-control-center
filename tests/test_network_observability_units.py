import unittest
import dns_bypass_sensor
import network_discovery
import device_intelligence
import flow_telemetry


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


class FakeFlowClock:
    def __init__(self):
        self.mono = 10_000_000_000
        self.epoch = 1_700_000_000_000_000_000

    def monotonic_ns(self):
        return self.mono

    def time_ns(self):
        return self.epoch

    def advance(self, seconds):
        delta = int(seconds * 1_000_000_000)
        self.mono += delta
        self.epoch += delta


class FlowRateTrackerTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeFlowClock()
        self.tracker = flow_telemetry.FlowRateTracker(
            samples_per_flow=3,
            monotonic_ns=self.clock.monotonic_ns,
            time_ns=self.clock.time_ns,
        )
        self.metadata = {
            "interface": "ap-test0",
            "client_ip": "10.77.0.22",
            "remote_ip": "93.184.216.34",
            "client_port": 51000,
            "remote_port": 443,
            "protocol": "TCP",
            "application": "TLS",
        }

    def record(self, size, direction):
        return self.tracker.record(
            packet_bytes=size,
            packet_timestamp_ns=self.clock.epoch,
            direction=direction,
            metadata=self.metadata,
        )

    def test_rates_use_actual_monotonic_elapsed_interval(self):
        self.record(1000, "upload")
        self.clock.advance(1.25)
        self.tracker.sample_once()
        flow_id = flow_telemetry.FlowRateTracker.make_flow_id(self.metadata)
        result = self.tracker.series(flow_id)
        sample = result["samples"][-1]
        self.assertAlmostEqual(sample["interval_seconds"], 1.25)
        self.assertAlmostEqual(sample["upload_bytes_per_second"], 800.0)
        self.assertEqual(sample["download_bytes_per_second"], 0.0)
        self.assertEqual(sample["bytes_delta"], 1000)
        self.assertEqual(sample["timestamp_unix_ns_text"], str(self.clock.epoch))

    def test_upload_and_download_are_separately_sampled(self):
        flow_id = self.record(1200, "upload")
        self.clock.advance(1.0)
        self.tracker.sample_once()
        self.record(500, "download")
        self.clock.advance(0.5)
        self.tracker.sample_once()
        sample = self.tracker.series(flow_id)["samples"][-1]
        self.assertAlmostEqual(sample["bytes_per_second"], 1000.0)
        self.assertEqual(sample["upload_bytes_per_second"], 0.0)
        self.assertAlmostEqual(sample["download_bytes_per_second"], 1000.0)
        self.assertEqual(sample["packets_delta"], 1)

    def test_flow_history_is_bounded_and_timestamped(self):
        flow_id = self.record(100, "upload")
        for _ in range(4):
            self.clock.advance(1.0)
            self.tracker.sample_once()
        result = self.tracker.series(flow_id, limit=3)
        self.assertEqual(result["sample_count"], 3)
        self.assertEqual(len(result["samples"]), 3)
        self.assertEqual(
            [x["timestamp_unix_ns"] for x in result["samples"]],
            sorted(x["timestamp_unix_ns"] for x in result["samples"]),
        )

    def test_flow_identity_includes_both_ports(self):
        first = self.tracker.make_flow_id(self.metadata)
        second = self.tracker.make_flow_id({**self.metadata, "client_port": 51001})
        third = self.tracker.make_flow_id({**self.metadata, "remote_port": 8443})
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, third)

    def test_invalid_flow_ids_and_history_limits_are_rejected(self):
        self.assertFalse(self.tracker.series("../etc/passwd")["ok"])
        self.assertFalse(self.tracker.series(flow_telemetry.FlowRateTracker.make_flow_id(self.metadata), limit=0)["ok"])


if __name__ == '__main__':
    unittest.main()
