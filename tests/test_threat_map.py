import json
import tempfile
import unittest
from pathlib import Path
import threat_intelligence as ti

class ThreatMapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.event_file = self.root / "events.jsonl"
        self.feed_file = self.root / "reputation.json"
        self.geo_file = self.root / "missing-city.mmdb"
        self.old_paths, self.old_feed, self.old_geo = ti.EVENT_PATHS, ti.FEED_PATH, ti.GEOIP_PATH
        ti.EVENT_PATHS = (self.event_file,)
        ti.FEED_PATH = self.feed_file
        ti.GEOIP_PATH = self.geo_file
        ti._geo.cache_clear()
        self.record = {
            "schema": 1, "timestamp": "2026-11-21T14:00:00+00:00",
            "type": "external_dns53_attempt", "confidence": "high",
            "interface": "wlan1",
            "source": {"ip": "192.168.50.64", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "lab-client"},
            "destination": {"ip": "8.8.8.8", "port": 53, "transport": "udp"},
            "evidence": "example.com", "indicators": [],
            "expected_policy": "DNAT should redirect to local resolver",
            "packet_payload_saved": False,
        }
        self.event_file.write_text(json.dumps(self.record, separators=(",", ":"), sort_keys=True)+"\n")

    def tearDown(self):
        ti.EVENT_PATHS, ti.FEED_PATH, ti.GEOIP_PATH = self.old_paths, self.old_feed, self.old_geo
        ti._geo.cache_clear()
        self.tmp.cleanup()

    def test_nested_sensor_schema_is_mapped(self):
        events = ti.collect_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["source_ip"], "192.168.50.64")
        self.assertEqual(event["destination_ip"], "8.8.8.8")
        self.assertEqual(event["destination_port"], 53)
        self.assertEqual(event["protocol"], "udp")
        self.assertRegex(event["event_id"], r"^ev_[a-f0-9]{24}$")

    def test_feed_match_is_indicator_not_block(self):
        self.feed_file.write_text(json.dumps({"cidrs": ["8.8.8.0/24"], "domains": []}))
        event = ti.collect_events()[0]
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["confidence"], "feed_match")

    def test_evidence_drilldown_returns_original_packet_metadata(self):
        event = ti.collect_events()[0]
        evidence = ti.get_event_evidence(event["event_id"])
        self.assertTrue(evidence["ok"])
        self.assertEqual(evidence["packet_metadata"]["destination_port"], 53)
        self.assertFalse(evidence["packet_metadata"]["packet_payload_saved"])
        self.assertEqual(evidence["sensor_record"]["type"], "external_dns53_attempt")

    def test_invalid_or_rotated_event_id_is_not_resolved(self):
        self.assertIsNone(ti.get_event_evidence("../events.jsonl"))
        self.assertIsNone(ti.get_event_evidence("ev_" + "0"*24))

if __name__ == "__main__":
    unittest.main()
