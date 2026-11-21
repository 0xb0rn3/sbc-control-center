import tempfile
import unittest
from pathlib import Path
import security_operations as so

class SecurityOperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_feed, self.old_geo = so.FEED_PATH, so.GEOIP_PATH
        so.FEED_PATH = Path(self.temp.name) / "reputation.json"
        so.GEOIP_PATH = Path(self.temp.name) / "missing.mmdb"
        so._geo.cache_clear()

    def tearDown(self):
        so.FEED_PATH, so.GEOIP_PATH = self.old_feed, self.old_geo
        so._geo.cache_clear()
        self.temp.cleanup()

    def test_public_ip_filter(self):
        self.assertTrue(so.is_public_ip("8.8.8.8"))
        self.assertFalse(so.is_public_ip("192.168.1.2"))
        self.assertFalse(so.is_public_ip("127.0.0.1"))
        self.assertFalse(so.is_public_ip("203.0.113.8"))

    def test_live_packet_event_is_normalized(self):
        rows = so.enrich_events([{
            "timestamp": 1795270000.0, "source_ip": "192.168.50.64",
            "destination_ip": "8.8.8.8", "remote_ip": "8.8.8.8",
            "source_port": 53000, "destination_port": 53, "protocol": "UDP",
            "application": "DNS", "dns_query": "example.com",
            "interface": "wlan0", "flow_id": "a" * 24,
        }])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["remote_ip"], "8.8.8.8")
        self.assertEqual(rows[0]["domain"], "example.com")
        self.assertEqual(rows[0]["confidence"], "observed")
        self.assertRegex(rows[0]["event_id"], r"^ev_[a-f0-9]{24}$")

    def test_reputation_match_is_indicator_only(self):
        so.FEED_PATH.write_text('{"cidrs":["8.8.8.0/24"],"domains":[]}', encoding="utf-8")
        rows = so.enrich_events([{"remote_ip":"8.8.8.8","dns_query":"example.com"}])
        self.assertEqual(rows[0]["confidence"], "feed_match")
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["automatic_action"], "none")

    def test_private_and_documentation_addresses_are_not_mapped(self):
        self.assertEqual(so.enrich_events([{"remote_ip":"10.0.0.2"}]), [])
        self.assertEqual(so.enrich_events([{"remote_ip":"203.0.113.8"}]), [])

    def test_evidence_drilldown_whitelists_packet_metadata(self):
        source = {"timestamp": 1795270000.0, "source_ip":"192.168.1.9",
                  "destination_ip":"8.8.8.8","remote_ip":"8.8.8.8",
                  "destination_port":53,"protocol":"UDP","dns_query":"example.org",
                  "raw_payload":"must never be returned"}
        event_id = so.enrich_events([source])[0]["event_id"]
        evidence = so.evidence_for_event(event_id, {"events":[source]})
        self.assertTrue(evidence["ok"])
        self.assertNotIn("raw_payload", evidence["packet_metadata"])
        self.assertFalse(evidence["packet_payload_saved"])

if __name__ == "__main__":
    unittest.main()
