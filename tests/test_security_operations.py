import unittest
from security_operations import is_public_ip, enrich_events

class SecurityOperationsTests(unittest.TestCase):
    def test_public_ip(self):
        self.assertTrue(is_public_ip("1.1.1.1"))
        self.assertFalse(is_public_ip("192.168.1.2"))
        self.assertFalse(is_public_ip("127.0.0.1"))

    def test_reputation_match_is_indicator_only(self):
        rows = enrich_events([{"dst_ip":"203.0.113.8","qname":"bad.example"}],
                             ["203.0.113.0/24"], [])
        self.assertEqual(rows[0]["confidence"], "feed_match")
        self.assertEqual(rows[0]["automatic_action"], "none")

    def test_private_addresses_are_not_mapped(self):
        self.assertEqual(enrich_events([{"dst_ip":"10.0.0.2"}]), [])

if __name__ == "__main__":
    unittest.main()
