import importlib.util, json, tempfile, unittest
from pathlib import Path
p=Path(__file__).parents[1]/'threat_intelligence.py'
spec=importlib.util.spec_from_file_location('ti',p); ti=importlib.util.module_from_spec(spec); spec.loader.exec_module(ti)
class ThreatIntelTests(unittest.TestCase):
 def test_external_ip_filter(self):
  self.assertTrue(ti._external('1.1.1.1')); self.assertFalse(ti._external('192.168.1.1')); self.assertFalse(ti._external('127.0.0.1'))
 def test_invalid_ip_filter(self): self.assertFalse(ti._external('not-an-ip'))
 def test_feed_missing_is_safe(self):
  nets,domains,state=ti._load_feed(); self.assertEqual(state,'feed_not_installed'); self.assertEqual(nets,[]); self.assertEqual(domains,set())
if __name__=='__main__': unittest.main()
