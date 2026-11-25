import unittest

import ambient_location as location


class CellIdentityTests(unittest.TestCase):
    def test_composite_ecgi_from_x17u(self):
        observation = location.observation_from_router({"ECGI": "6400503CE233"})
        self.assertEqual(observation, {
            "mcc": "640", "mnc": "05", "cell": str(int("3CE233", 16)), "radio": "LTE"
        })

    def test_separate_fields(self):
        observation = location.observation_from_router({
            "MCC": "640", "MNC": "05", "CELL_ID": "3CE233", "PCI": "406"
        })
        self.assertEqual(observation["cell"], str(int("3CE233", 16)))

    def test_pci_is_not_used_as_cell_id(self):
        with self.assertRaises(ValueError):
            location.observation_from_router({"MCC": "640", "MNC": "05", "PCI": "406"})

    def test_rejects_invalid_eci(self):
        with self.assertRaises(ValueError):
            location.observation_from_router({"MCC": "640", "MNC": "05", "CELL_ID": "XYZ"})

    def test_numeric_only_router_cell_id_is_still_hex(self):
        observation = location.observation_from_router({
            "MCC": "640", "MNC": "05", "CELL_ID": "123456"
        })
        self.assertEqual(observation["cell"], str(int("123456", 16)))

    def test_tac_is_included_when_router_reports_it(self):
        observation = location.observation_from_router({
            "ECGI": "6400503CE233", "TAC": "0xC123"
        })
        self.assertEqual(observation["area"], str(int("C123", 16)))


class CellLookupTests(unittest.TestCase):
    def setUp(self):
        with location._cache_lock:
            location._cache.clear()

    def observation(self):
        return {"mcc": "640", "mnc": "05", "cell": str(int("3CE233", 16)), "radio": "LTE"}

    def test_single_result_is_estimated_cell_area(self):
        def fetch(url):
            self.assertIn("mcc=640", url)
            self.assertIn("mnc=05", url)
            self.assertIn("radio=LTE", url)
            return {"data": [{"lat": -2.5, "lon": 32.9, "range": 1200, "samples": 12, "radio": "LTE"}]}
        result = location.lookup_cell(self.observation(), fetch)
        self.assertEqual(result["status"], "estimated")
        self.assertEqual(result["location"]["latitude"], -2.5)
        self.assertIn("OpenCelliD", result["attribution"])

    def test_multiple_results_are_not_guessed(self):
        def fetch(_url):
            return {"data": [
                {"lat": -2.5, "lon": 32.9},
                {"lat": -2.6, "lon": 33.0},
            ]}
        result = location.lookup_cell(self.observation(), fetch)
        self.assertEqual(result["status"], "ambiguous")
        self.assertNotIn("location", result)
        self.assertEqual(len(result["candidates"]), 2)

    def test_no_result_is_not_found(self):
        result = location.lookup_cell(self.observation(), lambda _url: {"data": []})
        self.assertEqual(result["status"], "not_found")

    def test_missing_router_identity_is_unavailable(self):
        result = location.resolve_from_router({"PCI": "406"}, lambda _url: {})
        self.assertEqual(result["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
