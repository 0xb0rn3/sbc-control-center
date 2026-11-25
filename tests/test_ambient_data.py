import unittest

import ambient_data


class AmbientReferenceDataTests(unittest.TestCase):
    def test_east_african_weather_cities_are_present(self):
        names = {row["name"] for row in ambient_data.CITIES}
        self.assertTrue({
            "Dar es Salaam", "Arusha", "Mwanza", "Dodoma", "Zanzibar City", "Mbeya",
            "Nairobi", "Mombasa", "Kampala", "Kigali", "Bujumbura", "Addis Ababa",
            "Juba", "Mogadishu",
        }.issubset(names))

    def test_world_clocks_include_east_africa_and_europe(self):
        names = {name for name, _zone in ambient_data.WORLD_CLOCKS}
        self.assertTrue({"Dar es Salaam","Nairobi","Kampala","Kigali","London","Paris","Berlin"}.issubset(names))

    def test_regional_and_european_currency_coverage(self):
        codes = {code for code, _name in ambient_data.CURRENCIES}
        self.assertTrue({"TZS","KES","UGX","RWF","BIF","ETB","SSP","SOS","EUR","GBP","CHF"}.issubset(codes))

    def test_only_technology_publishers_are_configured(self):
        sources = {name for name, _url in ambient_data.NEWS_FEEDS}
        self.assertEqual(sources, {"TechCrunch","The Verge","Ars Technica","BBC Technology"})

    def test_cell_estimate_only_uses_nearby_city_names(self):
        nearby = ambient_data._nearest_city(-2.52, 32.92)
        self.assertEqual(nearby["name"], "Mwanza")
        self.assertIsNone(ambient_data._nearest_city(-20.0, 20.0))


if __name__ == "__main__":
    unittest.main()
