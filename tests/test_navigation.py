import unittest
from html.parser import HTMLParser
from pathlib import Path


HTML_PATH = Path(__file__).resolve().parents[1] / "index.html"


class PortalParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sections = set()
        self.nav_targets = set()
        self.center_targets = set()
        self.mobile_targets = set()
        self.center_groups = set()
        self.ids = []
        self.in_mobile_nav = False
        self.in_center = False
        self.mobile_more = False
        self.dialog_attrs = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "section" and attrs.get("id"):
            self.sections.add(attrs["id"])
        if tag == "nav" and attrs.get("id") == "mobileNav":
            self.in_mobile_nav = True
        if tag == "dialog" and attrs.get("id") == "navCenterDialog":
            self.dialog_attrs = attrs
            self.in_center = True
        if tag == "section" and attrs.get("class", "").find("nav-center-group") >= 0:
            self.center_groups.add(attrs.get("aria-labelledby", ""))
        if tag == "button" and attrs.get("data-target"):
            target = attrs["data-target"]
            self.nav_targets.add(target)
            if self.in_center and "nav-center-item" in attrs.get("class", ""):
                self.center_targets.add(target)
            if self.in_mobile_nav:
                self.mobile_targets.add(target)
        if tag == "button" and attrs.get("id") == "mobileNavMoreBtn":
            self.mobile_more = attrs.get("aria-haspopup") == "dialog"

    def handle_endtag(self, tag):
        if tag == "nav" and self.in_mobile_nav:
            self.in_mobile_nav = False
        if tag == "dialog" and self.in_center:
            self.in_center = False


class NavigationMarkupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = HTML_PATH.read_text(encoding="utf-8")
        cls.parser = PortalParser()
        cls.parser.feed(cls.source)

    def test_every_navigation_target_is_a_real_section(self):
        missing = self.parser.nav_targets - self.parser.sections
        self.assertEqual(missing, set(), f"Navigation points to missing sections: {missing}")

    def test_navigation_center_covers_all_eleven_sections(self):
        expected = {
            "overview", "telemetry", "network", "storage", "services", "updates",
            "backups", "logs", "terminal", "firewall", "system",
        }
        self.assertEqual(self.parser.center_targets, expected)

    def test_mobile_dock_keeps_four_primary_destinations(self):
        self.assertEqual(
            self.parser.mobile_targets,
            {"overview", "telemetry", "network", "terminal"},
        )
        self.assertTrue(self.parser.mobile_more)

    def test_navigation_center_has_accessible_dialog_metadata(self):
        attrs = self.parser.dialog_attrs or {}
        self.assertEqual(attrs.get("aria-labelledby"), "navCenterTitle")
        self.assertEqual(attrs.get("aria-describedby"), "navCenterDescription")
        self.assertIn('id="navCenterSearch"', self.source)
        self.assertIn('for="navCenterSearch"', self.source)

    def test_keyboard_shortcut_and_focusable_controls_exist(self):
        self.assertIn("event.ctrlKey||event.metaKey", self.source)
        self.assertIn("event.key.toLowerCase()==='k'", self.source)
        self.assertIn("navCenterDialog.showModal()", self.source)
        self.assertIn("navCenterDialog.close()", self.source)


    def test_per_core_cpu_load_is_rendered_from_live_telemetry(self):
        self.assertIn('id="cpuCoreList" class="cpu-core-grid"', self.source)
        self.assertIn("const cores=t.cpu?.cores||[]", self.source)
        self.assertIn("$('cpuCoreCount').textContent=cores.length", self.source)

    def test_thermal_sensor_list_uses_a_dedicated_responsive_grid(self):
        self.assertRegex(self.source, r'id="thermalSensorList" class="thermal-sensors"')
        self.assertIn('.thermal-sensors { display:grid;', self.source)

    def test_live_telemetry_has_resource_and_packet_graphs(self):
        for element_id in ('cpuChart', 'memoryChart', 'networkChart', 'packetChart', 'diskChart', 'temperatureChart',
                           'trafficInterfaceTable', 'thermalSensorList'):
            self.assertIn(f'id="{element_id}"', self.source)
        self.assertIn('function scheduleTelemetryPoll()', self.source)
        self.assertIn('setTimeout(async()=>{await refreshTelemetry();scheduleTelemetryPoll();},1000)', self.source)
        self.assertIn('if(telemetryHistory.length>900)telemetryHistory=telemetryHistory.slice(-900)', self.source)
        self.assertNotIn('setInterval(refreshTelemetry,1500)', self.source)
        self.assertIn('packets per second', self.source.lower())
        self.assertIn('does not capture packet payloads', self.source)

    def test_admin_sensitive_actions_use_step_up_verification(self):
        self.assertIn("'logs','backup_download'", self.source)
        self.assertIn("/api/privilege/authorize", self.source)
        self.assertIn("/api/backups/download", self.source)
        self.assertNotIn('href="/api/backups/${encodeURIComponent(x.name)}"', self.source)

    def test_document_ids_are_unique(self):
        duplicates = sorted({item for item in self.parser.ids if self.parser.ids.count(item) > 1})
        self.assertEqual(duplicates, [])


if __name__ == "__main__":
    unittest.main()
