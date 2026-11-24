import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sbc_site

ROOT = Path(__file__).resolve().parents[1]


class SiteConfigTests(unittest.TestCase):
    def test_defaults_are_generic(self):
        cfg = sbc_site.load(Path('/nonexistent/config.json'))
        self.assertEqual(cfg, sbc_site.DEFAULTS)
        self.assertEqual(cfg['device_label'], 'SBC Control Center')

    def test_device_values_override_and_invalid_values_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text(json.dumps({
                'device_label': 'Lab router', 'ap_interface': 'wlx001122334455',
                'ap_ip': '10.9.8.1', 'ap_subnet': '10.9.8.0/24', 'ap_ssid': 'Lab',
                'vpn_unit': 'wg-quick@lab',
                # invalid ones fall back to the defaults
                'ap2_interface': 'wlan0; reboot', 'ap2_ip': '999.1.1.1', 'ap2_subnet': '10.0.0.1/24',
                'uplink_interface': '', 'device_label_extra': 'ignored', 'ap2_label': '<script>',
            }))
            cfg = sbc_site.load(path)
        self.assertEqual(cfg['device_label'], 'Lab router')
        self.assertEqual(cfg['ap_interface'], 'wlx001122334455')
        self.assertEqual(cfg['vpn_unit'], 'wg-quick@lab')
        for key in ('ap2_interface', 'ap2_ip', 'ap2_subnet', 'uplink_interface', 'ap2_label'):
            self.assertEqual(cfg[key], sbc_site.DEFAULTS[key], key)
        self.assertNotIn('device_label_extra', cfg)

    def test_public_view_leaves_out_file_paths(self):
        self.assertNotIn('dhcp_lease_file', sbc_site.public_view(dict(sbc_site.DEFAULTS)))

    def test_names_follow_the_environment(self):
        with mock.patch.dict(os.environ, {'SBC_NAME': 'lab-control', 'SBC_PREFIX': 'lab'}):
            self.assertEqual(sbc_site._word('SBC_NAME', 'x'), 'lab-control')
        with mock.patch.dict(os.environ, {'SBC_NAME': '../etc'}):
            self.assertEqual(sbc_site._word('SBC_NAME', 'fallback'), 'fallback')


class PublicTreeTests(unittest.TestCase):
    """The public repository carries no hardware identifiers: they live in the device's config."""

    def files(self):
        for path in ROOT.rglob('*'):
            if path.is_file() and '.git' not in path.parts and path.suffix in {'.py', '.html', '.sh', '.service', '.md', '.json', '.conf', ''}:
                yield path

    def test_no_adapter_mac_interface_names(self):
        for path in self.files():
            text = path.read_text(errors='replace')
            for name in re.findall(r'\bwlx([0-9a-f]{12})\b', text):
                self.assertEqual(name, '001122334455', f'{path.relative_to(ROOT)} names a real adapter (wlx{name})')

    def test_no_real_mac_addresses(self):
        placeholders = {'aa:bb:cc:dd:ee:ff', '00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff', '00:11:22:33:44:55'}
        for path in self.files():
            text = path.read_text(errors='replace').lower()
            for mac in re.findall(r'\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', text):
                self.assertIn(mac, placeholders | {m for m in [mac] if mac.startswith(('02:', '00:00:5e'))},
                              f'{path.relative_to(ROOT)} contains a MAC address ({mac})')


class PageTokenTests(unittest.TestCase):
    def test_every_page_token_is_filled(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('sbc_web_tokens', ROOT / 'web.py')
        web = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(web)
        page = (ROOT / 'index.html').read_bytes()
        for token, value in web.PAGE_TOKENS:
            page = page.replace(token, value)
        self.assertEqual(re.findall(rb'__SBC_[A-Z0-9_]+__', page), [])

    def test_site_json_cannot_close_the_script(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('sbc_web_tokens2', ROOT / 'web.py')
        web = importlib.util.module_from_spec(spec)
        with mock.patch.object(sbc_site, 'load', return_value={**sbc_site.DEFAULTS, 'device_label': 'a</script><b>'}):
            spec.loader.exec_module(web)
        tokens = dict(web.PAGE_TOKENS)
        self.assertNotIn(b'</script>', tokens[b'__SBC_SITE_JSON__'])
        self.assertNotIn(b'<', tokens[b'__SBC_DEVICE_LABEL__'])


if __name__ == '__main__':
    unittest.main()
