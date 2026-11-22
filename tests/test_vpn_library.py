import io
import json
import shutil
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import vpn_library as vl

KEY_A = 'cGVlcmtleWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE='
KEY_B = 'cGVlcmtleWJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI='
PRIV = 'YHB2cml2YXRla2V5MDAwMDAwMDAwMDAwMDAwMDAwMDA='
LIVE = f"""[Interface]
PostUp = ip route replace default dev %i table 200
# Device: test
PrivateKey = {PRIV}
Address = 10.66.0.2/32,fc00:bbbb:bbbb:bb01::2/128
Table = off

[Peer]
PublicKey = {KEY_A}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.10:51820
"""


class VpnLibraryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        patches = {'LIB_DIR': self.tmp / 'vpn', 'SERVERS_PATH': self.tmp / 'vpn/servers.json',
                   'KEYS_PATH': self.tmp / 'vpn/keys.json', 'STATE_PATH': self.tmp / 'vpn/state.json',
                   'CONF_PATH': self.tmp / 'wg0.conf'}
        self.patchers = [mock.patch.object(vl, k, v) for k, v in patches.items()]
        for p in self.patchers:
            p.start()
        (self.tmp / 'wg0.conf').write_text(LIVE)
        vl._last_refresh = 0.0

    def tearDown(self):
        for p in self.patchers:
            p.stop()
        shutil.rmtree(self.tmp)

    def test_parse_conf(self):
        conf = vl.parse_conf(LIVE)
        self.assertEqual(conf['interface']['table'], 'off')
        self.assertEqual(conf['peers'][0]['publickey'], KEY_A)

    def test_render_keeps_interface_lines_and_replaces_peer(self):
        out = vl._render_conf(LIVE, None, None, {'hostname': 'se-sto-wg-001', 'pubkey': KEY_B, 'ipv4': '198.51.100.7', 'port': 51820})
        conf = vl.parse_conf(out)
        self.assertIn('PostUp = ip route replace default dev %i table 200', out)
        self.assertEqual(conf['interface']['table'], 'off')
        self.assertEqual(conf['interface']['privatekey'], PRIV)
        self.assertEqual(len(conf['peers']), 1)
        self.assertEqual(conf['peers'][0]['publickey'], KEY_B)
        self.assertEqual(conf['peers'][0]['endpoint'], '198.51.100.7:51820')

    def test_render_with_another_key(self):
        other = 'b3RoZXJwcml2YXRla2V5MDAwMDAwMDAwMDAwMDAwMDA='
        out = vl._render_conf(LIVE, other, '10.70.0.9/32', {'hostname': 'x', 'pubkey': KEY_B, 'ipv4': '198.51.100.7', 'port': 51820})
        conf = vl.parse_conf(out)
        self.assertEqual(conf['interface']['privatekey'], other)
        self.assertEqual(conf['interface']['address'], '10.70.0.9/32')

    def test_endpoint_and_key_validation(self):
        self.assertEqual(vl._valid_endpoint('8.8.4.4:51820'), ('8.8.4.4', 51820))
        for bad in ('10.0.0.1:51820', '8.8.4.4:0', 'example.com:51820', '8.8.4.4', '127.0.0.1:1'):
            self.assertIsNone(vl._valid_endpoint(bad), bad)
        self.assertTrue(vl._KEY.fullmatch(KEY_A))
        self.assertFalse(vl._KEY.fullmatch('short='))

    def _relays(self, n=12):
        return json.dumps([{'hostname': f'se-sto-wg-{i:03d}', 'country_code': 'se', 'country_name': 'Sweden',
                            'city_name': 'Stockholm', 'ipv4_addr_in': f'8.8.{i}.1', 'pubkey': KEY_B,
                            'active': True, 'owned': True, 'provider': 'Mullvad', 'type': 'wireguard'} for i in range(n)]
                          + [{'hostname': 'bad name', 'ipv4_addr_in': '10.0.0.1', 'pubkey': 'x'}]).encode()

    def test_refresh_relays_keeps_valid_servers_only(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = self._relays()
        with mock.patch('urllib.request.OpenerDirector.open', return_value=response):
            result = vl.refresh_relays()
        self.assertEqual(result['count'], 12)
        lib = vl._load_servers()['servers']
        self.assertTrue(all(s['country_code'] == 'se' for s in lib))
        with self.assertRaises(vl.VpnError):  # rate limited
            vl.refresh_relays()

    def test_too_few_relays_changes_nothing(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = self._relays(3)
        with mock.patch('urllib.request.OpenerDirector.open', return_value=response):
            with self.assertRaises(vl.VpnError):
                vl.refresh_relays()
        self.assertFalse(vl.SERVERS_PATH.exists())

    def test_import_zip_stores_key_privately(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('mullvad_config_linux/se-sto-wg-001.conf', LIVE.replace('203.0.113.10', '8.8.8.8'))
            z.writestr('README.txt', 'ignored')
            z.writestr('junk.conf', '[Interface]\nPrivateKey = nope\n')
        with mock.patch.object(vl, 'public_key_of', return_value=KEY_A):
            result = vl.import_configs(buf.getvalue(), 'configs.zip')
        self.assertEqual((result['imported'], result['skipped']), (1, 1))
        self.assertEqual(vl.KEYS_PATH.stat().st_mode & 0o777, 0o600)
        server = vl._load_servers()['servers'][0]
        self.assertEqual((server['hostname'], server['country_code'], server['key_id']), ('se-sto-wg-001', 'se', vl.key_id(KEY_A)))
        self.assertNotIn(PRIV, vl.SERVERS_PATH.read_text())

    def test_import_rejects_oversized_entries(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('big.conf', 'x' * 20000)
        with self.assertRaises(vl.VpnError):
            vl.import_configs(buf.getvalue(), 'big.zip')

    def test_rotation_settings_and_due(self):
        vl._write_json(vl.SERVERS_PATH, {'servers': [{'hostname': 'se-sto-wg-001', 'country_code': 'se', 'active': True}]})
        with self.assertRaises(vl.VpnError):
            vl.set_rotation(True, 5, ['se'])      # not an offered interval
        with self.assertRaises(vl.VpnError):
            vl.set_rotation(True, 6, ['zz'])      # no servers there
        vl.set_rotation(True, 6, ['se'])
        self.assertFalse(vl.rotation_due())
        self.assertTrue(vl.rotation_due(time.time() + 6 * 3600 + 1))
        vl.set_rotation(False, 6, [])
        self.assertFalse(vl.rotation_due(time.time() + 99 * 3600))

    def test_switch_restores_previous_server_when_new_one_is_silent(self):
        vl._write_json(vl.SERVERS_PATH, {'servers': [{'hostname': 'se-sto-wg-001', 'country_code': 'se', 'country': 'Sweden',
                                                      'city': 'Stockholm', 'ipv4': '8.8.8.8', 'port': 51820, 'pubkey': KEY_B, 'active': True}]})
        applied = []
        with mock.patch.object(vl, '_apply', side_effect=lambda text, restart: applied.append(text)), \
             mock.patch.object(vl, '_verify', return_value=False), \
             mock.patch.object(vl, '_wg_dump', return_value={'up': True, 'public_key': KEY_A, 'peers': []}):
            with self.assertRaises(vl.VpnError):
                vl.switch('se-sto-wg-001')
        self.assertEqual(len(applied), 2)
        self.assertIn(KEY_B, applied[0])
        self.assertEqual(applied[1], LIVE)   # the previous config, byte for byte


    def test_switch_job_logs_live_and_allows_one_at_a_time(self):
        import threading
        gate = threading.Event()
        def slow():
            vl._log('step one')
            gate.wait(2)
            vl._log('step two', 'ok')
            return {'ok': True, 'message': 'done'}
        started = vl.start_switch_job('manual', slow)
        self.assertTrue(started['ok'])
        with self.assertRaises(vl.VpnError):
            vl.start_switch_job('manual', slow)
        job = vl.job_status()['job']
        self.assertEqual(job['state'], 'running')
        gate.set()
        deadline = time.time() + 3
        while vl.job_status()['job']['state'] == 'running' and time.time() < deadline:
            time.sleep(0.02)
        job = vl.job_status()['job']
        self.assertEqual(job['state'], 'done')
        self.assertEqual([l['msg'] for l in job['lines']], ['step one', 'step two'])

    def test_failed_job_ends_with_the_error(self):
        def boom():
            raise vl.VpnError('no answer')
        vl.start_switch_job('random', boom)
        deadline = time.time() + 3
        while vl.job_status()['job']['state'] == 'running' and time.time() < deadline:
            time.sleep(0.02)
        job = vl.job_status()['job']
        self.assertEqual(job['state'], 'failed')
        self.assertEqual(job['lines'][-1]['level'], 'error')


if __name__ == '__main__':
    unittest.main()
