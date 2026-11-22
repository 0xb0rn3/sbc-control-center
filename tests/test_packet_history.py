import json
import os
import shutil
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import packet_history as ph


def frame(src_mac, dst_mac, src_ip, dst_ip):
    eth = bytes.fromhex(dst_mac.replace(':', '')) + bytes.fromhex(src_mac.replace(':', '')) + b'\x08\x00'
    payload = b'\x00' * 8
    total = 20 + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 1, 0, 64, 17, 0,
                     bytes(map(int, src_ip.split('.'))), bytes(map(int, dst_ip.split('.'))))
    return eth + ip + payload


def write_pcap(path, frames, start):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, data in enumerate(frames):
            f.write(struct.pack('<IIII', int(start) + i, 0, len(data), len(data)) + data)


class PacketHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.patches = [mock.patch.object(ph, 'HISTORY_DIR', self.tmp / 'ring'),
                        mock.patch.object(ph, 'SUMMARY_DIR', self.tmp / 'summaries')]
        for p in self.patches:
            p.start()
        (self.tmp / 'ring').mkdir()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp)

    def test_unit_records_both_aps_and_uplink_without_the_tunnel(self):
        cfg = {'ap_interface': 'wlan1', 'ap2_interface': 'wlan0', 'uplink_interface': 'end0'}
        text = ph.unit_text(cfg)
        self.assertIn("-i wlan0 -i wlan1 -i end0 -f 'not udp port 51820'", text)
        self.assertIn('-b files:24', text)
        self.assertIn('AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN', text)
        self.assertIn('DynamicUser=yes', text)

    def test_ring_files_mark_only_the_newest_as_open(self):
        for seq, stamp in ((1, '20261122100000'), (2, '20261122110000')):
            (self.tmp / 'ring' / f'ring_{seq:05d}_{stamp}.pcapng').write_bytes(b'x' * seq)
        (self.tmp / 'ring' / 'other.txt').write_text('ignored')
        files = ph.ring_files()
        self.assertEqual([f['closed'] for f in files], [True, False])
        self.assertEqual(files[0]['bytes'], 1)

    @unittest.skipUnless(os.path.exists(ph.TSHARK), 'tshark is not installed')
    def test_summary_and_unrecognised_hosts(self):
        start = time.time() - 7200
        a, b, c = '02:00:00:00:00:01', '02:00:00:00:00:02', '02:11:22:33:44:55'
        frames = [frame(a, b, '192.168.60.20', '1.1.1.1'), frame(b, a, '1.1.1.1', '192.168.60.20'),
                  frame(c, 'ff:ff:ff:ff:ff:ff', '192.168.60.99', '192.168.60.255')]
        write_pcap(self.tmp / 'ring' / 'ring_00001_20261122100000.pcapng', frames, start)
        (self.tmp / 'ring' / 'ring_00002_20261122110000.pcapng').write_bytes(b'')
        self.assertEqual(ph.summarize(), 1)
        self.assertEqual(ph.summarize(), 0)   # summarised once
        with mock.patch.object(ph, '_known_macs', return_value={a: 'phone', b: 'uplink router'}), \
             mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
            status = ph.status()
        rows = {r['mac']: r for r in status['hosts']}
        self.assertEqual(rows[a]['ips'], ['192.168.60.20'])
        self.assertFalse(rows[a]['unrecognised'])
        self.assertTrue(rows[c]['unrecognised'])
        self.assertEqual(status['unrecognised'], 1)
        self.assertEqual(status['hosts'][0]['mac'], c)   # unrecognised first


if __name__ == '__main__':
    unittest.main()
