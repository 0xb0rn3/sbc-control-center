import os
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

import packet_monitor
import packet_analysis


class FlowRateSeriesTests(unittest.TestCase):
    def _event(self, flow_id='abc123', direction='client-to-network', size=100, timestamp=1000.0):
        return {
            'timestamp': timestamp, 'flow_id': flow_id, 'interface': 'wlan0',
            'path': 'AP · onboard 2.4 GHz', 'client_ip': '192.168.60.20',
            'remote_ip': '93.184.216.34', 'client_label': 'test-client',
            'remote_port': 443, 'client_port': 51000, 'protocol': 'TCP',
            'application': 'TLS', 'domain': 'example.com',
            'flow_direction': direction, 'bytes': size, 'signal': None, 'note': None,
        }

    def test_actual_elapsed_interval_and_utc_timestamp(self):
        monitor = packet_monitor.PacketMonitor()
        event = self._event()
        monitor._update_flow_locked(event)
        key = 'wlan0:abc123'
        start = monitor._flows[key]['_sample_mono']
        with monitor._lock:
            monitor._sample_rates_locked(start + 2.0, 1_800_000_000_000_000_000)
        flow = monitor._flows[key]
        sample = list(monitor._flow_series[key])[-1]
        self.assertEqual(sample['upload_bytes'], 100)
        self.assertEqual(sample['download_bytes'], 0)
        self.assertEqual(sample['upload_bytes_per_second'], 50.0)
        self.assertEqual(sample['elapsed_ms'], 2000.0)
        self.assertEqual(sample['timestamp_ns'], 1_800_000_000_000_000_000)
        self.assertTrue(sample['timestamp_utc'].endswith('Z'))
        self.assertEqual(flow['packets_per_second'], 0.5)

    def test_idle_interval_is_a_zero_sample_not_a_stale_rate(self):
        monitor = packet_monitor.PacketMonitor()
        monitor._update_flow_locked(self._event())
        key = 'wlan0:abc123'
        start = monitor._flows[key]['_sample_mono']
        with monitor._lock:
            monitor._sample_rates_locked(start + 1.0, 1_800_000_000_000_000_000)
            monitor._sample_rates_locked(start + 2.0, 1_800_000_001_000_000_000)
        samples = list(monitor._flow_series[key])
        self.assertEqual(samples[-1]['upload_bytes'], 0)
        self.assertEqual(samples[-1]['upload_bytes_per_second'], 0.0)
        self.assertEqual(monitor._flows[key]['bits_per_second'], 0.0)

    def test_upload_and_download_are_separated(self):
        monitor = packet_monitor.PacketMonitor()
        monitor._update_flow_locked(self._event(direction='client-to-network', size=300))
        monitor._update_flow_locked(self._event(direction='network-to-client', size=700))
        key = 'wlan0:abc123'
        start = monitor._flows[key]['_sample_mono']
        with monitor._lock:
            monitor._sample_rates_locked(start + 1.0, 1_800_000_000_000_000_000)
        sample = list(monitor._flow_series[key])[-1]
        self.assertEqual(sample['upload_bytes'], 300)
        self.assertEqual(sample['download_bytes'], 700)
        self.assertEqual(sample['bytes'], 1000)

    def test_flow_series_memory_is_bounded(self):
        monitor = packet_monitor.PacketMonitor()
        for index in range(packet_monitor.MAX_FLOW_SERIES + 10):
            monitor._update_flow_locked(self._event(flow_id=f'flow{index}'))
        self.assertEqual(len(monitor._flow_series), packet_monitor.MAX_FLOW_SERIES)
        self.assertNotIn('wlan0:flow0', monitor._flow_series)

    def test_snapshot_returns_only_requested_flow_series(self):
        monitor = packet_monitor.PacketMonitor()
        monitor._update_flow_locked(self._event())
        key = 'wlan0:abc123'
        response = monitor.snapshot(after=0, limit=0, series_id=key)
        self.assertEqual(response['flow_series']['series_id'], key)
        self.assertEqual(len(response['flow_series_options']), 1)
        self.assertIsNone(monitor.snapshot(series_id='../../etc/passwd')['flow_series'])


class TSharkAnalysisTests(unittest.TestCase):
    def test_conversations_tcp_flags_dns_and_expert_fields_are_parsed(self):
        with tempfile.NamedTemporaryFile(suffix='.pcapng') as capture:
            fields = [''] * 33
            fields[0] = '1'
            fields[1] = 'ip:tcp:tls'
            fields[2] = '1800000000.250000'
            fields[3] = '192.168.60.20'
            fields[5] = '93.184.216.34'
            fields[7] = '51000'
            fields[9] = '443'
            fields[11] = 'example.com'
            fields[12] = '1'
            fields[13] = '3'
            fields[14] = 'example.com'
            fields[16] = '1500'
            fields[17] = '1'
            fields[20] = '1'
            fields[23] = '0.025'
            fields[24] = '0x0002'
            fields[27] = ''
            fields[28] = '1200'  # UDP length must not be misread as a TCP window.
            fields[31] = '3'
            fields[32] = 'TCP duplicate ACK'
            udp_row = fields.copy()
            tcp_row = fields.copy()
            tcp_row[0] = '2'
            tcp_row[2] = '1800000001.250000'
            tcp_row[27] = '0'
            output = ('\t'.join(udp_row) + '\n' + '\t'.join(tcp_row) + '\n').encode()
            completed = SimpleNamespace(stdout=output, stderr=b'', returncode=0)
            with mock.patch.object(packet_analysis, '_validated_capture', return_value=__import__('pathlib').Path(capture.name)), \
                 mock.patch.object(packet_analysis.shutil, 'which', return_value='/usr/bin/tshark'), \
                 mock.patch.object(packet_analysis.os, 'geteuid', return_value=0), \
                 mock.patch.object(packet_analysis.subprocess, 'run', return_value=completed) as run_mock:
                result = packet_analysis.analyse_capture(capture.name)
        self.assertTrue(result['ok'])
        self.assertEqual(result['capture']['analysed_packets'], 2)
        self.assertIn('separator=/t', run_mock.call_args.args[0])
        self.assertEqual(result['conversations'][0]['frames'], 2)
        self.assertEqual(result['conversations'][0]['bytes'], 3000)
        self.assertEqual(result['dns_rcodes'][0]['name'], 'NXDOMAIN')
        self.assertEqual(result['tcp_analysis'][0]['name'], 'Retransmissions')
        tcp_rows = {item['name']: item['count'] for item in result['tcp_analysis']}
        self.assertEqual(tcp_rows['Zero Window Advertisements'], 1)
        self.assertEqual(result['tcp_rtt']['average_ms'], 25.0)
        self.assertIn('TCP duplicate ACK', result['expert'][0]['message'])


if __name__ == '__main__':
    unittest.main()
