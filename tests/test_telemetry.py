import importlib.util
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sbc_telemetry_test', ROOT / 'telemetry.py')
telemetry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(telemetry)


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        telemetry.reset_for_tests()

    def tearDown(self):
        telemetry.reset_for_tests()

    def test_cpu_usage_uses_deltas_and_excludes_guest_double_count(self):
        # guest/guest_nice jump by a large amount, but those fields are already
        # represented in user/nice in /proc/stat and must not change utilization.
        with mock.patch.object(telemetry, '_read_cpu_times', side_effect=[
            {'cpu': (100, 50), 'cpu0': (50, 25)},
            {'cpu': (200, 100), 'cpu0': (100, 50)},
        ]):
            first = telemetry._cpu_usage()
            second = telemetry._cpu_usage()
        self.assertIsNone(first['percent'])
        self.assertEqual(second['percent'], 50.0)
        self.assertEqual(second['cores'][0]['percent'], 50.0)

    def test_network_rates_are_calculated_from_kernel_counter_deltas(self):
        base = {
            'eth0': {'rx_bytes': 1000, 'rx_packets': 10, 'rx_errors': 0, 'rx_dropped': 0,
                     'tx_bytes': 2000, 'tx_packets': 20, 'tx_errors': 0, 'tx_dropped': 0,
                     '_include_total': 1, '_state_up': 1},
            'lo': {'rx_bytes': 500, 'rx_packets': 5, 'rx_errors': 0, 'rx_dropped': 0,
                   'tx_bytes': 500, 'tx_packets': 5, 'tx_errors': 0, 'tx_dropped': 0,
                   '_include_total': 0, '_state_up': 1},
        }
        later = {
            'eth0': {'rx_bytes': 5000, 'rx_packets': 50, 'rx_errors': 1, 'rx_dropped': 2,
                     'tx_bytes': 6000, 'tx_packets': 60, 'tx_errors': 3, 'tx_dropped': 4,
                     '_include_total': 1, '_state_up': 1},
            'lo': {'rx_bytes': 1500, 'rx_packets': 15, 'rx_errors': 0, 'rx_dropped': 0,
                   'tx_bytes': 1500, 'tx_packets': 15, 'tx_errors': 0, 'tx_dropped': 0,
                   '_include_total': 0, '_state_up': 1},
        }
        with mock.patch.object(telemetry, '_net_counters', side_effect=[base, later]):
            first = telemetry._network_rates(10.0)
            second = telemetry._network_rates(12.0)
        self.assertEqual(first['totals']['rx_bytes_per_sec'], 0.0)
        self.assertEqual(second['totals']['rx_bytes_per_sec'], 2000.0)
        self.assertEqual(second['totals']['tx_bytes_per_sec'], 2000.0)
        self.assertEqual(second['totals']['rx_packets_per_sec'], 20.0)
        self.assertEqual(second['totals']['tx_packets_per_sec'], 20.0)
        self.assertEqual(second['interfaces'][0]['rx_errors'], 1)
        self.assertEqual(second['interfaces'][0]['tx_dropped'], 4)
        self.assertEqual(second['totals']['rx_bytes_per_sec'],
                         second['interfaces'][0]['rx_bytes_per_sec'])

    def test_temperature_reads_merge_thermal_zones_and_hwmon_sensors(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); thermal=base/'thermal'; hwmon=base/'hwmon'
            zone=thermal/'thermal_zone0'; zone.mkdir(parents=True)
            (zone/'temp').write_text('52000'); (zone/'type').write_text('cpu-thermal')
            device=hwmon/'hwmon0'; device.mkdir(parents=True)
            (device/'name').write_text('gpu-monitor')
            (device/'temp1_input').write_text('49500')
            (device/'temp1_label').write_text('gpu-thermal')
            with mock.patch.object(telemetry, 'SYS_THERMAL', thermal), \
                 mock.patch.object(telemetry, 'SYS_HWMON', hwmon):
                result=telemetry._temperature_sensors()
        self.assertEqual({item['label'] for item in result}, {'cpu-thermal', 'gpu-thermal'})
        self.assertEqual({item['source'] for item in result}, {'thermal', 'hwmon'})

    def test_snapshot_exposes_all_live_resource_series(self):
        with mock.patch.object(telemetry, '_cpu_usage', return_value={'percent': 12.5, 'cores': []}), \
             mock.patch.object(telemetry, '_network_rates', return_value={
                 'interfaces': [], 'totals': {'rx_bytes_per_sec': 100, 'tx_bytes_per_sec': 50,
                                              'rx_packets_per_sec': 2, 'tx_packets_per_sec': 1}}), \
             mock.patch.object(telemetry, '_temperature_sensors', return_value=[
                 {'label': 'CPU', 'temperature_c': 48.5, 'source': 'thermal'}]), \
             mock.patch.object(telemetry, '_memory', return_value={'total': 1024, 'used': 512,
                                                                   'available': 512, 'swap_total': 0,
                                                                   'swap_used': 0}), \
             mock.patch.object(telemetry, '_disk_io', return_value={'read_bytes_per_sec': 5,
                                                                    'write_bytes_per_sec': 6,
                                                                    'devices': 1}), \
             mock.patch.object(telemetry.Path, 'read_text', return_value='0.10 0.20 0.30 1/2 100'):
            result = telemetry.snapshot()
        for key in ('timestamp', 'cpu', 'memory', 'temperature_c', 'temperatures', 'network', 'disk_io', 'load'):
            self.assertIn(key, result)
        self.assertEqual(result['temperature_c'], 48.5)
        self.assertEqual(result['network']['totals']['rx_packets_per_sec'], 2)
        self.assertEqual(result['disk_io']['write_bytes_per_sec'], 6)

    def test_pressure_stall_information_parses_available_kernel_metrics(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / 'cpu').write_text('some avg10=1.25 avg60=0.50 avg300=0.10 total=123\nfull avg10=0.25 avg60=0.10 avg300=0.01 total=45\n')
            (base / 'memory').write_text('some avg10=2.00 avg60=1.00 avg300=0.50 total=456\n')
            with mock.patch.object(telemetry, 'PROC_PRESSURE', base):
                result = telemetry._pressure()
        self.assertEqual(result['cpu']['some']['avg10'], 1.25)
        self.assertEqual(result['cpu']['full']['total'], 45)
        self.assertEqual(result['memory']['some']['avg60'], 1.0)
        self.assertNotIn('io', result)

    def test_cpu_frequency_reads_per_cpu_policy_and_reports_mhz(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cpu = Path(tmp) / 'cpu0' / 'cpufreq'
            cpu.mkdir(parents=True)
            (cpu / 'scaling_cur_freq').write_text('1800000')
            (cpu / 'scaling_min_freq').write_text('600000')
            (cpu / 'scaling_max_freq').write_text('2400000')
            with mock.patch.object(telemetry, 'SYS_CPU', Path(tmp)):
                result = telemetry._cpu_frequency()
        self.assertEqual(result['average_mhz'], 1800.0)
        self.assertEqual(result['cpus'][0]['min_mhz'], 600.0)
        self.assertEqual(result['cpus'][0]['max_mhz'], 2400.0)

    def test_devfreq_ignores_non_accelerator_domains(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            gpu = base / 'ff9a0000.gpu'; gpu.mkdir()
            (gpu / 'name').write_text('mali-g610')
            (gpu / 'cur_freq').write_text('800000000')
            (gpu / 'max_freq').write_text('1000000000')
            (gpu / 'load').write_text('37')
            ddr = base / 'ddr'; ddr.mkdir()
            (ddr / 'name').write_text('ddr-controller')
            (ddr / 'cur_freq').write_text('800000000')
            with mock.patch.object(telemetry, 'SYS_DEVFREQ', base), \
                 mock.patch.object(telemetry, 'SYS_DRM', base / 'no-drm'):
                result = telemetry._accelerator_metrics()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'mali-g610')
        self.assertEqual(result[0]['utilization_percent'], 37)

    def test_snapshot_includes_extended_board_and_resource_metrics(self):
        with mock.patch.object(telemetry, '_cpu_usage', return_value={'percent': 12.5, 'cores': []}), \
             mock.patch.object(telemetry, '_network_rates', return_value={'interfaces': [], 'totals': {}}), \
             mock.patch.object(telemetry, '_temperature_sensors', return_value=[]), \
             mock.patch.object(telemetry, '_memory', return_value={'total': 100, 'used': 20, 'available': 80, 'swap_total': 0, 'swap_used': 0}), \
             mock.patch.object(telemetry, '_disk_io', return_value={'read_bytes_per_sec': 0, 'write_bytes_per_sec': 0, 'devices': 0}), \
             mock.patch.object(telemetry, '_cpu_frequency', return_value={'average_mhz': 1200, 'cpus': []}), \
             mock.patch.object(telemetry, '_accelerator_metrics', return_value=[]), \
             mock.patch.object(telemetry, '_pressure', return_value={'cpu': {'some': {'avg10': 0.1}}}), \
             mock.patch.object(telemetry, '_device_model', return_value='Test SBC'), \
             mock.patch.object(telemetry, '_process_count', return_value=42), \
             mock.patch.object(telemetry.Path, 'read_text', return_value='0.10 0.20 0.30 1/2 100'):
            result = telemetry.snapshot()
        self.assertEqual(result['device_model'], 'Test SBC')
        self.assertEqual(result['process_count'], 42)
        self.assertEqual(result['cpu_frequency']['average_mhz'], 1200)
        self.assertIn('pressure', result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
