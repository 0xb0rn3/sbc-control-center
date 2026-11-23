import os
import unittest
from pathlib import Path

import device_intelligence
import sbc_admin
import sbc_site


class IeeeUnitTests(unittest.TestCase):
    def test_units_run_this_program(self):
        units = sbc_admin.ieee_units()
        service = units[f'{sbc_site.PREFIX}-ieee-update.service']
        timer = units[f'{sbc_site.PREFIX}-ieee-update.timer']
        admin = Path(os.path.abspath(sbc_admin.__file__))
        self.assertIn(f'ExecStart=/usr/bin/python3 {admin} oui update\n', service)
        self.assertTrue(admin.exists())   # the path the timer runs is a file that is really there
        self.assertIn(f'ReadWritePaths={device_intelligence.OUI_DATA_DIR}\n', service)
        self.assertIn('ProtectSystem=strict', service)
        self.assertNotIn('kickpi_admin', service)
        self.assertIn(f'Unit={sbc_site.PREFIX}-ieee-update.service', timer)
        self.assertIn('OnUnitActiveSec=30d', timer)

    @unittest.skipIf(os.geteuid() == 0, 'as root this would really install the units')
    def test_install_units_parses_and_needs_root(self):
        # an unknown subcommand would raise SystemExit from argparse; a known one returns 2 (needs sudo)
        self.assertEqual(sbc_admin.main(['oui', 'install-units']), 2)


if __name__ == '__main__':
    unittest.main()
