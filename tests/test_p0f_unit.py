"""The p0f monitor's unit starts p0f 3 with options it has (one it lacked kept it restarting forever)."""
import re
import shlex
import unittest
from pathlib import Path

UNIT = Path(__file__).resolve().parent.parent / 'systemd' / 'kickpi-p0f@.service'
P0F3_OPTIONS = set('irpLofsuSdtm')   # p0f 3.09b's usage text: -i -r -p -L -o -f -s -u -S -d -t -m


class P0fUnitTests(unittest.TestCase):
    def test_only_options_p0f_3_has(self):
        line = next(l for l in UNIT.read_text().splitlines() if l.startswith('ExecStart='))
        args = shlex.split(line.split('=', 1)[1])
        self.assertEqual(args[0], '/usr/sbin/p0f')
        flags = [a[1:] for a in args[1:] if re.fullmatch(r'-[A-Za-z]', a)]
        self.assertTrue(flags)
        self.assertEqual([f for f in flags if f not in P0F3_OPTIONS], [])

    def test_its_lines_stay_out_of_the_journal(self):
        self.assertIn('StandardOutput=null', UNIT.read_text())


if __name__ == '__main__':
    unittest.main()
