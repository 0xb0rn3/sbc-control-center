import json
import stat
import unittest
from unittest import mock

import zlt_readonly


class ZltRouterConfigTests(unittest.TestCase):
    def _fake_path(self, payload):
        fake = mock.Mock()
        fake.stat.return_value = mock.Mock(
            st_mode=stat.S_IFREG | 0o640,
            st_uid=0,
        )
        fake.read_text.return_value = json.dumps(payload)
        return fake

    def test_private_lan_router_host_is_allowed(self):
        fake = self._fake_path({
            "host":"192.168.1.1","username":"router-admin","password":"not-a-real-password"
        })
        with mock.patch.object(zlt_readonly, "CONFIG_PATH", fake):
            config = zlt_readonly._config()
        self.assertEqual(config["host"], "192.168.1.1")
        self.assertEqual(config["password"], "not-a-real-password")

    def test_public_router_host_is_rejected(self):
        fake = self._fake_path({
            "host":"8.8.8.8","username":"router-admin","password":"not-a-real-password"
        })
        with mock.patch.object(zlt_readonly, "CONFIG_PATH", fake):
            with self.assertRaises(zlt_readonly.RouterUnavailable):
                zlt_readonly._config()

    def test_missing_router_configuration_is_reported(self):
        fake = mock.Mock()
        fake.stat.side_effect = FileNotFoundError
        with mock.patch.object(zlt_readonly, "CONFIG_PATH", fake):
            with self.assertRaisesRegex(zlt_readonly.RouterUnavailable, "not configured"):
                zlt_readonly._config()


if __name__ == "__main__":
    unittest.main()
