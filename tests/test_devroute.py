import unittest

import devroute as dr

CFG = {**dr.SITE, 'ap_interface': 'wlan1', 'ap2_interface': 'wlan0', 'uplink_interface': 'end0', 'vpn_interface': 'wg0'}
FIREWALL = """define AP5 = "wlan1"
define AP2 = "wlan0"
define VPN = "wg0"
define NET5 = 192.168.50.0/24
define NET2 = 192.168.60.0/24
table inet apguard
delete table inet apguard
table inet apguard {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state invalid drop
        iifname $AP5 oifname $VPN ip saddr $NET5 accept
        iifname $AP2 oifname $VPN ip saddr $NET2 accept
        iifname $VPN oifname { $AP5, $AP2 } ct state established,related accept
        counter drop comment "fail-closed"
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr { $NET5, $NET2 } oifname $VPN masquerade
    }
}
"""
STATE = {'devices': {'02:00:00:00:00:01': {'route': 'direct'}, '02:00:00:00:00:02': {'route': 'blocked'},
                     '02:00:00:00:00:03': {'route': 'second'}}}


class DevrouteTests(unittest.TestCase):
    def test_rules_go_before_fail_closed_and_after_masquerade(self):
        out = dr.render(FIREWALL, STATE, CFG)
        self.assertLess(out.index('devroute: blocked device'), out.index('counter drop comment "fail-closed"'))
        self.assertLess(out.index('ip saddr { $NET5, $NET2 } oifname $VPN masquerade'), out.index('meta mark 0x5a1 oifname "end0" masquerade'))
        self.assertIn('set devroute_direct { type ether_addr; elements = { 02:00:00:00:00:01 } }', out)
        self.assertIn('set devroute_blocked { type ether_addr; elements = { 02:00:00:00:00:02 } }', out)
        self.assertIn(f'oifname "{dr.SECOND_IFACE}"', out)

    def test_render_is_idempotent_and_removable(self):
        once = dr.render(FIREWALL, STATE, CFG)
        self.assertEqual(dr.render(once, STATE, CFG), once)
        self.assertEqual(dr._strip_managed(once), FIREWALL)

    def test_empty_state_still_renders_valid_sets(self):
        out = dr.render(FIREWALL, {'devices': {}}, CFG)
        self.assertIn('set devroute_direct { type ether_addr; }', out)

    def test_refuses_a_firewall_without_fail_closed(self):
        with self.assertRaises(dr.RouteError):
            dr.render(FIREWALL.replace('counter drop comment "fail-closed"', 'accept'), STATE, CFG)

    def test_set_route_validates(self):
        with self.assertRaises(dr.RouteError):
            dr.set_route('not-a-mac', 'direct')
        with self.assertRaises(dr.RouteError):
            dr.set_route('02:00:00:00:00:01', 'everywhere')


if __name__ == '__main__':
    unittest.main()
