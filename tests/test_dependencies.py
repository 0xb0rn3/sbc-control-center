import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DependencyTests(unittest.TestCase):
    def test_every_local_import_is_in_the_tree(self):
        local = {p.stem for p in ROOT.glob('*.py')}
        third_party = {'fido2', 'yaml', 'maxminddb', 'geoip2'}
        for path in ROOT.glob('*.py'):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                names = [a.name.split('.')[0] for a in node.names] if isinstance(node, ast.Import) else \
                        [node.module.split('.')[0]] if isinstance(node, ast.ImportFrom) and node.module and node.level == 0 else []
                for name in names:
                    if name in third_party or name in local:
                        continue
                    __import__(name)   # must be the standard library

    def test_third_party_python_modules_are_in_the_package_list(self):
        packages = set((ROOT / 'packages' / 'debian-required.txt').read_text().split())
        for pkg in ('python3-fido2', 'python3-yaml', 'python3-maxminddb', 'python3-geoip2'):
            self.assertIn(pkg, packages)

    def test_tools_the_code_calls_are_in_the_package_lists(self):
        packages = set((ROOT / 'packages' / 'debian-required.txt').read_text().split()) | \
                   set((ROOT / 'packages' / 'debian-optional.txt').read_text().split())
        for pkg in ('conntrack', 'tshark', 'wireguard-tools', 'nftables', 'hostapd', 'dnsmasq', 'arp-scan',
                    'nmap', 'p0f', 'arpwatch', 'curl', 'suricata', 'suricata-update', 'rsync'):
            self.assertIn(pkg, packages, pkg)

    def test_installer_uses_the_dependency_tool(self):
        self.assertIn('tools/install-dependencies.sh', (ROOT / 'install.sh').read_text())


if __name__ == '__main__':
    unittest.main()
