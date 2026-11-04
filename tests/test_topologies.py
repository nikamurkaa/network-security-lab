"""Public topology and configuration consistency checks (not device simulation)."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TopologyTests(unittest.TestCase):
    def test_sanitized_topology_files(self):
        for name, expected_nodes, expected_links in [('vlan-segmentation', 6, 5), ('ospf-chain', 3, 2)]:
            with self.subTest(name=name):
                raw = (ROOT / 'topologies/gns3' / f'{name}.gns3').read_text()
                doc = json.loads(raw)
                self.assertEqual(len(doc['topology']['nodes']), expected_nodes)
                self.assertEqual(len(doc['topology']['links']), expected_links)
                self.assertNotIn('image_md5sum', raw)
                self.assertNotIn('system_id', raw)

    def test_vlan_configs(self):
        for name in ('vlan-sw1.example.cfg', 'vlan-sw2.example.cfg'):
            with self.subTest(name=name):
                data = (ROOT / 'configs' / name).read_text()
                for required in ('switchport mode trunk', 'switchport trunk native vlan 999',
                                 'switchport trunk allowed vlan 10,20,999', 'switchport access vlan 998',
                                 'switchport access vlan 10', 'switchport access vlan 20', 'shutdown'):
                    self.assertIn(required, data)

    def test_ospf_configs(self):
        configs = [(ROOT/'configs'/f'ospf-r{i}.example.cfg').read_text() for i in (1, 2, 3)]
        for content in configs:
            self.assertIn('router ospf 1', content)
            self.assertIn('area 0 authentication message-digest', content)
            self.assertIn('REPLACE_WITH_', content)
        self.assertIn('10.0.12.1', configs[0])
        self.assertIn('10.0.12.2', configs[1])
        self.assertIn('10.0.23.1', configs[1])
        self.assertIn('10.0.23.2', configs[2])

    def test_no_proprietary_binary(self):
        forbidden = {'.image', '.ghost', '.iso', '.qcow2', '.vmdk', '.gns3project'}
        self.assertFalse([str(p) for p in ROOT.rglob('*') if p.is_file() and p.suffix.lower() in forbidden])


if __name__ == '__main__':
    unittest.main()
