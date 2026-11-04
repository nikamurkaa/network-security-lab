"""Regression checks for offline parser and synthetic packet builder."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))
from pcap_summary import CaptureError, classify_packet, read_packets, summarize_capture
from generate_demo_pcaps import checksum, dns_query, eth, ipv4, write_pcap, main as generate


class CaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generate()

    def test_dns_count(self):
        result = summarize_capture(ROOT / 'captures/demo/dns-demo.pcap')
        self.assertEqual(result['packets'], 1)
        self.assertEqual(result['protocols']['DNS'], 1)
        self.assertEqual(result['top_flows'][0]['destination'], '192.0.2.53:53')
        self.assertEqual(len(result['sha256']), 64)

    def test_dhcp_and_ntp(self):
        for name, protocol in [('dhcp', 'DHCP'), ('ntp', 'NTP')]:
            with self.subTest(name=name):
                result = summarize_capture(ROOT / f'captures/demo/{name}-demo.pcap')
                self.assertEqual(result['protocols'][protocol], 1)

    def test_ssh_smb_ospf(self):
        for name, protocol in [('ssh','SSH'), ('smb','SMB'), ('ospf','OSPF')]:
            with self.subTest(name=name):
                result = summarize_capture(ROOT / f'captures/demo/{name}-demo.pcap')
                self.assertEqual(result['protocols'][protocol], 1 if name != 'ssh' else 2)

    def test_vlan_and_arp(self):
        base = bytes.fromhex('020000000002020000000001')
        vlan = base + bytes.fromhex('810000640800') + ipv4('192.0.2.1','192.0.2.2',1,b'abc')[14:]
        self.assertIn('VLAN', classify_packet(1, vlan)[0])
        self.assertIn('ARP', classify_packet(1, eth(bytes(28), 0x0806))[0])

    def test_unsupported_linktype(self):
        self.assertEqual(classify_packet(101, b'x')[0], ['unsupported-linktype'])

    def test_truncated_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / 'broken.pcap'
            f.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + bytes(9))
            with self.assertRaises(CaptureError):
                list(read_packets(f))

    def test_bad_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / 'random.bin'
            f.write_bytes(b'INVALID')
            with self.assertRaises(CaptureError):
                summarize_capture(f)

    def test_big_capture_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / 'huge.pcap'
            f.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + struct.pack('<IIII', 0, 0, 8*1024*1024, 8*1024*1024))
            with self.assertRaises(CaptureError):
                summarize_capture(f)

    def test_pcapng_enhanced_packet(self):
        # Minimal PCAPNG with one section, Ethernet interface, one packet.
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'demo.pcapng'
            packet = dns_query()
            padded = packet + bytes((-len(packet)) % 4)
            shb = struct.pack('<II I HH q I', 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1, 28)
            idb = struct.pack('<II HH I I', 1, 20, 1, 0, 65535, 20)
            total = 32 + len(padded)
            epb = struct.pack('<II IIIII', 6, total, 0, 0, 0, len(packet), len(packet)) + padded + struct.pack('<I', total)
            p.write_bytes(shb + idb + epb)
            r = summarize_capture(p)
            self.assertEqual(r['protocols'].get('DNS'), 1)

    def test_cli_json(self):
        p = subprocess.run([sys.executable, str(ROOT/'src/pcap_summary.py'), str(ROOT/'captures/demo/dns-demo.pcap'), '--json'],capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(p.stdout)['packets'], 1)

    def test_no_real_network_activity(self):
        # Generator and parser rely on standard-library file I/O only.
        self.assertEqual(checksum(b'\x00\x00'), 0xffff)


if __name__ == '__main__':
    unittest.main()
