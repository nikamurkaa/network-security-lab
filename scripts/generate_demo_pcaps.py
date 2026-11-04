#!/usr/bin/env python3
"""Generate original, synthetic, offline demonstration PCAPs (no traffic is sent)."""
from __future__ import annotations
import ipaddress
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'captures' / 'demo'


def checksum(buf: bytes):
    if len(buf) % 2:
        buf += b'\0'
    total = sum(struct.unpack('!%dH' % (len(buf) // 2), buf))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def eth(payload: bytes, type_: int = 0x800):
    return bytes.fromhex('020000000002020000000001') + struct.pack('!H', type_) + payload


def ipv4(src: str, dst: str, proto: int, body: bytes, identification: int = 0x42):
    s, d = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    head = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), identification, 0, 64, proto, 0, s, d)
    head = head[:10] + struct.pack('!H', checksum(head)) + head[12:]
    return eth(head + body)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes):
    h = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    pseudo = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed + struct.pack('!BBH', 0, 17, len(h) + len(payload))
    csum = checksum(pseudo + h + payload) or 0xffff
    h = h[:6] + struct.pack('!H', csum)
    return ipv4(src, dst, 17, h + payload)


def tcp(src: str, dst: str, sport: int, dport: int, payload: bytes = b'', flags: int = 0x02):
    h = struct.pack('!HHIIHHHH', sport, dport, 1000, 0, (5 << 12) | flags, 65535, 0, 0)
    pseudo = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed + struct.pack('!BBH', 0, 6, len(h) + len(payload))
    h = h[:16] + struct.pack('!H', checksum(pseudo + h + payload)) + h[18:]
    return ipv4(src, dst, 6, h + payload)


def dns_query():
    # Documentation-only domain (RFC 6761).
    qname = b'\x07example\x04test\x00'
    dns = struct.pack('!HHHHHH', 0x1234, 0x100, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)
    return udp('192.0.2.10', '192.0.2.53', 53535, 53, dns)


def dhcp_discover():
    bootp = bytearray(236)
    bootp[0:4] = bytes([1, 1, 6, 0])
    bootp[4:8] = b'\x12\x34\x56\x78'
    bootp[10:12] = b'\x80\x00'
    bootp[28:34] = bytes.fromhex('020000000001')
    payload = bytes(bootp) + b'\x63\x82\x53\x63' + b'\x35\x01\x01\xff'
    return udp('0.0.0.0', '255.255.255.255', 68, 67, payload)


def ntp_request():
    return udp('192.0.2.10', '192.0.2.123', 123, 123, bytes([0x1b]) + bytes(47))


def ospf_hello():
    # Protocol metadata demo only, NOT a fully valid OSPF adjacency message.
    return ipv4('192.0.2.1', '224.0.0.5', 89, bytes(24))


def write_pcap(dest: Path, packets):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open('wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for idx, packet in enumerate(packets):
            f.write(struct.pack('<IIII', 1700000000 + idx, 0, len(packet), len(packet)))
            f.write(packet)


def main():
    cases = {
        'dns-demo.pcap': [dns_query()],
        'dhcp-demo.pcap': [dhcp_discover()],
        'ntp-demo.pcap': [ntp_request()],
        'ssh-demo.pcap': [tcp('192.0.2.10', '192.0.2.22', 53000, 22), tcp('192.0.2.22', '192.0.2.10', 22, 53000, flags=0x12)],
        'ospf-demo.pcap': [ospf_hello()],
        'tcp-review-demo.pcap': [tcp('198.51.100.10', '198.51.100.20', 50001, 4444), tcp('198.51.100.20', '198.51.100.10', 4444, 50001, flags=0x12)],
        'smb-demo.pcap': [tcp('203.0.113.10', '203.0.113.20', 53111, 445)],
    }
    for filename, packets in cases.items():
        write_pcap(DEST / filename, packets)
        print('Created', filename, f'({len(packets)} packet(s))')


if __name__ == '__main__':
    main()
