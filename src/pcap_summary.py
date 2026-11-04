#!/usr/bin/env python3
"""Offline, payload-free summary of classic PCAP and basic PCAPNG captures.

No packet injection, active scanning, or network connections.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import socket
import struct
import sys

MAX_CAPTURED_PACKET = 4 * 1024 * 1024


class CaptureError(ValueError):
    """Unsupported or malformed packet capture."""


def _read_exact(stream, size: int) -> bytes:
    block = stream.read(size)
    if len(block) != size:
        raise CaptureError("Truncated capture")
    return block


def _classic_packets(stream, magic: bytes):
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    hdr = magic + _read_exact(stream, 20)
    linktype = struct.unpack_from(endian + "I", hdr, 20)[0] & 0xFFFF
    while True:
        rec = stream.read(16)
        if not rec:
            return
        if len(rec) < 16:
            raise CaptureError("Truncated PCAP packet header")
        _, _, included, _ = struct.unpack(endian + "IIII", rec)
        if included > MAX_CAPTURED_PACKET:
            raise CaptureError("Packet exceeds safety limit")
        yield linktype, _read_exact(stream, included)


def _pcapng_packets(stream, magic: bytes):
    # PCAPNG blocks are byte-order dependent; each section begins with SHB.
    current_endian = None
    interfaces = []
    pending_magic = magic
    while True:
        if pending_magic:
            head = pending_magic + stream.read(4)
            pending_magic = b""
        else:
            head = stream.read(8)
        if not head:
            return
        if len(head) < 8:
            raise CaptureError("Truncated PCAPNG block header")
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            bom = _read_exact(stream, 4)
            if bom == b"\x4d\x3c\x2b\x1a":
                current_endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                current_endian = ">"
            else:
                raise CaptureError("Invalid PCAPNG byte-order magic")
            block_len = struct.unpack(current_endian + "I", head[4:])[0]
            if not 28 <= block_len <= MAX_CAPTURED_PACKET or block_len % 4:
                raise CaptureError("Invalid PCAPNG section length")
            rest = _read_exact(stream, block_len - 12)
            if struct.unpack(current_endian + "I", rest[-4:])[0] != block_len:
                raise CaptureError("PCAPNG section size mismatch")
            interfaces = []
            continue
        if current_endian is None:
            raise CaptureError("PCAPNG data before section header")
        block_type, block_len = struct.unpack(current_endian + "II", head)
        if not 12 <= block_len <= MAX_CAPTURED_PACKET or block_len % 4:
            raise CaptureError("Invalid PCAPNG block length")
        body = _read_exact(stream, block_len - 8)
        if struct.unpack_from(current_endian + "I", body, len(body) - 4)[0] != block_len:
            raise CaptureError("PCAPNG block size mismatch")
        content = body[:-4]
        if block_type == 1:  # interface description
            if len(content) < 8:
                raise CaptureError("Invalid PCAPNG interface block")
            interfaces.append(struct.unpack_from(current_endian + "H", content)[0])
        elif block_type == 6:  # enhanced packet block
            if len(content) < 20:
                raise CaptureError("Invalid PCAPNG enhanced packet block")
            index, _, _, captured, _ = struct.unpack_from(current_endian + "IIIII", content)
            if index >= len(interfaces) or captured > MAX_CAPTURED_PACKET or 20 + captured > len(content):
                raise CaptureError("Invalid PCAPNG packet length or interface")
            yield interfaces[index], content[20 : 20 + captured]
        elif block_type == 3 and interfaces:  # simple packet block
            if len(content) >= 4:
                original = struct.unpack_from(current_endian + "I", content)[0]
                length = min(original, len(content) - 4)
                yield interfaces[0], content[4 : 4 + length]


def read_packets(path: Path):
    with path.open("rb") as stream:
        magic = stream.read(4)
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _classic_packets(stream, magic)
        elif magic == b"\x0a\x0d\x0d\x0a":
            yield from _pcapng_packets(stream, magic)
        else:
            raise CaptureError("Unsupported or invalid PCAP/PCAPNG format")


def classify_packet(linktype: int, packet: bytes):
    """Return (protocol labels, flow tuple); never decode or expose payloads."""
    labels = []
    flow = None
    if linktype != 1 or len(packet) < 14:  # Ethernet only
        return ["unsupported-linktype"], None
    ethertype = int.from_bytes(packet[12:14], "big")
    pos = 14
    while ethertype in (0x8100, 0x88A8):
        if len(packet) < pos + 4:
            return ["truncated"], None
        ethertype = int.from_bytes(packet[pos + 2 : pos + 4], "big")
        pos += 4
        labels.append("VLAN")
    if ethertype == 0x0806:
        return labels + ["ARP"], None
    if ethertype != 0x0800:
        return labels + ["other-ethernet"], None
    if len(packet) < pos + 20:
        return labels + ["truncated"], None
    ver_ihl = packet[pos]
    ihl = (ver_ihl & 15) * 4
    if ver_ihl >> 4 != 4 or ihl < 20 or len(packet) < pos + ihl:
        return labels + ["truncated"], None
    proto = packet[pos + 9]
    src = socket.inet_ntoa(packet[pos + 12 : pos + 16])
    dst = socket.inet_ntoa(packet[pos + 16 : pos + 20])
    flags_fragment = int.from_bytes(packet[pos + 6 : pos + 8], "big")
    pos += ihl
    labels.append("IPv4")
    if flags_fragment & 0x1FFF:
        return labels + ["fragment"], None
    if proto in (6, 17) and len(packet) >= pos + 4:
        source_port, dest_port = struct.unpack_from("!HH", packet, pos)
        transport = "TCP" if proto == 6 else "UDP"
        labels.append(transport)
        flow = (src, source_port, dst, dest_port, transport)
        ports = {source_port, dest_port}
        if proto == 17 and 53 in ports:
            labels.append("DNS")
        if proto == 17 and ports.intersection({67, 68}):
            labels.append("DHCP")
        if proto == 17 and 123 in ports:
            labels.append("NTP")
        if proto == 6 and 22 in ports:
            labels.append("SSH")
        if proto == 6 and 445 in ports:
            labels.append("SMB")
    elif proto == 89:
        labels.append("OSPF")
    elif proto == 1:
        labels.append("ICMP")
    else:
        labels.append("other-ip")
    return labels, flow


def summarize_capture(path: Path):
    counts, flows = Counter(), Counter()
    total = 0
    for linktype, data in read_packets(path):
        total += 1
        labels, flow = classify_packet(linktype, data)
        counts.update(set(labels))
        if flow:
            flows[flow] += 1
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            digest.update(block)
    return {
        "file": path.name,
        "sha256": digest.hexdigest(),
        "packets": total,
        "protocols": dict(sorted(counts.items())),
        "top_flows": [
            {"source": f"{a}:{sp}", "destination": f"{b}:{dp}", "transport": proto, "packets": count}
            for (a, sp, b, dp, proto), count in flows.most_common(10)
        ],
        "limitations": "Port-based protocol hints only; no payload inspection, intrusion detection, or exploit verification.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline PCAP/PCAPNG protocol metadata inventory")
    parser.add_argument("capture", type=Path, help="PCAP or PCAPNG file")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON")
    args = parser.parse_args(argv)
    try:
        result = summarize_capture(args.capture)
    except (CaptureError, OSError) as exc:
        parser.exit(2, f"Error: {exc}\n")
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"File: {result['file']}\nSHA-256: {result['sha256']}\nPackets: {result['packets']}")
        print("Protocols (overlapping labels):")
        for k, v in result["protocols"].items():
            print(f"  {k:22} {v}")
        print("Top flows:")
        for entry in result["top_flows"]:
            print(f"  {entry['source']} -> {entry['destination']} ({entry['transport']}): {entry['packets']}")
        print(result["limitations"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
