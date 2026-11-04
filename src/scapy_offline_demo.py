#!/usr/bin/env python3
"""Optional Scapy example. Writes a safe offline capture; never sends packets."""
from pathlib import Path


def main():
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError as exc:
        raise SystemExit('Install the optional dependency: pip install scapy') from exc
    output = Path('build/scapy-demo.pcap')
    output.parent.mkdir(parents=True, exist_ok=True)
    packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='192.0.2.10', dst='198.51.100.20') / TCP(sport=52000, dport=12345, flags='PA') / Raw(load=b'Synthetic offline lab packet')
    wrpcap(str(output), [packet])
    print('Saved offline capture:', output)


if __name__ == '__main__':
    main()
