# Protocol review: DNS, DHCP, SSH, NTP and routing

The original hands-on observations were made in a simulated network. The captures published in this repository are **new synthetic illustrations**, not copies of the source captures. Port identifiers and message types below are protocol-level concepts, not proof of a full end-to-end session in the synthetic PCAPs.

## DNS

- A host-resolution request uses DNS query type `A` (QTYPE=1), class `IN` (QCLASS=1).
- DNS frequently uses UDP destination port `53`; DNS also supports TCP and other transports.
- To investigate an observed exchange in Wireshark, review transaction ID, questions, response codes and answer records.
- Offline sample: [`dns-demo.pcap`](../captures/demo/dns-demo.pcap). It contains a single sample query for the reserved name `example.test`.

## DHCP

- The address-acquisition cycle is commonly summarized as **DORA**: Discover → Offer → Request → Acknowledge.
- Before obtaining an address, a client can send Discover from `0.0.0.0:68` to `255.255.255.255:67`.
- In packet review, distinguish the message type, transaction ID, server identifier, offered address and lease options.
- Offline sample: [`dhcp-demo.pcap`](../captures/demo/dhcp-demo.pcap). **Only a Discover**, not an entire DORA exchange.

## SSH

- SSH normally uses TCP port `22` and protects the application protocol after connection establishment.
- TCP flow metadata alone does **not** reveal credentials or verify that authentication succeeded.
- Offline sample: [`ssh-demo.pcap`](../captures/demo/ssh-demo.pcap). Only synthetic TCP handshake metadata; no SSH authentication exchange.

## NTP

- NTP commonly uses UDP port `123` and includes timestamp fields used for clock synchronization.
- Accurate interpretation requires inspection of NTP header fields, not only the port number.
- Offline sample: [`ntp-demo.pcap`](../captures/demo/ntp-demo.pcap). A minimal example request, not a completed time sync.

## Static routing, VLANs and OSPF

- Static routes are explicitly configured next-hop or exit-interface paths; validate them with route-table output and connectivity checks.
- VLANs partition a Layer 2 topology. Segmentation depends on correct access/trunk assignments and corresponding network policy.
- OSPF forms adjacencies, exchanges link-state information and computes routes from interface cost.
- OSPF protocol number is `89` (not TCP/UDP port 89). A basic IP protocol identifier appears in [`ospf-demo.pcap`](../captures/demo/ospf-demo.pcap), **not** a working OSPF adjacency.

## Suggested Wireshark display filters

```text
dns
dhcp
ntp
tcp.port == 22
ospf
tcp.port == 445
```

For actual troubleshooting, correlate filters with addresses, timestamps, topology and device logs. See [traffic analysis case notes](traffic-cases.md).
