# Offline traffic analysis: case notes

These are **redacted summaries of observations** from prior isolated training captures. The raw traces and packet payloads are intentionally not redistributed; instead the repository includes safe, clearly labeled synthetic demonstrations in [`captures/demo`](../captures/demo/).

## Case A — SMB negotiation and authentication

A captured client/server TCP exchange used SMB over port **445**. Review of the original trace found:

1. SMB dialect negotiation, with the connection using **SMB 3.1.1** (`0x0311`).
2. An **NTLM** authentication sequence in the captured handshake.
3. An established SMB session followed by encrypted SMB3 application traffic.

The original report recorded an account name and a Session ID; both are intentionally omitted from the public notes. Encrypted SMB3 application data cannot be meaningfully inspected without access to appropriate session material. **Authentication being present is not evidence of a vulnerability.**

Useful Wireshark filters:

```text
tcp.port == 445
smb2
ntlmssp
```

## Case B — Suspicious interactive TCP session

Review of an isolated capture found an interactive TCP connection containing recognizable operating-system command strings. The observed activity was consistent with a **reverse-shell-style interaction** in that closed lab context. The analysis relied on correlated endpoints and readable application payloads, **not** on a particular destination port alone.

Analysis workflow:

1. Identify the two endpoints and transport protocol.
2. Reconstruct the TCP conversation and ordering of packets.
3. Review application payloads only in an authorized isolated environment.
4. Compare findings with host logs and process evidence when available.
5. Record uncertainty: command-like strings can appear in benign or generated captures.

The sample [`tcp-review-demo.pcap`](../captures/demo/tcp-review-demo.pcap) only illustrates endpoint metadata and **does not contain a reverse shell or transmitted commands**. The repository does not include instructions for establishing remote command execution.

## Case C — Simulated packet generation

An introductory packet-crafting exercise used Python and Scapy with a loopback TCP payload. The public adaptation in [`scapy_offline_demo.py`](../src/scapy_offline_demo.py) constructs a harmless example packet and writes it to disk, without sending network traffic. This supports repeatable packet inspection without injecting traffic into an interface.

## Analyst limitations

[`pcap_summary.py`](../src/pcap_summary.py) summarizes Ethernet/IPv4 metadata, well-known ports, flow endpoints and file integrity hash. It is **not** an IDS, a full protocol decoder, a proof of intrusion, or a vulnerability scanner. Do not infer successful login, exploitability, or malicious intent from a port label.
