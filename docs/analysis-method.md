# Lab methodology and validation

## Where the information comes from

The portfolio contains three distinct kinds of artifacts:

| Type | Included | Interpretation |
| --- | --- | --- |
| Review notes | Protocol/VLAN/OSPF/SMB/TCP Markdown files | Redacted observations and conclusions from earlier hands-on labs |
| Network topology templates | Two `.gns3` JSON project files | Sanitized node-and-link layouts, not complete runnable device state |
| Synthetic examples | Seven generated PCAPs plus Python scripts | Newly created public demonstration data; not historical packet evidence |

The protocol analyzer and testing utilities were added as an enhancement for a reproducible public project. They should not be presented as the exact code used for the earlier manual investigations.

## Evidence and independent verification

- Protocol identification is based on headers and ports; source reports were manually compared with protocol documentation and traffic views.
- VLAN hardening decisions were evaluated against the device's supported command list. For example, commands supported on newer switch platforms were not blindly copied onto an older EtherSwitch module.
- OSPF topology verification relied on neighbor-state (`FULL`), route-table and connectivity checks, not only on configuration text.
- An AI assistant was used for suggestions during earlier network labs, but proposed configurations were reviewed and checked against actual device output. AI output was not accepted as independent proof of security.
- Observations from private traffic are described in general terms. Original packet files are not reproduced.

## Reproduction and boundaries

`make test` verifies the public Python tooling and topology syntax; it **does not** launch the GNS3 projects, establish live OSPF neighbors, validate real Cisco CLI behavior or replay historical network recordings.

For hands-on reproduction, open a GNS3 topology in an authorized lab, supply your own device image, apply commands that match your platform and compare live `show` output. Use offline synthetic packet samples for Wireshark exercises without sending traffic to any external host.
