# GNS3 topology templates

These files preserve the **node/link layout** of two educational network scenarios:

- `vlan-segmentation.gns3`: two switches, four PCs, 802.1Q trunk link;
- `ospf-chain.gns3`: three routers connected in a chain.

Device images and runtime state are not included. The GNS3 files reference a particular Cisco device platform and will require a separately obtained **legally licensed compatible image**. They are topology templates, **not** ready-to-run saved sessions. All source task names, platform hashes, system IDs and source-specific project identifiers have been removed or replaced for publication.

The illustrative configs under [`../../configs`](../../configs/) provide a starting point; check every command against the IOS/platform version you actually use. Never paste placeholder secrets into a real network.
