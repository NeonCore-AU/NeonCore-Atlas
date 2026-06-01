# Capability Model

NeonCore Atlas models advanced network-client features without implementing real tunnelling in this scaffold.

## Profiles and Subscriptions

Profiles group nodes, subscriptions, routing settings, DNS settings, and rewrite rules. Subscriptions support replace, merge, and keep-existing update strategies so future importers can handle duplicate nodes predictably.

## Nodes and Protocols

Nodes carry endpoint, protocol, tags, UDP support, and TLS support metadata. The current protocol enum covers common neutral categories and leaves a custom protocol escape hatch for future adapters.

## Routing Rules

Routing rules match domains, domain suffixes, domain keywords, CIDR ranges, country codes, or user agents. Actions can proxy through a selected node, connect directly, or reject traffic.

## DNS

The DNS model supports system DNS, remote DNS, and parallel fastest-response modes. DNS servers can be UDP, TCP, HTTPS, TLS, or QUIC. Host overrides are represented separately.

## Rewrites

Rewrite rules are stored as enabled pattern/replacement pairs. They are data only in this scaffold; runtime request modification belongs in a future engine adapter with explicit user consent and platform policy review.

## Diagnostics and Stats

The API includes latency test results, traffic counters, and diagnostic reports with stable message keys for localization.
