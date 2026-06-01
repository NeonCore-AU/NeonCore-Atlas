# Capability Model

NeonCore Atlas is moving from product scaffolding into an owned networking runtime. The macOS app imports real subscriptions and starts the in-repository kernel for protocols that the kernel marks as available.

## Profiles and Subscriptions

Profiles group nodes, subscriptions, routing settings, DNS settings, and rewrite rules. Subscriptions support replace, merge, and keep-existing update strategies so future importers can handle duplicate nodes predictably.

## Nodes and Protocols

Nodes carry endpoint, protocol, tags, UDP support, and TLS support metadata. The subscription importer preserves protocol parameters so the owned `neoncore-kernel` can consume exact node settings through its session schema.

## Routing Rules

Routing rules match domains, domain suffixes, domain keywords, and CIDR ranges inside `neoncore-kernel`. Actions can proxy through a selected node, connect directly, or reject traffic. Country-code and user-agent matching remain part of the portable profile model and are not runtime kernel matchers yet.

## DNS

The kernel resolver supports host overrides, system lookups, and IPv6 preference ordering. The portable model also represents remote DNS servers and parallel fastest-response mode; those remote resolver transports are not runtime kernel transports yet.

## TUN and VPN

The workspace includes first-pass packet-decision crates for system-level proxy clients:

1. `neoncore-ip-stack` parses IPv4 and IPv6 packets and extracts TCP/UDP flow metadata.
2. `neoncore-routing` applies IPv4/IPv6-aware routing rules to flow metadata.
3. `neoncore-dns` detects DNS flows and identifies DNS queries for interception.
4. `neoncore-tun` combines packet parsing, DNS interception, and routing into TCP/UDP forward/drop decisions.

Platform device adapters are still separate follow-up work: iOS and macOS Network Extension, Android VPNService, Windows Wintun, and Linux tun/tap.

## Rewrites

Rewrite rules are stored as enabled pattern/replacement pairs. They are data only in this scaffold; runtime request modification belongs in a future engine adapter with explicit user consent and platform policy review.

## Diagnostics and Stats

The API includes latency test results, traffic counters, and diagnostic reports with stable message keys for localization.

## Owned Kernel

`neoncore-kernel` is the in-repository networking runtime. It currently owns the async TCP runtime, local SOCKS5 and HTTP proxy listeners, session validation, bidirectional TCP relay infrastructure, DNS host mapping, rule-based routing, kernel session schema, structured logs, and protocol adapter boundaries. Protocol transport adapters are implemented inside this crate rather than by downloading external cores.

Current adapter status:

1. Direct TCP relay is available through the local SOCKS5 listener.
2. HTTP CONNECT inbound and HTTP proxy outbound are available.
3. VLESS TCP with no encrypted transport has request framing, response-header handling, and local adapter tests.
4. Hysteria2 configuration parsing, Salamander datagram obfuscation, TCP request/response framing, and UDP message framing are covered by tests.
5. VLESS Reality configuration parsing and TCP request framing are covered by tests.
6. Hysteria2 QUIC transport, VLESS encrypted transports, and AnyTLS are not marked available until their transport handshakes are implemented.
