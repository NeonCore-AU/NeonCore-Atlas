# Capability Model

NeonCore Atlas combines native apps, shared Rust models, and the owned `neoncore-kernel` networking runtime.

## Profiles and Subscriptions

Profiles group nodes, subscriptions, routing settings, DNS settings, and rewrite rules. Subscription importers preserve protocol parameters so the kernel can consume exact node settings through its session schema.

## Nodes and Protocols

Nodes carry endpoint, protocol, tags, UDP support, and TLS support metadata. Kernel adapters validate node configuration before a session starts.

## Routing Rules

Routing rules match domains, domain suffixes, domain keywords, and CIDR ranges inside `neoncore-kernel`. Actions can proxy through a selected node, connect directly, or reject traffic.

## DNS

The kernel resolver supports host overrides, system lookups, IPv6 preference ordering, proxy bootstrap resolution, and cache behavior. DNS interception primitives live in `neoncore-dns` for system-level routing paths.

## TUN and VPN

The workspace includes packet-decision crates for system-level clients:

1. `neoncore-ip-stack` parses IPv4 and IPv6 packets and extracts TCP/UDP flow metadata.
2. `neoncore-routing` applies IPv4/IPv6-aware routing rules to flow metadata.
3. `neoncore-dns` detects DNS flows and identifies DNS queries for interception.
4. `neoncore-tun` combines packet parsing, DNS interception, and routing into TCP/UDP forward/drop decisions.

Platform device adapters remain platform-specific: iOS and macOS Network Extension, Android VPNService, Windows Wintun, and Linux tun/tap.

## Diagnostics and Stats

The API includes latency test results, traffic counters, structured log events, and diagnostic reports with stable message keys for localization.

## Owned Kernel

`neoncore-kernel` owns the async TCP runtime, local SOCKS5 and HTTP proxy listeners, session validation, bidirectional relay infrastructure, DNS host mapping, rule-based routing, kernel session schema, structured logs, and protocol adapter boundaries.

Current runtime areas include direct TCP, HTTP, Shadowsocks AEAD/2022, VLESS transports and mux paths, AnyTLS, and Hysteria2-oriented QUIC work. Capability flags should reflect actual adapter readiness and tests.
