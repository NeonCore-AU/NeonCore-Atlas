# Protocol Support

NeonCore Atlas is building protocol support inside `neoncore-kernel`, the in-repository Rust networking runtime.

## Implemented or Actively Wired

| Area | Status |
| --- | --- |
| Direct TCP | Available through the local inbound runtime. |
| SOCKS5 inbound | Available for TCP connect and UDP associate test paths. |
| HTTP inbound | Available for HTTP CONNECT. |
| HTTP outbound | Available for upstream HTTP proxy connections. |
| DNS | Host overrides, proxy bootstrap resolution, IPv4/IPv6 preference, and cache behavior are covered by tests. |
| Routing | Domain, suffix, keyword, and CIDR matching with proxy/direct/reject actions. |
| Shadowsocks AEAD/2022 | Adapter validation and outbound support are implemented through the kernel adapter boundary. |
| VLESS | TCP, TLS, REALITY, WS, gRPC, H2, HTTPUpgrade, XHTTP, UDP, XUDP, and mux-oriented paths are under active implementation with unit coverage for framing and config. |
| AnyTLS | TCP relay, session pooling, and UDP-over-TCP packet connection work are implemented in the adapter path. |
| Hysteria2 | QUIC session, TCP/UDP framing, datagram handling, reconnectable clients, obfuscation, and custom pacing work live in the kernel/vendor runtime path. |

## Engineering Requirements

Protocol changes should include:

- configuration validation
- no hard-coded production credentials
- structured errors and logs
- unit or integration tests for framing and connection behavior
- platform capability notes when behavior differs across operating systems

Protocol implementations should remain owned by the NeonCore codebase rather than relying on downloaded runtime binaries.
