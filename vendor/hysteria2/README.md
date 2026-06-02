# hysteria2

Vendored Rust client components for Hysteria 2 support inside NeonCore Atlas.

This copy is kept in-tree so NeonCore can tune QUIC transport behavior, UDP session handling, pacing, padding, and reconnect behavior together with the kernel adapter. It is treated as an internal dependency of the NeonCore networking runtime.

## Capabilities

- Hysteria 2 authentication over HTTP/3.
- TCP stream setup over QUIC.
- UDP message framing and session management.
- QUIC datagram transport.
- Salamander and Gecko obfuscation hooks.
- Reconnectable client behavior for unstable paths.
- Tunable congestion-control integration.

## Notes

This vendored package is not the public entry point for NeonCore Atlas. See the repository root README for product-level architecture, build instructions, and contribution guidelines.
