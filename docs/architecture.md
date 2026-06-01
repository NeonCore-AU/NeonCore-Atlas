# Architecture

NeonCore Atlas separates portable network-client logic from platform-specific UI and VPN/service adapters.

## Atlas Core

`atlas-core` contains pure Rust data models and parsing stubs. It has no OS-specific code, which keeps it usable from desktop daemons, CLIs, mobile adapters, and future FFI bindings.

## Atlas Engine

`atlas-engine` defines the `Engine` trait and `EngineStatus`. The runtime target is the owned `neoncore-kernel` binary, with platform apps and daemons calling it through explicit session files and IPC.

## Atlas API

`atlas-api` defines JSON-serializable request and response types. It intentionally does not implement networking yet. The daemon, CLI, and GUIs can share a stable command vocabulary before IPC is chosen.

The first command vocabulary covers status, connect, disconnect, profiles, nodes, subscriptions, routing rules, DNS updates, rewrite rules, latency testing, traffic statistics, diagnostics, and profile export.

## Desktop Daemon

`atlas-daemon` is the future privileged or background service layer. IPC options under consideration are Unix domain sockets on macOS/Linux, named pipes on Windows, and optional localhost HTTP/gRPC for developer tooling.

## Native GUIs

Each platform uses its native UI toolkit: SwiftUI, Jetpack Compose, WinUI 3, and GTK4/libadwaita. GUI apps should communicate with the daemon or mobile VPN adapter rather than embedding platform service code in views.

## Mobile VPN Adapters

The iOS Packet Tunnel Provider and Android `VpnService` adapters are intentionally thin. Tunnel lifecycle, profile validation, DNS, routing, and permission handling belong behind testable platform boundaries.
