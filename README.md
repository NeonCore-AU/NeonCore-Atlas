# NeonCore Atlas

NeonCore Atlas is an open-source advanced network client scaffold for desktop and mobile platforms. It is designed for native apps, shared Rust core logic, and future pluggable proxy/VPN engine support, while keeping the first version focused on long-term architecture instead of production VPN or proxy tunneling.

Atlas does not include paid service credentials, analytics, telemetry, or real traffic tunneling in this initial scaffold.

## Architecture

```mermaid
flowchart TD
    GUI[Native platform GUIs] --> API[atlas-api types]
    CLI[atlas CLI] --> API
    API --> Daemon[atlas-daemon]
    Daemon --> Engine[atlas-engine]
    Engine --> Core[atlas-core]
    Mobile[iOS Packet Tunnel / Android VpnService placeholders] --> Core
```

- `atlas-core`: pure Rust profile, node, subscription, routing, and state models.
- `atlas-engine`: engine abstraction with a mock implementation, ready for future pluggable engine integration.
- `atlas-api`: serde-compatible local API request and response types shared by CLI, daemon, and GUIs.
- `atlas-daemon`: desktop service process scaffold for Windows, macOS, and Linux.
- `atlas-cli`: cross-platform command-line client with localized output.
- Native apps: SwiftUI for Apple platforms, Kotlin/Compose for Android, WinUI 3 for Windows, GTK4/libadwaita for Linux.

## Platform Matrix

| Platform | UI | VPN/service integration | Status |
| --- | --- | --- | --- |
| iOS | SwiftUI | Network Extension Packet Tunnel Provider | Scaffold |
| Android | Kotlin + Jetpack Compose | Android `VpnService` | Scaffold |
| macOS | SwiftUI | Network Extension/helper | Scaffold |
| Windows | WinUI 3 / Windows App SDK | Windows Service, Wintun later | Scaffold |
| Linux | GTK4 + libadwaita | systemd service, TUN later | Scaffold |
| Desktop CLI | Rust + clap | Talks to daemon later | Mocked |

## Internationalization

English (Australia) (`en-AU`) is the source language. Initial locales are `en-AU`, `zh-Hans`, and pseudolocale `en-XA`. Production UI, CLI, daemon status, errors, accessibility labels, and tooltips should use localization resources from the first commit. See [i18n/README.md](i18n/README.md).

## Build

```sh
cargo test --workspace
cargo run -p atlas-cli -- status
cargo run -p atlas-daemon -- health
```

Platform app folders contain native project skeletons and local README files where additional SDK tooling is required.

## Current Status

This repository is a real starting scaffold. It compiles the Rust workspace, includes models and tests, and demonstrates native UI/i18n structure. It does not implement real proxy, VPN, TUN, firewall, subscription protocol parsing, or daemon IPC yet.
