# Platforms

- iOS: SwiftUI app plus a Network Extension Packet Tunnel Provider entry point. The provider configures IPv4 and IPv6 default routes, DNS interception servers, and a packet loop that classifies TCP, UDP, DNS, and dropped packets.
- Android: Kotlin/Compose app plus `VpnService`. The service establishes IPv4 and IPv6 addresses, default routes, DNS interception servers, and a TUN file-descriptor packet loop.
- macOS: SwiftUI app plus a Network Extension Packet Tunnel Provider source entry point with the same dual-stack route and packet loop shape as iOS.
- Windows: WinUI 3 app plus a Wintun lifecycle and packet-classification adapter. The adapter is ready to bind native Wintun sessions once `wintun.dll` is present at runtime.
- Linux: GTK4/libadwaita app plus `/dev/net/tun` open/ioctl/read glue that feeds packets into `neoncore-tun`.
- Desktop CLI and daemon: Rust binaries for Windows, macOS, and Linux.

The shared packet decision layer lives in `neoncore-tun`, `neoncore-ip-stack`, `neoncore-routing`, and `neoncore-dns`. Platform adapters are responsible for device privileges, OS-specific routes, and foreground/background service lifecycle.
