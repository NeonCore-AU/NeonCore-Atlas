import Foundation
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var packetTask: Task<Void, Never>?
    private let classifier = PacketClassifier()

    override func startTunnel(options: [String : NSObject]?) async throws {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")
        settings.ipv4Settings = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.0"])
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        settings.ipv6Settings = NEIPv6Settings(addresses: ["fd7a:115c:a1e0::2"], networkPrefixLengths: [64])
        settings.ipv6Settings?.includedRoutes = [NEIPv6Route.default()]
        settings.dnsSettings = NEDNSSettings(servers: ["198.18.0.1", "fd7a:115c:a1e0::1"])
        try await setTunnelNetworkSettings(settings)
        packetTask = Task { await runPacketLoop() }
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        packetTask?.cancel()
        packetTask = nil
        try? await setTunnelNetworkSettings(nil)
    }

    private func runPacketLoop() async {
        while !Task.isCancelled {
            let packets = await readPackets()
            for packet in packets {
                switch classifier.classify(packet) {
                case .tcp:
                    handleTcp(packet)
                case .udp:
                    handleUdp(packet)
                case .dns:
                    handleDns(packet)
                case .drop:
                    continue
                }
            }
        }
    }

    private func readPackets() async -> [Data] {
        await withCheckedContinuation { continuation in
            packetFlow.readPackets { packets, _ in
                continuation.resume(returning: packets)
            }
        }
    }

    private func handleTcp(_ packet: Data) {
        _ = packet
    }

    private func handleUdp(_ packet: Data) {
        _ = packet
    }

    private func handleDns(_ packet: Data) {
        _ = packet
    }
}

private enum PacketDecision {
    case tcp
    case udp
    case dns
    case drop
}

private struct PacketClassifier {
    func classify(_ packet: Data) -> PacketDecision {
        guard let first = packet.first else { return .drop }
        switch first >> 4 {
        case 4:
            return classifyIPv4(packet)
        case 6:
            return classifyIPv6(packet)
        default:
            return .drop
        }
    }

    private func classifyIPv4(_ packet: Data) -> PacketDecision {
        guard packet.count >= 20 else { return .drop }
        let headerLength = Int(packet[0] & 0x0f) * 4
        guard headerLength >= 20, packet.count >= headerLength else { return .drop }
        return classifyTransport(protocolNumber: packet[9], payload: packet.dropFirst(headerLength))
    }

    private func classifyIPv6(_ packet: Data) -> PacketDecision {
        guard packet.count >= 40 else { return .drop }
        return classifyTransport(protocolNumber: packet[6], payload: packet.dropFirst(40))
    }

    private func classifyTransport(protocolNumber: UInt8, payload: Data.SubSequence) -> PacketDecision {
        switch protocolNumber {
        case 6:
            return .tcp
        case 17:
            guard payload.count >= 8 else { return .drop }
            let destinationPort = UInt16(payload[payload.startIndex + 2]) << 8 | UInt16(payload[payload.startIndex + 3])
            return destinationPort == 53 ? .dns : .udp
        default:
            return .drop
        }
    }
}
