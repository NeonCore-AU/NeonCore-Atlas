import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String : NSObject]?) async throws {
        // Future work: start Atlas tunnel engine through Network Extension APIs.
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        // Future work: stop tunnel and persist final connection state.
    }
}
