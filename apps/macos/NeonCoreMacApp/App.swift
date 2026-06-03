import Foundation
import Network
import CoreText
import SwiftUI

@main
struct NeonCoreMacApp: App {
    init() {
        NeonCoreFont.register()
        AppRuntime.writeBuildMarker()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 1120, minHeight: 720)
        }
        .windowStyle(.hiddenTitleBar)
    }
}

private enum NeonCorePage: String, CaseIterable, Identifiable {
    case dashboard
    case nodes
    case profiles
    case routing
    case logs
    case diagnostics
    case settings

    var id: String { rawValue }
    var titleKey: String { "nav.\(rawValue)" }
    var symbol: String {
        switch self {
        case .dashboard: "gauge.with.dots.needle.bottom.50percent"
        case .nodes: "network"
        case .profiles: "rectangle.stack"
        case .routing: "arrow.triangle.branch"
        case .logs: "list.bullet.rectangle"
        case .diagnostics: "waveform.path.ecg"
        case .settings: "gearshape"
        }
    }
}

private enum ConnectionStatus {
    case disconnected
    case connected
}

@MainActor
private final class NeonCoreStore: ObservableObject {
    @Published var selectedPage: NeonCorePage = .dashboard
    @Published var status: ConnectionStatus = .disconnected
    @Published var activeNodeID: UUID?
    @Published var subscriptionURL = "" {
        didSet { PersistedStore.saveSubscriptionURL(subscriptionURL) }
    }
    @Published var routingMode = "Rule"
    @Published var dnsMode = "System"
    @Published var preferIPv6 = false
    @Published var proxyBytesIn = 0
    @Published var proxyBytesOut = 0
    @Published var directBytesIn = 0
    @Published var directBytesOut = 0
    @Published var lastLatencyRun = "--"
    @Published var localProxyPort = 19091
    @Published var showingManualNodeEditor = false
    @Published var manualNodeDraft = ManualNodeDraft()
    @Published var kernelCapabilities = KernelCapabilitySchema.fallback
    @Published var logs: [NeonCoreLog] = [
        .init(level: "info", messageKey: "log.app_ready"),
    ]
    @Published var nodes: [NeonCoreNode] = [] {
        didSet { PersistedStore.saveNodes(nodes) }
    }
    @Published var profiles: [NeonCoreProfile] = [] {
        didSet { PersistedStore.saveProfiles(profiles) }
    }
    @Published var rules: [NeonCoreRule] = []

    private let engine = NeonCoreKernel()

    init() {
        subscriptionURL = PersistedStore.loadSubscriptionURL()
        nodes = PersistedStore.loadNodes()
        profiles = PersistedStore.loadProfiles()
        activeNodeID = nodes.first?.id
        kernelCapabilities = engine.loadCapabilities() ?? .fallback
    }

    var activeNode: NeonCoreNode? {
        nodes.first { $0.id == activeNodeID } ?? nodes.first
    }

    var statusKey: String {
        status == .connected ? "connection.status.connected" : "connection.status.disconnected"
    }

    func toggleConnection() {
        if status == .connected {
            disconnect()
        } else {
            connect()
        }
    }

    func selectNode(_ node: NeonCoreNode) {
        activeNodeID = node.id
        connect()
    }

    func importSubscription() async {
        let value = subscriptionURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.hasPrefix("https://") || value.hasPrefix("http://") else {
            log("subscription.import.error_invalid_url", level: "warn")
            return
        }
        do {
            let importedNodes = try await SubscriptionParser.fetch(urlString: value)
            nodes = importedNodes
            activeNodeID = importedNodes.first?.id
            profiles = [.init(name: "Imported Subscription", detail: "\(importedNodes.count) nodes")]
            log("subscription.import.success")
        } catch {
            log("subscription.import.error_failed", level: "warn")
        }
    }

    func addManualNode() {
        do {
            let node = try manualNodeDraft.makeNode()
            upsert(node: node)
            manualNodeDraft = ManualNodeDraft()
            showingManualNodeEditor = false
            log("log.manual_node_added")
        } catch {
            AppRuntime.appendDiagnostic("manual node rejected: \(error)")
            log("log.manual_node_invalid", level: "warn")
        }
    }

    func importManualNodeURI() {
        do {
            let node = try manualNodeDraft.makeNodeFromURI()
            upsert(node: node)
            manualNodeDraft = ManualNodeDraft()
            showingManualNodeEditor = false
            log("log.manual_node_added")
        } catch {
            AppRuntime.appendDiagnostic("manual node URI rejected: \(error)")
            log("log.manual_node_invalid", level: "warn")
        }
    }

    func removeNode(_ node: NeonCoreNode) {
        nodes.removeAll { $0.id == node.id }
        if activeNodeID == node.id {
            activeNodeID = nodes.first?.id
        }
        log("log.manual_node_removed")
    }

    func testLatency() async {
        for index in nodes.indices {
            let start = Date()
            let reachable = await TCPProbe.check(host: nodes[index].host, port: nodes[index].port, timeout: 3)
            nodes[index].latency = reachable ? max(1, Int(Date().timeIntervalSince(start) * 1000)) : nil
        }
        lastLatencyRun = Date.now.formatted(date: .omitted, time: .shortened)
        log("log.latency_completed")
    }

    func addRule() {
        log("log.rules_runtime_managed", level: "warn")
    }

    func runDiagnostics() async {
        log(engine.isAvailable ? "log.engine_available" : "log.engine_missing", level: engine.isAvailable ? "info" : "warn")
        if let node = activeNode {
            let reachable = await TCPProbe.check(host: node.host, port: node.port, timeout: 3)
            log(reachable ? "log.node_reachable" : "log.node_unreachable", level: reachable ? "info" : "warn")
        }
        log("log.diagnostics_completed")
    }

    func clearLogs() {
        logs.removeAll()
    }

    func log(_ messageKey: String, level: String = "info") {
        logs.insert(.init(level: level, messageKey: messageKey), at: 0)
    }

    private func connect() {
        guard let node = activeNode else {
            log("nodes.empty.title", level: "warn")
            return
        }
        guard node.hasRequiredCredentials else {
            AppRuntime.appendDiagnostic("connection rejected before kernel start: missing credentials for \(node.protocolName) \(node.endpoint)")
            log("log.engine_start_failed", level: "warn")
            return
        }
        do {
            try engine.start(node: node, port: localProxyPort, fullTunnel: true)
            guard ProxyProbe.httpConnect(port: localProxyPort, timeout: 30) else {
                AppRuntime.appendDiagnostic("proxy preflight failed for \(node.protocolName) \(node.endpoint)")
                throw NeonCoreError.proxyPreflightFailed
            }
            try SystemProxy.enable(port: localProxyPort)
            status = .connected
            activeNodeID = node.id
            log("log.connected")
        } catch {
            AppRuntime.appendDiagnostic("connection failed for \(node.protocolName) \(node.endpoint): \(error)")
            try? SystemProxy.disable()
            engine.stop()
            status = .disconnected
            log(logKey(for: error), level: "warn")
        }
    }

    private func logKey(for error: Error) -> String {
        guard let error = error as? NeonCoreError else {
            return "log.engine_start_failed"
        }
        switch error {
        case .engineMissing:
            return "log.engine_missing"
        case .unsupportedProtocol:
            return "log.protocol_adapter_missing"
        case .kernelCheckFailed, .listenerUnavailable:
            return "log.engine_start_failed"
        case .proxyPreflightFailed:
            return "log.proxy_preflight_failed"
        case .invalidURL, .subscriptionFailed, .systemProxyFailed, .tunBridgeMissing, .tunBridgeFailed, .tunRouteConflict, .invalidManualNode:
            return "log.engine_start_failed"
        }
    }

    private func disconnect() {
        engine.stop()
        try? SystemProxy.disable()
        status = .disconnected
        log("log.disconnected")
    }

    private func upsert(node: NeonCoreNode) {
        if let index = nodes.firstIndex(where: { $0.id == node.id }) {
            nodes[index] = node
        } else {
            nodes.append(node)
        }
        activeNodeID = node.id
        if profiles.isEmpty {
            profiles = [.init(name: "Manual Nodes", detail: "\(nodes.count) nodes")]
        }
    }
}

private struct NeonCoreNode: Identifiable, Codable {
    var id = UUID()
    var name: String
    var region: String
    var host: String
    var port: Int
    var userID: String
    var protocolName: String
    var query: [String: String]
    var latency: Int?
    var tags: [String]

    var endpoint: String {
        "\(host):\(port)"
    }

    var hasRequiredCredentials: Bool {
        if protocolName == "hysteria2" || protocolName == "hy2" {
            return !userID.isEmpty
        }
        return true
    }
}

private enum ManualNodeProtocol: String, CaseIterable, Identifiable {
    case vless
    case hysteria2
    case anytls
    case shadowsocks
    case shadowsocksr
    case http
    case direct

    var id: String { rawValue }

    var title: String {
        switch self {
        case .vless: "VLESS"
        case .hysteria2: "Hysteria2"
        case .anytls: "AnyTLS"
        case .shadowsocks: "Shadowsocks"
        case .shadowsocksr: "SSR / ShadowsocksR"
        case .http: "HTTP"
        case .direct: "Direct"
        }
    }

    var credentialLabel: String {
        switch self {
        case .vless: "UUID"
        case .hysteria2: "Auth"
        case .anytls: "Password"
        case .shadowsocks: "Password"
        case .shadowsocksr: "Password"
        case .http: "Username"
        case .direct: "Credential"
        }
    }

    var defaultPort: Int {
        switch self {
        case .vless, .anytls: 443
        case .hysteria2: 443
        case .shadowsocks: 8388
        case .shadowsocksr: 8388
        case .http: 8080
        case .direct: 0
        }
    }
}

private struct ManualNodeDraft {
    var uri = ""
    var name = ""
    var protocolName: ManualNodeProtocol = .vless
    var host = ""
    var port = "443"
    var credential = ""
    var security = "reality"
    var transport = "tcp"
    var flow = "xtls-rprx-vision"
    var sni = ""
    var publicKey = ""
    var shortID = ""
    var fingerprint = "chrome"
    var transportHost = ""
    var transportPath = "/"
    var serviceName = "Tun"
    var authority = ""
    var xhttpMode = "auto"
    var httpVersion = "auto"
    var scMaxEachPostBytes = "262144"
    var scMinPostsIntervalMs = "0"
    var xmuxMaxConcurrency = "0"
    var xmuxMaxConnections = "0"
    var xmuxCMaxReuseTimes = "0"
    var xmuxHMaxRequestTimes = "0"
    var xmuxHMaxReusableSecs = "0"
    var method = "2022-blake3-aes-256-gcm"
    var plugin = ""
    var tcpFastOpen = false
    var udpRelay = true
    var udpOverTcp = false
    var ssObfuscation = "none"
    var ssObfuscationTLS = false
    var ssPluginMode = "websocket"
    var ssPluginHost = ""
    var ssPluginPath = "/"
    var ssPluginHeaders = ""
    var ssPluginTLS = false
    var ssPluginMux = true
    var ssPluginSkipCertVerify = false
    var ssPluginFingerprint = ""
    var ssPluginCertificate = ""
    var ssPluginPrivateKey = ""
    var ssPluginECHConfig = ""
    var ssPluginECHQueryServerName = ""
    var ssPluginHTTPUpgrade = false
    var ssPluginHTTPUpgradeFastOpen = false
    var kcpKey = ""
    var kcpCrypt = "aes"
    var kcpMode = "fast"
    var kcpConn = "1"
    var kcpAutoExpire = "0"
    var kcpScavengeTTL = "600"
    var kcpMTU = "1350"
    var kcpRateLimit = "0"
    var kcpSndWnd = "128"
    var kcpRcvWnd = "512"
    var kcpDataShard = "10"
    var kcpParityShard = "3"
    var kcpDSCP = "0"
    var kcpNoDelay = "0"
    var kcpInterval = "50"
    var kcpResend = "0"
    var kcpSockBuf = "4194304"
    var kcpSmuxVer = "1"
    var kcpSmuxBuf = "4194304"
    var kcpFrameSize = "8192"
    var kcpStreamBuf = "2097152"
    var kcpKeepAlive = "10"
    var kcpNoComp = false
    var kcpAckNoDelay = false
    var kcpNoCongestion = false
    var shadowTLSVersion = "2"
    var shadowTLSPassword = ""
    var shadowTLSHost = ""
    var shadowTLSALPN = ""
    var ssrProtocol = "origin"
    var ssrProtocolParam = ""
    var obfs = ""
    var obfsPassword = ""
    var obfsHost = ""
    var mport = ""
    var udpTimeoutMs = "30000"
    var bbrProfile = "auto"
    var idleSessionTimeout = "30s"
    var minIdleSession = "0"
    var insecure = false

    mutating func applyProtocolDefaults() {
        port = String(protocolName.defaultPort)
        switch protocolName {
        case .vless:
            security = "reality"
            transport = "tcp"
            flow = "xtls-rprx-vision"
            transportHost = ""
            transportPath = "/"
            serviceName = "Tun"
            authority = ""
            xhttpMode = "auto"
            httpVersion = "auto"
            scMaxEachPostBytes = "262144"
            scMinPostsIntervalMs = "0"
            xmuxMaxConcurrency = "0"
            xmuxMaxConnections = "0"
            xmuxCMaxReuseTimes = "0"
            xmuxHMaxRequestTimes = "0"
            xmuxHMaxReusableSecs = "0"
        case .hysteria2:
            security = ""
            transport = ""
            flow = ""
            mport = ""
            udpTimeoutMs = "30000"
            bbrProfile = "auto"
        case .anytls:
            security = "tls"
            transport = "tcp"
            flow = ""
            idleSessionTimeout = "30s"
            minIdleSession = "0"
        case .shadowsocks:
            security = ""
            transport = ""
            flow = ""
            method = "2022-blake3-aes-256-gcm"
            tcpFastOpen = false
            udpRelay = true
            udpOverTcp = false
            plugin = ""
            ssObfuscation = "none"
            ssObfuscationTLS = false
            applyPluginDefaults()
        case .shadowsocksr:
            security = ""
            transport = ""
            flow = ""
            method = "aes-256-cfb"
            tcpFastOpen = false
            udpRelay = true
            udpOverTcp = false
            ssrProtocol = "origin"
            obfs = "plain"
            obfsHost = ""
        case .http:
            security = ""
            transport = "tcp"
            flow = ""
        case .direct:
            security = "none"
            transport = "tcp"
            flow = ""
        }
    }

    mutating func applyPluginDefaults() {
        let normalizedPlugin = plugin.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch normalizedPlugin {
        case "v2ray-plugin":
            ssObfuscation = "none"
            ssPluginMode = "websocket"
            if ssPluginPath.isEmpty { ssPluginPath = "/" }
            ssPluginMux = true
        case "gost", "gost-plugin":
            ssObfuscation = "none"
            ssPluginMode = "websocket"
            if ssPluginPath.isEmpty { ssPluginPath = "/" }
            ssPluginMux = true
        case "shadow-tls", "shadow_tls":
            ssObfuscation = "none"
            if shadowTLSVersion.isEmpty { shadowTLSVersion = "2" }
        case "cloak", "ck-client":
            ssObfuscation = "none"
            if ssPluginCertificate.isEmpty { ssPluginCertificate = "ck-client" }
        case "kcptun":
            ssObfuscation = "none"
            if kcpCrypt.isEmpty { kcpCrypt = "aes" }
            if kcpMode.isEmpty { kcpMode = "fast" }
        case "obfs-local", "simple-obfs", "simple_obfs":
            if ssObfuscation == "none" { ssObfuscation = "http" }
        default:
            ssObfuscation = "none"
            break
        }
        if !normalizedPlugin.isEmpty && normalizedPlugin != "none" {
            udpOverTcp = true
        }
    }

    mutating func applySSRObfsDefaults() {
        switch obfs.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "http_simple", "http_post", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
            if obfsHost.isEmpty { obfsHost = host }
        default:
            break
        }
    }

    var supportsCertificateVerificationSkip: Bool {
        switch protocolName {
        case .vless, .hysteria2, .anytls:
            true
        case .shadowsocks, .shadowsocksr, .http, .direct:
            false
        }
    }

    var hasUnsupportedPendingSelection: Bool {
        guard protocolName == .shadowsocks else { return false }
        let normalizedPlugin = plugin.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let normalizedMode = ssPluginMode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch normalizedPlugin {
        case "v2ray-plugin", "gost", "gost-plugin":
            return !normalizedMode.isEmpty && normalizedMode != "websocket"
        case "external-sip003", "external_sip003", "sip003":
            return ssPluginCertificate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        default:
            return false
        }
    }

    var shadowsocksPluginForcesUoT: Bool {
        false
    }

    var shouldShowShadowsocksObfuscationTLS: Bool {
        guard protocolName == .shadowsocks,
              plugin.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return false }
        let normalized = ssObfuscation.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ["websocket", "ws", "httpupgrade", "http_upgrade", "h2", "xhttp"].contains(normalized)
    }

    var shouldShowShadowsocksXHTTPFields: Bool {
        guard protocolName == .shadowsocks,
              plugin.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return false }
        return ssObfuscation.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "xhttp"
    }

    func makeNodeFromURI() throws -> NeonCoreNode {
        guard let node = SubscriptionParser.parseSharedNode(uri.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw NeonCoreError.invalidManualNode
        }
        return node
    }

    func makeNode() throws -> NeonCoreNode {
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedHost.isEmpty else { throw NeonCoreError.invalidManualNode }
        guard let portValue = Int(port.trimmingCharacters(in: .whitespacesAndNewlines)),
              (protocolName == .direct && portValue >= 0) || (portValue > 0 && portValue <= 65535)
        else { throw NeonCoreError.invalidManualNode }

        var query: [String: String] = [:]
        let trimmedSecurity = security.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedTransport = transport.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedFlow = flow.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedSNI = sni.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedPublicKey = publicKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedShortID = shortID.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedFingerprint = fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedTransportHost = transportHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedTransportPath = transportPath.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedServiceName = serviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedAuthority = authority.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedXhttpMode = xhttpMode.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedHTTPVersion = httpVersion.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedScMaxEachPostBytes = scMaxEachPostBytes.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedScMinPostsIntervalMs = scMinPostsIntervalMs.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedXmuxMaxConcurrency = xmuxMaxConcurrency.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedXmuxMaxConnections = xmuxMaxConnections.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedXmuxCMaxReuseTimes = xmuxCMaxReuseTimes.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedXmuxHMaxRequestTimes = xmuxHMaxRequestTimes.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedXmuxHMaxReusableSecs = xmuxHMaxReusableSecs.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedMethod = method.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedPlugin = plugin.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedSSObfuscation = ssObfuscation.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedSSRProtocol = ssrProtocol.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedSSRProtocolParam = ssrProtocolParam.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedObfs = obfs.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedObfsPassword = obfsPassword.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedObfsHost = obfsHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedMport = mport.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedUDPTimeoutMs = udpTimeoutMs.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedBBRProfile = bbrProfile.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedIdleSessionTimeout = idleSessionTimeout.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedMinIdleSession = minIdleSession.trimmingCharacters(in: .whitespacesAndNewlines)

        switch protocolName {
        case .vless:
            guard !credential.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw NeonCoreError.invalidManualNode }
            set(&query, "security", trimmedSecurity)
            set(&query, "type", trimmedTransport)
            set(&query, "flow", trimmedFlow)
            set(&query, "sni", trimmedSNI)
            set(&query, "pbk", trimmedPublicKey)
            set(&query, "sid", trimmedShortID)
            set(&query, "fp", trimmedFingerprint)
            set(&query, "host", trimmedTransportHost)
            set(&query, "path", trimmedTransportPath)
            set(&query, "serviceName", trimmedServiceName)
            set(&query, "authority", trimmedAuthority)
            set(&query, "mode", trimmedXhttpMode)
            set(&query, "httpVersion", trimmedHTTPVersion)
            set(&query, "scMaxEachPostBytes", trimmedScMaxEachPostBytes)
            set(&query, "scMinPostsIntervalMs", trimmedScMinPostsIntervalMs)
            set(&query, "xmuxMaxConcurrency", trimmedXmuxMaxConcurrency)
            set(&query, "xmuxMaxConnections", trimmedXmuxMaxConnections)
            set(&query, "xmuxCMaxReuseTimes", trimmedXmuxCMaxReuseTimes)
            set(&query, "xmuxHMaxRequestTimes", trimmedXmuxHMaxRequestTimes)
            set(&query, "xmuxHMaxReusableSecs", trimmedXmuxHMaxReusableSecs)
        case .hysteria2:
            guard !credential.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw NeonCoreError.invalidManualNode }
            set(&query, "sni", trimmedSNI)
            set(&query, "obfs", trimmedObfs)
            set(&query, "obfs-password", trimmedObfsPassword)
            set(&query, "mport", trimmedMport)
            set(&query, "udp-timeout-ms", trimmedUDPTimeoutMs)
            set(&query, "bbr-profile", trimmedBBRProfile)
        case .anytls:
            guard !credential.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw NeonCoreError.invalidManualNode }
            set(&query, "sni", trimmedSNI)
            set(&query, "idle_session_timeout", trimmedIdleSessionTimeout)
            set(&query, "min_idle_session", trimmedMinIdleSession)
        case .shadowsocks:
            guard !credential.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw NeonCoreError.invalidManualNode }
            set(&query, "method", trimmedMethod)
            setBool(&query, "tcp-fast-open", tcpFastOpen)
            query["udp-relay"] = udpRelay ? "true" : "false"
            setBool(&query, "udp-over-tcp", udpOverTcp || shadowsocksPluginForcesUoT)
            set(&query, "plugin", trimmedPlugin)
            set(&query, "plugin_opts", shadowsocksPluginOptionsValue())
            if trimmedPlugin.isEmpty {
                set(&query, "obfuscation", trimmedSSObfuscation)
                if shouldShowShadowsocksObfuscationTLS {
                    query["obfuscation-tls"] = ssObfuscationTLS ? "true" : "false"
                    if trimmedSSObfuscation.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "h2" && !ssObfuscationTLS {
                        query["h2c"] = "true"
                    }
                }
                if shouldShowShadowsocksXHTTPFields {
                    set(&query, "plugin_opts", shadowsocksXHTTPObfuscationOptionsValue())
                }
            }
            set(&query, "obfs-host", trimmedObfsHost)
        case .shadowsocksr:
            guard !credential.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw NeonCoreError.invalidManualNode }
            set(&query, "method", trimmedMethod)
            setBool(&query, "tcp-fast-open", tcpFastOpen)
            query["udp-relay"] = udpRelay ? "true" : "false"
            set(&query, "protocol", trimmedSSRProtocol)
            set(&query, "protocol_param", trimmedSSRProtocolParam)
            set(&query, "obfs", trimmedObfs)
            set(&query, "obfs_param", ssrObfsParameterValue())
        case .http:
            break
        case .direct:
            break
        }
        if supportsCertificateVerificationSkip && insecure {
            query["insecure"] = "true"
            query["skip-cert-verify"] = "true"
        }

        let displayName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let finalName = displayName.isEmpty ? "\(protocolName.title) \(trimmedHost)" : displayName
        return NeonCoreNode(
            name: finalName,
            region: SubscriptionParser.region(from: finalName),
            host: trimmedHost,
            port: portValue,
            userID: credential.trimmingCharacters(in: .whitespacesAndNewlines),
            protocolName: protocolName.rawValue,
            query: query,
            latency: nil,
            tags: SubscriptionParser.tagsFor(scheme: protocolName.rawValue, query: query)
        )
    }

    private func shadowsocksPluginOptionsValue() -> String {
        let normalizedPlugin = plugin.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var options: [String] = []

        func append(_ key: String, _ value: String) {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }
            options.append("\(escapePluginOption(key))=\(escapePluginOption(trimmed))")
        }

        func appendFlag(_ key: String, _ enabled: Bool) {
            guard enabled else { return }
            options.append(escapePluginOption(key))
        }

        func appendBool(_ key: String, _ enabled: Bool) {
            guard enabled else { return }
            append(key, "true")
        }

        switch normalizedPlugin {
        case "obfs-local", "simple-obfs", "simple_obfs":
            append("obfs", ssObfuscation == "none" ? "" : ssObfuscation)
            append("obfs-host", obfsHost)
        case "v2ray-plugin":
            append("mode", ssPluginMode)
            append("host", ssPluginHost)
            append("path", ssPluginPath)
            appendBool("tls", ssPluginTLS)
        case "gost", "gost-plugin":
            append("mode", ssPluginMode)
            append("host", ssPluginHost)
            append("path", ssPluginPath)
            appendBool("tls", ssPluginTLS)
        case "shadow-tls", "shadow_tls":
            append("host", shadowTLSHost)
            append("password", shadowTLSPassword)
            append("version", shadowTLSVersion)
            append("alpn", shadowTLSALPN)
            appendBool("skip-cert-verify", ssPluginSkipCertVerify)
        case "cloak", "ck-client", "external-sip003", "external_sip003", "sip003":
            let defaultProgram = normalizedPlugin == "cloak" || normalizedPlugin == "ck-client" ? "ck-client" : ""
            append("program", ssPluginCertificate.isEmpty ? defaultProgram : ssPluginCertificate)
            let rawOptions = ssPluginHeaders.trimmingCharacters(in: .whitespacesAndNewlines)
            if !rawOptions.isEmpty {
                options.append(rawOptions)
            }
        case "kcptun":
            append("key", kcpKey)
            append("crypt", kcpCrypt)
            append("mode", kcpMode)
            append("conn", kcpConn)
            append("autoexpire", kcpAutoExpire)
            append("scavengettl", kcpScavengeTTL)
            append("mtu", kcpMTU)
            append("ratelimit", kcpRateLimit)
            append("sndwnd", kcpSndWnd)
            append("rcvwnd", kcpRcvWnd)
            append("datashard", kcpDataShard)
            append("parityshard", kcpParityShard)
            append("dscp", kcpDSCP)
            appendBool("nocomp", kcpNoComp)
            appendBool("acknodelay", kcpAckNoDelay)
            append("nodelay", kcpNoDelay)
            append("interval", kcpInterval)
            append("resend", kcpResend)
            appendBool("nc", kcpNoCongestion)
            append("sockbuf", kcpSockBuf)
            append("smuxver", kcpSmuxVer)
            append("smuxbuf", kcpSmuxBuf)
            append("framesize", kcpFrameSize)
            append("streambuf", kcpStreamBuf)
            append("keepalive", kcpKeepAlive)
        default:
            appendFlag("", false)
        }

        return options.joined(separator: ";")
    }

    private func shadowsocksXHTTPObfuscationOptionsValue() -> String {
        var options: [String] = []

        func append(_ key: String, _ value: String) {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }
            options.append("\(escapePluginOption(key))=\(escapePluginOption(trimmed))")
        }

        append("mode", xhttpMode)
        append("httpVersion", httpVersion)
        append("scMaxEachPostBytes", scMaxEachPostBytes)
        append("scMinPostsIntervalMs", scMinPostsIntervalMs)
        if ssPluginSkipCertVerify {
            append("skip-cert-verify", "true")
        }

        return options.joined(separator: ";")
    }

    private func ssrObfsParameterValue() -> String {
        let normalizedPlugin = obfs.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let hostValue = obfsHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let headerValue = ssPluginHeaders.trimmingCharacters(in: .whitespacesAndNewlines)
        switch normalizedPlugin {
        case "http_simple", "http_post":
            if headerValue.isEmpty { return hostValue }
            return "\(hostValue)#\(headerValue)"
        case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
            return hostValue
        default:
            return hostValue
        }
    }

    private func escapePluginOption(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: ";", with: "\\;")
            .replacingOccurrences(of: "=", with: "\\=")
    }

    private func set(_ query: inout [String: String], _ key: String, _ value: String) {
        if !value.isEmpty {
            query[key] = value
        }
    }

    private func setBool(_ query: inout [String: String], _ key: String, _ value: Bool) {
        if value {
            query[key] = "true"
        }
    }
}

private struct NeonCoreProfile: Identifiable, Codable {
    var id = UUID()
    var name: String
    var detail: String
}

private struct NeonCoreRule: Identifiable, Codable {
    var id = UUID()
    var name: String
    var matcher: String
    var action: String
    var enabled: Bool
}

private struct NeonCoreLog: Identifiable {
    let id = UUID()
    let time = Date.now
    var level: String
    var messageKey: String
}

private struct ResolvedServer {
    var originalHost: String
    var connectHost: String
}

private struct KernelResolvedServerOutput: Decodable {
    var server: String
    var serverPort: Int
    var addresses: [String]

    private enum CodingKeys: String, CodingKey {
        case server
        case serverPort = "server_port"
        case addresses
    }
}

private struct KernelCapabilitySchema {
    var shadowsocksPlugins: [String]
    var shadowsocksObfuscation: [String]
    var shadowsocksPluginModes: [String]
    var shadowTLSVersions: [String]
    var xhttpModes: [String]
    var httpVersions: [String]
    var ssrObfs: [String]

    static let fallback = KernelCapabilitySchema(
        shadowsocksPlugins: ["", "kcptun", "v2ray-plugin", "gost", "gost-plugin", "shadow-tls", "cloak", "external-sip003"],
        shadowsocksObfuscation: ["none", "http", "tls", "ssl", "h1", "h2", "wss", "websocket", "httpupgrade", "xhttp"],
        shadowsocksPluginModes: ["websocket"],
        shadowTLSVersions: ["1", "2", "3"],
        xhttpModes: ["auto", "stream-one", "stream-up", "packet-up"],
        httpVersions: ["auto", "1.1", "h2", "h3"],
        ssrObfs: ["plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"]
    )

    static func parse(_ data: Data) -> KernelCapabilitySchema? {
        guard
            let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let shadowsocks = root["shadowsocks"] as? [String: Any],
            let shadowsocksr = root["shadowsocksr"] as? [String: Any]
        else { return nil }

        let fallback = KernelCapabilitySchema.fallback
        let pluginMap = shadowsocks["plugins"] as? [String: Any] ?? [:]
        let orderedPlugins = fallback.shadowsocksPlugins.filter { plugin in
            plugin.isEmpty || pluginMap.keys.contains(plugin)
        }
        let pluginModes = pluginMap.values.compactMap { value -> [String]? in
            (value as? [String: Any])?["modes"] as? [String]
        }.flatMap { $0 }
        let sortedPluginModes = Array(Set(pluginModes)).sorted()
        let shadowTLSVersions = (pluginMap["shadow-tls"] as? [String: Any])?["versions"] as? [String]
        let xhttp = shadowsocks["xhttp"] as? [String: Any]

        return KernelCapabilitySchema(
            shadowsocksPlugins: orderedPlugins.isEmpty ? fallback.shadowsocksPlugins : orderedPlugins,
            shadowsocksObfuscation: shadowsocks["obfuscation"] as? [String] ?? fallback.shadowsocksObfuscation,
            shadowsocksPluginModes: sortedPluginModes.isEmpty ? fallback.shadowsocksPluginModes : sortedPluginModes,
            shadowTLSVersions: shadowTLSVersions ?? fallback.shadowTLSVersions,
            xhttpModes: xhttp?["modes"] as? [String] ?? fallback.xhttpModes,
            httpVersions: xhttp?["http_versions"] as? [String] ?? fallback.httpVersions,
            ssrObfs: shadowsocksr["obfs"] as? [String] ?? fallback.ssrObfs
        )
    }
}

private enum AppRuntime {
    private static let runtimeDirectory = URL(fileURLWithPath: "/tmp/neoncore-atlas", isDirectory: true)

    static func writeBuildMarker() {
        try? FileManager.default.createDirectory(at: runtimeDirectory, withIntermediateDirectories: true)
        let marker = """
        build=2026-06-02T16:56:00Z
        port=19091
        runtime=/tmp/neoncore-atlas
        hy2_auth=required_user_password
        """
        try? marker.write(to: runtimeDirectory.appendingPathComponent("app-build.txt"), atomically: true, encoding: .utf8)
    }

    static func appendDiagnostic(_ message: String) {
        try? FileManager.default.createDirectory(at: runtimeDirectory, withIntermediateDirectories: true)
        let line = "\(Date()) \(message)\n"
        let url = runtimeDirectory.appendingPathComponent("app-diagnostics.log")
        if FileManager.default.fileExists(atPath: url.path),
           let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            if let data = line.data(using: .utf8) {
                try? handle.write(contentsOf: data)
            }
        } else {
            try? line.write(to: url, atomically: true, encoding: .utf8)
        }
    }
}

private enum PersistedStore {
    private static let subscriptionKey = "neoncore.subscriptionURL"
    private static let nodesKey = "neoncore.nodes"
    private static let profilesKey = "neoncore.profiles"

    static func loadSubscriptionURL() -> String {
        UserDefaults.standard.string(forKey: subscriptionKey) ?? ""
    }

    static func saveSubscriptionURL(_ value: String) {
        UserDefaults.standard.set(value, forKey: subscriptionKey)
    }

    static func loadNodes() -> [NeonCoreNode] {
        load([NeonCoreNode].self, key: nodesKey) ?? []
    }

    static func saveNodes(_ value: [NeonCoreNode]) {
        save(value, key: nodesKey)
    }

    static func loadProfiles() -> [NeonCoreProfile] {
        load([NeonCoreProfile].self, key: profilesKey) ?? []
    }

    static func saveProfiles(_ value: [NeonCoreProfile]) {
        save(value, key: profilesKey)
    }

    private static func load<T: Decodable>(_ type: T.Type, key: String) -> T? {
        guard let data = UserDefaults.standard.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    private static func save<T: Encodable>(_ value: T, key: String) {
        guard let data = try? JSONEncoder().encode(value) else { return }
        UserDefaults.standard.set(data, forKey: key)
    }
}

private enum SubscriptionParser {
    static func fetch(urlString: String) async throws -> [NeonCoreNode] {
        guard let url = URL(string: urlString) else { throw NeonCoreError.invalidURL }
        var request = URLRequest(url: url)
        request.setValue("NeonCore/0.1 macOS", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw NeonCoreError.subscriptionFailed }
        let body = String(decoding: data, as: UTF8.self)
        let decoded = decodeSubscriptionBody(body)
        return decoded
            .split(whereSeparator: \.isNewline)
            .compactMap { parseSharedNode(String($0)) }
            .filter { $0.host != "127.0.0.1" && $0.port > 1 }
    }

    private static func decodeSubscriptionBody(_ body: String) -> String {
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        let padded = trimmed + String(repeating: "=", count: (4 - trimmed.count % 4) % 4)
        if let data = Data(base64Encoded: padded),
           let decoded = String(data: data, encoding: .utf8),
           decoded.contains("://")
        {
            return decoded
        }
        return body
    }

    static func parseSharedNode(_ line: String) -> NeonCoreNode? {
        if line.lowercased().hasPrefix("ss://") {
            return parseShadowsocksNode(line)
        }
        if line.lowercased().hasPrefix("ssr://") {
            return parseShadowsocksRNode(line)
        }
        guard let components = URLComponents(string: line),
              let scheme = components.scheme?.lowercased(),
              let host = components.host,
              let port = components.port
        else { return nil }

        let userID: String
        if scheme == "hysteria2" || scheme == "hy2" {
            let user = components.percentEncodedUser?.removingPercentEncoding ?? components.user ?? ""
            if let password = components.percentEncodedPassword?.removingPercentEncoding ?? components.password, !password.isEmpty {
                userID = "\(user):\(password)"
            } else {
                userID = user
            }
        } else {
            userID = components.user ?? ""
        }
        let query = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).compactMap { item in
            item.value.map { (item.name, $0) }
        })
        let name = components.percentEncodedFragment?.removingPercentEncoding ?? "\(scheme.uppercased()) \(host)"
        let tags = tagsFor(scheme: scheme, query: query)
        return NeonCoreNode(
            name: name,
            region: region(from: name),
            host: host,
            port: port,
            userID: userID,
            protocolName: scheme,
            query: query,
            latency: nil,
            tags: tags
        )
    }

    private static func parseShadowsocksRNode(_ line: String) -> NeonCoreNode? {
        let encoded = String(line.dropFirst("ssr://".count))
        guard let decoded = decodeUrlSafeBase64(encoded) else { return nil }
        let mainAndQuery = decoded.split(separator: "/?", maxSplits: 1).map(String.init)
        let main = mainAndQuery.first ?? decoded
        let queryText = mainAndQuery.count > 1 ? mainAndQuery[1] : ""
        let fields = main.split(separator: ":", maxSplits: 5).map(String.init)
        guard fields.count == 6,
              let port = Int(fields[1]),
              let password = decodeUrlSafeBase64(fields[5])
        else { return nil }
        let query = parseQueryString(queryText)
        var parameters: [String: String] = [
            "method": fields[3],
            "protocol": fields[2],
            "obfs": fields[4]
        ]
        if let protocolParam = query["protoparam"].flatMap(decodeUrlSafeBase64), !protocolParam.isEmpty {
            parameters["protocol_param"] = protocolParam
        }
        if let obfsParam = query["obfsparam"].flatMap(decodeUrlSafeBase64), !obfsParam.isEmpty {
            parameters["obfs_param"] = obfsParam
        }
        let decodedRemark = query["remarks"].flatMap { decodeUrlSafeBase64($0) }
        let name = decodedRemark?.isEmpty == false ? decodedRemark! : "SSR \(fields[0])"
        return NeonCoreNode(
            name: name,
            region: region(from: name),
            host: fields[0],
            port: port,
            userID: password,
            protocolName: "ssr",
            query: parameters,
            latency: nil,
            tags: tagsFor(scheme: "ssr", query: parameters)
        )
    }

    private static func parseShadowsocksNode(_ line: String) -> NeonCoreNode? {
        let linkComponents = URLComponents(string: line)
        let fragment = linkComponents?.percentEncodedFragment?.removingPercentEncoding
        let extraQuery = Dictionary(uniqueKeysWithValues: (linkComponents?.queryItems ?? []).compactMap { item in
            item.value.map { (item.name, $0) }
        })
        let withoutScheme = String(line.dropFirst("ss://".count))
        let withoutFragment = withoutScheme.split(separator: "#", maxSplits: 1).first.map(String.init) ?? withoutScheme
        let body = withoutFragment.split(separator: "?", maxSplits: 1).first.map(String.init) ?? withoutFragment
        let decodedBody: String
        if body.contains("@") {
            decodedBody = body
        } else {
            let padded = body + String(repeating: "=", count: (4 - body.count % 4) % 4)
            guard let data = Data(base64Encoded: padded),
                  let decoded = String(data: data, encoding: .utf8)
            else { return nil }
            decodedBody = decoded
        }
        guard let at = decodedBody.lastIndex(of: "@") else { return nil }
        let credentials = String(decodedBody[..<at])
        let endpoint = String(decodedBody[decodedBody.index(after: at)...])
        guard let separator = credentials.firstIndex(of: ":") else { return nil }
        let method = String(credentials[..<separator]).removingPercentEncoding ?? String(credentials[..<separator])
        let password = String(credentials[credentials.index(after: separator)...]).removingPercentEncoding ?? String(credentials[credentials.index(after: separator)...])
        guard let authority = URLComponents(string: "neoncore://\(endpoint)"),
              let host = authority.host,
              let port = authority.port
        else { return nil }
        let name = fragment ?? "SS \(host)"
        return NeonCoreNode(
            name: name,
            region: region(from: name),
            host: host,
            port: port,
            userID: password,
            protocolName: "shadowsocks",
            query: extraQuery.merging(["method": method]) { current, _ in current },
            latency: nil,
            tags: ["SS", method.uppercased()]
        )
    }

    private static func decodeUrlSafeBase64(_ value: String) -> String? {
        let normalized = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let padded = normalized + String(repeating: "=", count: (4 - normalized.count % 4) % 4)
        guard let data = Data(base64Encoded: padded) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func parseQueryString(_ query: String) -> [String: String] {
        Dictionary(uniqueKeysWithValues: query.split(separator: "&").compactMap { pair in
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { return nil }
            let key = parts[0].removingPercentEncoding ?? parts[0]
            let value = parts[1].removingPercentEncoding ?? parts[1]
            return (key, value)
        })
    }

    static func tagsFor(scheme: String, query: [String: String]) -> [String] {
        var tags = [scheme.uppercased()]
        if let security = query["security"], security != "none" { tags.append(security.uppercased()) }
        if query["flow"] != nil { tags.append("VISION") }
        if let plugin = query["plugin"], !plugin.isEmpty { tags.append("PLUGIN") }
        if let obfs = query["obfs"], obfs != "plain" { tags.append(obfs.uppercased()) }
        return tags
    }

    static func region(from name: String) -> String {
        let uppercased = name.uppercased()
        if uppercased.contains("🇦🇺") || uppercased.contains(" AU ") || uppercased.contains("[AU]") { return "AU" }
        if uppercased.contains("🇺🇸") || uppercased.contains(" US ") || uppercased.contains("[US]") { return "US" }
        if uppercased.contains("🇯🇵") || uppercased.contains(" JP ") || uppercased.contains("[JP]") { return "JP" }
        if uppercased.contains("🇭🇰") || uppercased.contains(" HK ") || uppercased.contains("[HK]") { return "HK" }
        if uppercased.contains("🇸🇬") || uppercased.contains(" SG ") || uppercased.contains("[SG]") { return "SG" }
        return "GLOBAL"
    }
}

private final class NeonCoreKernel {
    private var process: Process?
    private var tunProcess: Process?
    private var configURL: URL {
        runtimeDirectory.appendingPathComponent("neoncore-kernel-session.json")
    }
    private var logURL: URL {
        runtimeDirectory.appendingPathComponent("neoncore-kernel.log")
    }
    private var tunLogURL: URL {
        runtimeDirectory.appendingPathComponent("neoncore-tun2proxy.log")
    }
    private var runtimeDirectory: URL {
        URL(fileURLWithPath: "/tmp/neoncore-atlas", isDirectory: true)
    }

    var isAvailable: Bool {
        binaryURL != nil
    }

    func loadCapabilities() -> KernelCapabilitySchema? {
        guard let binaryURL else { return nil }
        let process = Process()
        let outputPipe = Pipe()
        process.executableURL = binaryURL
        process.arguments = ["capabilities"]
        process.standardOutput = outputPipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return nil }
            let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
            return KernelCapabilitySchema.parse(data)
        } catch {
            return nil
        }
    }

    func start(node: NeonCoreNode, port: Int, fullTunnel: Bool) throws {
        stop()
        guard let binaryURL else { throw NeonCoreError.engineMissing }
        try FileManager.default.createDirectory(at: runtimeDirectory, withIntermediateDirectories: true)
        let session = try makeSession(node: node, port: port)
        try session.write(to: configURL)
        try checkSession(binaryURL: binaryURL)
        let resolvedServer = try resolveServer(binaryURL: binaryURL, node: node)
        let process = Process()
        process.executableURL = binaryURL
        process.arguments = ["run", "--session", configURL.path]
        FileManager.default.createFile(atPath: logURL.path, contents: nil)
        let logHandle = try FileHandle(forWritingTo: logURL)
        process.standardOutput = logHandle
        process.standardError = logHandle
        try process.run()
        self.process = process
        guard waitForListener(port: port, timeout: 8.0), process.isRunning else {
            stop()
            throw NeonCoreError.listenerUnavailable
        }
        if fullTunnel {
            do {
                try startTunBridge(node: node, port: port, resolvedServer: resolvedServer)
            } catch {
                AppRuntime.appendDiagnostic("TUN bridge unavailable; continuing in system proxy mode: \(error)")
            }
        }
    }

    func stop() {
        tunProcess?.terminate()
        tunProcess = nil
        process?.terminate()
        process = nil
    }

    private var binaryURL: URL? {
        let release = URL(fileURLWithPath: "/Users/neoncore/NeonCore Dev/neoncore-atlas/target/release/neoncore-kernel")
        if FileManager.default.isExecutableFile(atPath: release.path) {
            return release
        }
        let bundleURL = Bundle.main.resourceURL?.appendingPathComponent("neoncore-kernel")
        if let bundleURL, FileManager.default.isExecutableFile(atPath: bundleURL.path) {
            return bundleURL
        }
        let debug = URL(fileURLWithPath: "/Users/neoncore/NeonCore Dev/neoncore-atlas/target/debug/neoncore-kernel")
        if FileManager.default.isExecutableFile(atPath: debug.path) {
            return debug
        }
        return nil
    }

    private var tunBinaryURL: URL? {
        let bundleURL = Bundle.main.resourceURL?.appendingPathComponent("neoncore-tun2proxy")
        if let bundleURL, FileManager.default.isExecutableFile(atPath: bundleURL.path) {
            return bundleURL
        }
        let release = URL(fileURLWithPath: "/Users/neoncore/NeonCore Dev/neoncore-atlas/target/release/neoncore-tun2proxy")
        if FileManager.default.isExecutableFile(atPath: release.path) {
            return release
        }
        let debug = URL(fileURLWithPath: "/Users/neoncore/NeonCore Dev/neoncore-atlas/target/debug/neoncore-tun2proxy")
        if FileManager.default.isExecutableFile(atPath: debug.path) {
            return debug
        }
        return nil
    }

    private func startTunBridge(node: NeonCoreNode, port: Int, resolvedServer: ResolvedServer) throws {
        if SystemTunnel.hasForeignDefaultTunnel() {
            return
        }
        guard let tunBinaryURL else { throw NeonCoreError.tunBridgeMissing }
        let process = Process()
        process.executableURL = tunBinaryURL
        process.arguments = tunArguments(node: node, port: port, resolvedServer: resolvedServer)
        FileManager.default.createFile(atPath: tunLogURL.path, contents: nil)
        let logHandle = try FileHandle(forWritingTo: tunLogURL)
        process.standardOutput = logHandle
        process.standardError = logHandle
        try process.run()
        tunProcess = process
        Thread.sleep(forTimeInterval: 1.0)
        guard process.isRunning else {
            tunProcess = nil
            if let tail = tailLog(url: tunLogURL), !tail.isEmpty {
                AppRuntime.appendDiagnostic("TUN bridge exited during startup: \(tail)")
            }
            throw NeonCoreError.tunBridgeFailed
        }
    }

    private func tailLog(url: URL, limit: Int = 2048) -> String? {
        guard let data = try? Data(contentsOf: url), !data.isEmpty else { return nil }
        let suffix = data.count > limit ? data.suffix(limit) : data[...]
        return String(decoding: suffix, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func tunArguments(node: NeonCoreNode, port: Int, resolvedServer: ResolvedServer) -> [String] {
        var arguments = [
            "--proxy-port", "\(port)",
            "--setup-routes",
            "--ipv6",
            "--dns", "over-tcp",
            "--mtu", "1500",
            "--max-sessions", "1024"
        ]
        if let bypass = bypassCIDR(for: resolvedServer.connectHost) {
            arguments.append(contentsOf: ["--bypass", bypass])
        }
        return arguments
    }

    private func bypassCIDR(for host: String) -> String? {
        if IPv4Address(host) != nil {
            return "\(host)/32"
        }
        if IPv6Address(host) != nil {
            return "\(host)/128"
        }
        return nil
    }

    private func makeSession(node: NeonCoreNode, port: Int) throws -> Data {
        let session: [String: Any] = [
            "listen_host": "127.0.0.1",
            "listen_port": port,
            "selected_node": makeKernelNode(node: node)
        ]
        return try JSONSerialization.data(withJSONObject: session, options: [.prettyPrinted, .sortedKeys])
    }

    private func makeKernelNode(node: NeonCoreNode) -> [String: Any] {
        return [
            "protocol": node.protocolName,
            "server": node.host,
            "server_port": node.port,
            "user_id": node.userID,
            "parameters": node.query
        ]
    }

    private func resolveServer(binaryURL: URL, node: NeonCoreNode) throws -> ResolvedServer {
        let process = Process()
        process.executableURL = binaryURL
        process.arguments = ["resolve-server", "--session", configURL.path]
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        try process.run()
        process.waitUntilExit()
        let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let errorOutput = String(decoding: errorPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if process.terminationStatus != 0 {
            let output = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            AppRuntime.appendDiagnostic("kernel resolve-server failed: \(output)")
            if !errorOutput.isEmpty {
                AppRuntime.appendDiagnostic("kernel resolve-server stderr: \(errorOutput)")
            }
            return ResolvedServer(originalHost: node.host, connectHost: node.host)
        }
        guard let output = try? JSONDecoder().decode(KernelResolvedServerOutput.self, from: data),
              let address = output.addresses.first
        else {
            AppRuntime.appendDiagnostic("kernel resolve-server returned no usable address")
            if !errorOutput.isEmpty {
                AppRuntime.appendDiagnostic("kernel resolve-server stderr: \(errorOutput)")
            }
            return ResolvedServer(originalHost: node.host, connectHost: node.host)
        }
        AppRuntime.appendDiagnostic("kernel resolved server \(output.server):\(output.serverPort) -> \(address)")
        return ResolvedServer(originalHost: output.server, connectHost: address)
    }

    private func checkSession(binaryURL: URL) throws {
        let process = Process()
        process.executableURL = binaryURL
        process.arguments = ["check", "--session", configURL.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        if process.terminationStatus != 0 {
            writeKernelDiagnostic(output)
            if output.lowercased().contains("unsupported protocol") {
                throw NeonCoreError.unsupportedProtocol
            }
            throw NeonCoreError.kernelCheckFailed
        }
    }

    private func writeKernelDiagnostic(_ message: String) {
        let diagnostic = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !diagnostic.isEmpty else { return }
        FileManager.default.createFile(atPath: logURL.path, contents: nil)
        guard let handle = try? FileHandle(forWritingTo: logURL) else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        if let data = "kernel check failed: \(diagnostic)\n".data(using: .utf8) {
            try? handle.write(contentsOf: data)
        }
    }

    private func waitForListener(port: Int, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if TCPProbe.syncCheck(host: "127.0.0.1", port: port, timeout: 0.25) {
                return true
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return false
    }
}

private enum SystemTunnel {
    static func hasForeignDefaultTunnel() -> Bool {
        guard let output = try? capture("/bin/sh", ["-c", "netstat -rn -f inet | awk '$1 == \"1\" || $1 == \"128.0/1\" || $1 == \"0/1\" { print }'"]) else {
            return false
        }
        return output.split(whereSeparator: \.isNewline).contains { line in
            line.contains("utun")
        }
    }

    private static func capture(_ executable: String, _ arguments: [String]) throws -> String {
        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        return String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }
}

@MainActor
private enum SystemProxy {
    private static var previousStates: [String: ProxyState] = [:]
    private static var managedServices: [String] = []

    static func enable(port: Int) throws {
        let services = try activeServices()
        if previousStates.isEmpty {
            previousStates = try Dictionary(uniqueKeysWithValues: services.map { service in
                (service, try captureState(service: service))
            })
            managedServices = services
        }
        for service in services {
            try run("/usr/sbin/networksetup", ["-setsocksfirewallproxy", service, "127.0.0.1", "\(port)"])
            try run("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", service, "on"])
            try run("/usr/sbin/networksetup", ["-setwebproxy", service, "127.0.0.1", "\(port)"])
            try run("/usr/sbin/networksetup", ["-setwebproxystate", service, "on"])
            try run("/usr/sbin/networksetup", ["-setsecurewebproxy", service, "127.0.0.1", "\(port)"])
            try run("/usr/sbin/networksetup", ["-setsecurewebproxystate", service, "on"])
        }
    }

    static func disable() throws {
        if previousStates.isEmpty {
            for service in managedServices.isEmpty ? try activeServices() : managedServices {
                try run("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", service, "off"])
                try run("/usr/sbin/networksetup", ["-setwebproxystate", service, "off"])
                try run("/usr/sbin/networksetup", ["-setsecurewebproxystate", service, "off"])
            }
            managedServices.removeAll()
            return
        }
        for (service, state) in previousStates {
            try restore(proxy: state.socks, service: service, kind: .socks)
            try restore(proxy: state.http, service: service, kind: .http)
            try restore(proxy: state.https, service: service, kind: .https)
        }
        previousStates.removeAll()
        managedServices.removeAll()
    }

    private static func activeServices() throws -> [String] {
        let defaultInterface = try defaultRouteInterface()
        let output = try capture("/usr/sbin/networksetup", ["-listallnetworkservices"])
        let services = output
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .filter { !$0.hasPrefix("An asterisk") && !$0.hasPrefix("*") }
        if let defaultInterface,
           let service = try serviceName(for: defaultInterface),
           services.contains(service) {
            return [service]
        }
        if services.contains("Wi-Fi") {
            return ["Wi-Fi"]
        }
        return services.isEmpty ? ["Wi-Fi"] : [services[0]]
    }

    private static func defaultRouteInterface() throws -> String? {
        let output = try capture("/sbin/route", ["-n", "get", "default"])
        for line in output.split(whereSeparator: \.isNewline).map(String.init) {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2, parts[0] == "interface" {
                return parts[1]
            }
        }
        return nil
    }

    private static func serviceName(for device: String) throws -> String? {
        let output = try capture("/usr/sbin/networksetup", ["-listnetworkserviceorder"])
        var currentService: String?
        for line in output.split(whereSeparator: \.isNewline).map(String.init) {
            if let service = parseServiceName(line) {
                currentService = service
                continue
            }
            if line.contains("Device: \(device)") {
                return currentService
            }
        }
        return nil
    }

    private static func parseServiceName(_ line: String) -> String? {
        guard line.hasPrefix("("),
              let close = line.firstIndex(of: ")")
        else { return nil }
        let name = line[line.index(after: close)...].trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? nil : name
    }

    private static func run(_ executable: String, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        try process.run()
        process.waitUntilExit()
        if process.terminationStatus != 0 { throw NeonCoreError.systemProxyFailed }
    }

    private static func capture(_ executable: String, _ arguments: [String]) throws -> String {
        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        return String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }

    private static func captureState(service: String) throws -> ProxyState {
        ProxyState(
            socks: parseProxy(try capture("/usr/sbin/networksetup", ["-getsocksfirewallproxy", service])),
            http: parseProxy(try capture("/usr/sbin/networksetup", ["-getwebproxy", service])),
            https: parseProxy(try capture("/usr/sbin/networksetup", ["-getsecurewebproxy", service]))
        )
    }

    private static func parseProxy(_ output: String) -> ProxyEndpoint {
        var enabled = false
        var server = "127.0.0.1"
        var port = 0
        for line in output.split(whereSeparator: \.isNewline).map(String.init) {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            switch parts[0] {
            case "Enabled": enabled = parts[1].lowercased() == "yes"
            case "Server": server = parts[1]
            case "Port": port = Int(parts[1]) ?? 0
            default: break
            }
        }
        return ProxyEndpoint(enabled: enabled, server: server, port: port)
    }

    private static func restore(proxy: ProxyEndpoint, service: String, kind: ProxyKind) throws {
        if proxy.port > 0 {
            try run("/usr/sbin/networksetup", kind.setCommand(service: service, server: proxy.server, port: proxy.port))
        }
        try run("/usr/sbin/networksetup", kind.stateCommand(service: service, enabled: proxy.enabled))
    }

    private struct ProxyState {
        var socks: ProxyEndpoint
        var http: ProxyEndpoint
        var https: ProxyEndpoint
    }

    private struct ProxyEndpoint {
        var enabled: Bool
        var server: String
        var port: Int
    }

    private enum ProxyKind {
        case socks
        case http
        case https

        func setCommand(service: String, server: String, port: Int) -> [String] {
            switch self {
            case .socks:
                return ["-setsocksfirewallproxy", service, server, "\(port)"]
            case .http:
                return ["-setwebproxy", service, server, "\(port)"]
            case .https:
                return ["-setsecurewebproxy", service, server, "\(port)"]
            }
        }

        func stateCommand(service: String, enabled: Bool) -> [String] {
            let state = enabled ? "on" : "off"
            switch self {
            case .socks:
                return ["-setsocksfirewallproxystate", service, state]
            case .http:
                return ["-setwebproxystate", service, state]
            case .https:
                return ["-setsecurewebproxystate", service, state]
            }
        }
    }
}

private enum TCPProbe {
    static func check(host: String, port: Int, timeout: TimeInterval) async -> Bool {
        await withCheckedContinuation { continuation in
            let connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(integerLiteral: NWEndpoint.Port.IntegerLiteralType(port)), using: .tcp)
            let state = ProbeState()
            let complete: @Sendable (Bool) -> Void = { value in
                guard state.markFinished() else { return }
                connection.cancel()
                continuation.resume(returning: value)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: complete(true)
                case .failed, .cancelled: complete(false)
                default: break
                }
            }
            connection.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                complete(false)
            }
        }
    }

    static func syncCheck(host: String, port: Int, timeout: TimeInterval) -> Bool {
        let semaphore = DispatchSemaphore(value: 0)
        let state = ProbeState()
        let connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(integerLiteral: UInt16(port)), using: .tcp)
        connection.stateUpdateHandler = { connectionState in
            switch connectionState {
            case .ready:
                if state.markFinished(success: true) {
                    connection.cancel()
                    semaphore.signal()
                }
            case .failed, .cancelled:
                if state.markFinished(success: false) {
                    connection.cancel()
                    semaphore.signal()
                }
            default:
                break
            }
        }
        connection.start(queue: .global())
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            if state.markFinished(success: false) {
                connection.cancel()
                semaphore.signal()
            }
        }
        semaphore.wait()
        return state.succeeded
    }
}

private enum ProxyProbe {
    static func httpConnect(port: Int, timeout: TimeInterval) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = [
            "--http1.1",
            "--proxy", "http://127.0.0.1:\(port)",
            "--connect-timeout", "\(Int(timeout))",
            "--max-time", "\(Int(timeout))",
            "-sS",
            "-o", "/dev/null",
            "-w", "%{http_code}",
            "https://www.google.com/generate_204"
        ]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            process.waitUntilExit()
            let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            AppRuntime.appendDiagnostic("proxy preflight curl status=\(process.terminationStatus) output=\(output.trimmingCharacters(in: .whitespacesAndNewlines))")
            return process.terminationStatus == 0 && output.contains("204")
        } catch {
            AppRuntime.appendDiagnostic("proxy preflight curl failed to launch: \(error)")
            return false
        }
    }
}

private final class ProbeState: @unchecked Sendable {
    private let lock = NSLock()
    private var finished = false
    private var success = false

    var succeeded: Bool {
        lock.lock()
        defer { lock.unlock() }
        return success
    }

    func markFinished(success: Bool = false) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !finished else { return false }
        finished = true
        self.success = success
        return true
    }
}

private enum NeonCoreError: Error {
    case invalidURL
    case subscriptionFailed
    case engineMissing
    case unsupportedProtocol
    case kernelCheckFailed
    case listenerUnavailable
    case systemProxyFailed
    case proxyPreflightFailed
    case tunBridgeMissing
    case tunBridgeFailed
    case tunRouteConflict
    case invalidManualNode
}

struct ContentView: View {
    @StateObject private var store = NeonCoreStore()

    var body: some View {
        ZStack {
            NeonCoreBackground()
            HStack(spacing: 0) {
                Sidebar(store: store)
                Workspace(store: store)
            }
        }
        .preferredColorScheme(.dark)
    }
}

private struct Sidebar: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(spacing: 18) {
            VStack(spacing: 2) {
                Text("app.name".localized)
                    .font(.custom(NeonCoreTheme.fontName, size: 24).weight(.bold))
                    .foregroundStyle(.white)
                Text("app.tagline".localized)
                    .font(.custom(NeonCoreTheme.fontName, size: 11).weight(.semibold))
                    .foregroundStyle(NeonCoreTheme.muted)
                    .textCase(.uppercase)
            }
            .frame(maxWidth: .infinity, minHeight: 86)
            .overlay(alignment: .bottom) {
                Rectangle().fill(NeonCoreTheme.line).frame(height: 1)
            }

            VStack(spacing: 8) {
                ForEach(NeonCorePage.allCases) { page in
                    Button {
                        store.selectedPage = page
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: page.symbol)
                                .frame(width: 20)
                            Text(page.titleKey.localized)
                                .font(.custom(NeonCoreTheme.fontName, size: 13).weight(.bold))
                            Spacer()
                        }
                        .textCase(.uppercase)
                        .tracking(0.8)
                    }
                    .buttonStyle(NeonNavButtonStyle(active: store.selectedPage == page))
                }
            }

            Spacer()

            VStack(alignment: .leading, spacing: 10) {
                StatusPill(key: store.statusKey, tone: store.status == .connected ? .good : .muted)
                Text("settings.language".localized)
                    .font(.custom(NeonCoreTheme.fontName, size: 11).weight(.semibold))
                    .foregroundStyle(NeonCoreTheme.muted)
                Text("en-AU · zh-Hans · en-XA")
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.72))
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .neonPanel()
        }
        .padding(24)
        .frame(width: 292)
        .background(.black.opacity(0.88))
        .overlay(alignment: .trailing) {
            Rectangle().fill(NeonCoreTheme.line).frame(width: 1)
        }
    }
}

private struct Workspace: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                Topbar(store: store)
                switch store.selectedPage {
                case .dashboard: DashboardPage(store: store)
                case .nodes: NodesPage(store: store)
                case .profiles: ProfilesPage(store: store)
                case .routing: RoutingPage(store: store)
                case .logs: LogsPage(store: store)
                case .diagnostics: DiagnosticsPage(store: store)
                case .settings: SettingsPage(store: store)
                }
            }
            .padding(26)
        }
    }
}

private struct Topbar: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("topbar.control_plane".localized)
                    .font(.custom(NeonCoreTheme.fontName, size: 11).weight(.bold))
                    .foregroundStyle(NeonCoreTheme.cyan)
                    .textCase(.uppercase)
                Text(store.selectedPage.titleKey.localized)
                    .font(.custom(NeonCoreTheme.fontName, size: 44).weight(.bold))
                    .textCase(.uppercase)
            }
            Spacer()
            Button {
                store.toggleConnection()
            } label: {
                Label(
                    store.status == .connected ? "connection.action.disconnect".localized : "connection.action.connect".localized,
                    systemImage: store.status == .connected ? "power.circle.fill" : "bolt.circle.fill"
                )
            }
            .buttonStyle(NeonPrimaryButtonStyle(active: store.status == .connected))
            .accessibilityLabel(Text("accessibility.connect_button".localized))
            .help("tooltip.connect_button".localized)
        }
        .frame(height: 90)
        .overlay(alignment: .bottom) {
            Rectangle().fill(NeonCoreTheme.line).frame(height: 1)
        }
    }
}

private struct DashboardPage: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(spacing: 18) {
            HeroPanel(store: store)
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 14), count: 4), spacing: 14) {
                MetricCard(titleKey: "metric.nodes", value: "\(store.nodes.count)", footKey: "metric.ready")
                MetricCard(titleKey: "metric.profiles", value: "\(store.profiles.count)", footKey: "metric.loaded")
                MetricCard(titleKey: "metric.latency", value: store.nodes.compactMap(\.latency).first.map { "\($0) ms" } ?? "--", footKey: "metric.latest")
                MetricCard(titleKey: "metric.traffic", value: ByteCountFormatter.string(fromByteCount: Int64(store.proxyBytesIn + store.proxyBytesOut), countStyle: .binary), footKey: "metric.system_proxy")
            }
            HStack(alignment: .top, spacing: 18) {
                NodesSummary(store: store)
                LogsSummary(store: store)
            }
        }
    }
}

private struct HeroPanel: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("dashboard.hero.title".localized)
                        .font(.custom(NeonCoreTheme.fontName, size: 58).weight(.bold))
                        .lineLimit(2)
                        .textCase(.uppercase)
                    Text("dashboard.hero.subtitle".localized)
                        .font(.custom(NeonCoreTheme.fontName, size: 16).weight(.semibold))
                        .foregroundStyle(NeonCoreTheme.muted)
                }
                Spacer()
                TrafficDial(store: store)
            }

            HStack(spacing: 10) {
                TextField("subscription.import.url_placeholder".localized, text: $store.subscriptionURL)
                    .textFieldStyle(NeonTextFieldStyle())
                Button {
                    Task { await store.importSubscription() }
                } label: {
                    Label("profiles.action.import_subscription".localized, systemImage: "square.and.arrow.down")
                }
                .buttonStyle(NeonSecondaryButtonStyle())
            }
        }
        .padding(30)
        .frame(maxWidth: .infinity, minHeight: 310, alignment: .leading)
        .neonPanel()
        .overlay(alignment: .bottom) {
            LinearGradient(colors: [NeonCoreTheme.cyan, NeonCoreTheme.blue, NeonCoreTheme.violet], startPoint: .leading, endPoint: .trailing)
                .frame(height: 2)
        }
    }
}

private struct TrafficDial: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        ZStack {
            Circle()
                .stroke(.white.opacity(0.08), lineWidth: 18)
            Circle()
                .trim(from: 0, to: store.status == .connected ? 0.72 : 0.18)
                .stroke(NeonCoreTheme.cyan, style: StrokeStyle(lineWidth: 18, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .shadow(color: NeonCoreTheme.cyan.opacity(0.55), radius: 14)
            VStack(spacing: 2) {
                Text(store.status == .connected ? "72%" : "18%")
                    .font(.custom(NeonCoreTheme.fontName, size: 34).weight(.bold))
                Text("metric.session".localized)
                    .font(.custom(NeonCoreTheme.fontName, size: 11).weight(.semibold))
                    .foregroundStyle(NeonCoreTheme.muted)
                    .textCase(.uppercase)
            }
        }
        .frame(width: 156, height: 156)
    }
}

private struct NodesSummary: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(titleKey: "nav.nodes", actionKey: "nodes.action.test_latency", systemImage: "timer") {
                Task { await store.testLatency() }
            }
            ForEach(store.nodes.prefix(3)) { node in
                DataRow(primary: node.name, secondary: node.endpoint, trailing: node.latency.map { "\($0) ms" } ?? "nodes.latency.unknown".localized, tone: node.id == store.activeNodeID ? .good : .muted)
            }
        }
        .padding(18)
        .neonPanel()
    }
}

private struct LogsSummary: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(titleKey: "logs.title", actionKey: "logs.action.clear", systemImage: "trash") {
                store.clearLogs()
            }
            if store.logs.isEmpty {
                EmptyState(titleKey: "logs.empty", descriptionKey: "empty.logs.description")
            } else {
                ForEach(store.logs.prefix(4)) { log in
                    DataRow(primary: log.messageKey.localized, secondary: log.time.formatted(date: .omitted, time: .standard), trailing: log.level.uppercased(), tone: log.level == "warn" ? .warn : .muted)
                }
            }
        }
        .padding(18)
        .neonPanel()
    }
}

private struct NodesPage: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(spacing: 18) {
            HStack {
                Text("nav.nodes".localized)
                    .font(.custom(NeonCoreTheme.fontName, size: 26).weight(.bold))
                    .textCase(.uppercase)
                Spacer()
                Button {
                    store.selectedPage = .profiles
                } label: {
                    Label("profiles.action.import_subscription".localized, systemImage: "square.and.arrow.down")
                }
                .buttonStyle(NeonSecondaryButtonStyle())
                Button {
                    Task { await store.testLatency() }
                } label: {
                    Label("nodes.action.test_latency".localized, systemImage: "timer")
                }
                .buttonStyle(NeonSecondaryButtonStyle())
                Button {
                    store.showingManualNodeEditor = true
                } label: {
                    Label("Add Node", systemImage: "plus")
                }
                .buttonStyle(NeonPrimaryButtonStyle(active: false))
            }
            .padding(18)
            .neonPanel()

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                ForEach(store.nodes) { node in
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(node.name)
                                    .font(.custom(NeonCoreTheme.fontName, size: 20).weight(.bold))
                                Text(node.endpoint)
                                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                    .foregroundStyle(NeonCoreTheme.muted)
                            }
                            Spacer()
                            StatusPill(key: node.latency.map { "\($0) ms" } ?? "nodes.latency.unknown", tone: node.latency == nil ? .muted : .good)
                        }
                        HStack {
                            ForEach(node.tags, id: \.self) { tag in
                                Text(tag)
                                    .font(.custom(NeonCoreTheme.fontName, size: 11).weight(.bold))
                                    .padding(.horizontal, 9)
                                    .frame(height: 26)
                                    .overlay(RoundedRectangle(cornerRadius: 0).stroke(NeonCoreTheme.lineBright))
                            }
                            Spacer()
                            Button("connection.action.connect".localized) {
                                store.selectNode(node)
                            }
                            .buttonStyle(NeonSecondaryButtonStyle())
                            Button {
                                store.removeNode(node)
                            } label: {
                                Image(systemName: "trash")
                                    .frame(width: 16, height: 16)
                            }
                            .buttonStyle(NeonSecondaryButtonStyle())
                        }
                    }
                    .padding(18)
                    .neonPanel(active: node.id == store.activeNodeID)
                }
            }
            if store.nodes.isEmpty {
                EmptyState(titleKey: "nodes.empty.title", descriptionKey: "nodes.empty.description")
                    .neonPanel()
            }
        }
        .sheet(isPresented: $store.showingManualNodeEditor) {
            ManualNodeEditor(store: store)
        }
    }
}

private struct ManualNodeEditor: View {
    @ObservedObject var store: NeonCoreStore

    private let securityOptions = ["none", "tls", "reality"]
    private let transportOptions = ["tcp", "ws", "grpc", "h2", "httpupgrade", "xhttp"]
    private let fingerprintOptions = ["chrome", "edge", "firefox", "safari", "ios", "android", "randomized", "random", "none"]
    private var xhttpModeOptions: [String] { store.kernelCapabilities.xhttpModes }
    private var httpVersionOptions: [String] { store.kernelCapabilities.httpVersions }
    private let methodOptions = [
        "2022-blake3-aes-256-gcm",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-chacha20-poly1305",
        "2022-blake3-chacha8-poly1305",
        "aes-256-gcm",
        "aes-128-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "aes-256-ccm",
        "aes-128-ccm",
        "aes-256-gcm-siv",
        "aes-128-gcm-siv",
        "sm4-gcm",
        "sm4-ccm",
        "none",
        "table",
        "rc4",
        "rc4-md5",
        "rc4-md5-6",
        "salsa20",
        "chacha20",
        "chacha20-ietf",
        "aes-256-cfb",
        "aes-192-cfb",
        "aes-128-cfb",
        "aes-256-cfb1",
        "aes-192-cfb1",
        "aes-128-cfb1",
        "aes-256-cfb8",
        "aes-192-cfb8",
        "aes-128-cfb8",
        "aes-256-ctr",
        "aes-192-ctr",
        "aes-128-ctr",
        "aes-256-ofb",
        "aes-192-ofb",
        "aes-128-ofb",
        "bf-cfb",
        "cast5-cfb",
        "des-cfb",
        "idea-cfb",
        "rc2-cfb",
        "seed-cfb",
        "camellia-256-cfb",
        "camellia-192-cfb",
        "camellia-128-cfb",
        "camellia-256-cfb1",
        "camellia-192-cfb1",
        "camellia-128-cfb1",
        "camellia-256-cfb8",
        "camellia-192-cfb8",
        "camellia-128-cfb8",
        "camellia-256-ctr",
        "camellia-192-ctr",
        "camellia-128-ctr",
        "camellia-256-ofb",
        "camellia-192-ofb",
        "camellia-128-ofb"
    ]
    private var shadowsocksPluginOptions: [String] { store.kernelCapabilities.shadowsocksPlugins }
    private var shadowsocksObfuscationOptions: [String] { store.kernelCapabilities.shadowsocksObfuscation }
    private var shadowsocksPluginModeOptions: [String] { store.kernelCapabilities.shadowsocksPluginModes }
    private let kcpCryptOptions = ["aes", "aes-128", "aes-128-gcm", "aes-192", "salsa20", "blowfish", "twofish", "cast5", "3des", "tea", "xtea", "xor", "none", "null"]
    private let kcpModeOptions = ["fast3", "fast2", "fast", "normal", "manual"]
    private var shadowTLSVersionOptions: [String] { store.kernelCapabilities.shadowTLSVersions }
    private let ssrMethodOptions = [
        "chacha20-ietf-poly1305",
        "chacha20-poly1305",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-chacha20-poly1305",
        "none",
        "table",
        "rc4",
        "rc4-md5",
        "rc4-md5-6",
        "salsa20",
        "chacha20",
        "chacha20-ietf",
        "aes-256-cfb",
        "aes-192-cfb",
        "aes-128-cfb",
        "aes-256-cfb1",
        "aes-192-cfb1",
        "aes-128-cfb1",
        "aes-256-cfb8",
        "aes-192-cfb8",
        "aes-128-cfb8",
        "aes-256-ctr",
        "aes-192-ctr",
        "aes-128-ctr",
        "aes-256-ofb",
        "aes-192-ofb",
        "aes-128-ofb",
        "bf-cfb",
        "cast5-cfb",
        "des-cfb",
        "idea-cfb",
        "rc2-cfb",
        "seed-cfb",
        "camellia-256-cfb",
        "camellia-192-cfb",
        "camellia-128-cfb",
        "camellia-256-cfb1",
        "camellia-192-cfb1",
        "camellia-128-cfb1",
        "camellia-256-cfb8",
        "camellia-192-cfb8",
        "camellia-128-cfb8",
        "camellia-256-ctr",
        "camellia-192-ctr",
        "camellia-128-ctr",
        "camellia-256-ofb",
        "camellia-192-ofb",
        "camellia-128-ofb"
    ]
    private let ssrProtocolOptions = [
        "origin",
        "plain",
        "verify_simple",
        "verify_sha1",
        "auth_simple",
        "auth_sha1",
        "auth_sha1_v2",
        "auth_sha1_v4",
        "auth-aes128_md5",
        "auth_aes128_sha1",
        "auth_chain_a",
        "auth_chain_b",
        "auth_chain_c",
        "auth_chain_d",
        "auth_chain_e",
        "auth_chain_f"
    ]
    private var ssrObfsOptions: [String] { store.kernelCapabilities.ssrObfs }
    private let obfsOptions = ["", "salamander", "gecko"]
    private let bbrProfileOptions = ["auto", "brutal", "bbr"]

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Add Manual Node")
                        .font(.custom(NeonCoreTheme.fontName, size: 26).weight(.bold))
                        .textCase(.uppercase)
                    Text("Create a node from a shared URI or from explicit protocol parameters.")
                        .font(.custom(NeonCoreTheme.fontName, size: 13).weight(.semibold))
                        .foregroundStyle(NeonCoreTheme.muted)
                }
                Spacer()
                Button {
                    store.showingManualNodeEditor = false
                } label: {
                    Image(systemName: "xmark")
                }
                .buttonStyle(NeonSecondaryButtonStyle())
            }
            .padding(20)

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Shared URI")
                            .font(.custom(NeonCoreTheme.fontName, size: 16).weight(.bold))
                        TextField("vless://, hysteria2://, hy2://, anytls://, ss://, ssr://, http://", text: $store.manualNodeDraft.uri)
                            .textFieldStyle(NeonTextFieldStyle())
                        HStack {
                            Spacer()
                            Button {
                                store.importManualNodeURI()
                            } label: {
                                Label("Import URI", systemImage: "link")
                            }
                            .buttonStyle(NeonSecondaryButtonStyle())
                        }
                    }
                    .padding(16)
                    .neonPanel()

                    VStack(alignment: .leading, spacing: 14) {
                        Text("Protocol Parameters")
                            .font(.custom(NeonCoreTheme.fontName, size: 16).weight(.bold))
                        HStack(spacing: 12) {
                            manualField("Name", text: $store.manualNodeDraft.name, placeholder: "Optional display name")
                            Picker("Protocol", selection: $store.manualNodeDraft.protocolName) {
                                ForEach(ManualNodeProtocol.allCases) { item in
                                    Text(item.title).tag(item)
                                }
                            }
                            .pickerStyle(.menu)
                            .onChange(of: store.manualNodeDraft.protocolName) {
                                store.manualNodeDraft.applyProtocolDefaults()
                            }
                            .frame(width: 220)
                        }
                        HStack(spacing: 12) {
                            manualField("Server", text: $store.manualNodeDraft.host, required: true)
                            manualField("Port", text: $store.manualNodeDraft.port, required: true)
                                .frame(width: 120)
                        }
                        if store.manualNodeDraft.protocolName != .http && store.manualNodeDraft.protocolName != .direct {
                            manualField(store.manualNodeDraft.protocolName.credentialLabel, text: $store.manualNodeDraft.credential, secure: store.manualNodeDraft.protocolName != .vless, required: true)
                        }
                        protocolSpecificFields
                    }
                    .padding(16)
                    .neonPanel()

                }
                .padding(20)
            }

            HStack {
                if store.manualNodeDraft.supportsCertificateVerificationSkip {
                    Toggle("Skip certificate verification", isOn: $store.manualNodeDraft.insecure)
                        .toggleStyle(.switch)
                }
                Spacer()
                Button("Cancel") {
                    store.showingManualNodeEditor = false
                }
                .buttonStyle(NeonSecondaryButtonStyle())
                Button {
                    store.addManualNode()
                } label: {
                    Label("Save Node", systemImage: "checkmark")
                }
                .disabled(store.manualNodeDraft.hasUnsupportedPendingSelection)
                .buttonStyle(NeonPrimaryButtonStyle(active: false))
            }
            .padding(20)
        }
        .frame(width: 760, height: 720)
        .background(NeonCoreTheme.panel)
    }

    @ViewBuilder
    private var protocolSpecificFields: some View {
        switch store.manualNodeDraft.protocolName {
        case .vless:
            HStack(spacing: 12) {
                picker("Security", selection: $store.manualNodeDraft.security, options: securityOptions)
                picker("Transport", selection: $store.manualNodeDraft.transport, options: transportOptions)
                picker("Fingerprint", selection: $store.manualNodeDraft.fingerprint, options: fingerprintOptions)
            }
            HStack(spacing: 12) {
                manualField("SNI", text: $store.manualNodeDraft.sni)
                manualField("Flow", text: $store.manualNodeDraft.flow)
            }
            HStack(spacing: 12) {
                manualField("Reality public key", text: $store.manualNodeDraft.publicKey)
                manualField("Reality short ID", text: $store.manualNodeDraft.shortID)
                    .frame(width: 180)
            }
            HStack(spacing: 12) {
                manualField("Transport host", text: $store.manualNodeDraft.transportHost)
                manualField("Path", text: $store.manualNodeDraft.transportPath)
                    .frame(width: 220)
            }
            HStack(spacing: 12) {
                manualField("Service name", text: $store.manualNodeDraft.serviceName)
                manualField("Authority", text: $store.manualNodeDraft.authority)
            }
            HStack(spacing: 12) {
                picker("XHTTP mode", selection: $store.manualNodeDraft.xhttpMode, options: xhttpModeOptions)
                picker("HTTP version", selection: $store.manualNodeDraft.httpVersion, options: httpVersionOptions)
            }
            HStack(spacing: 12) {
                manualField("XHTTP post bytes", text: $store.manualNodeDraft.scMaxEachPostBytes)
                manualField("XHTTP post interval ms", text: $store.manualNodeDraft.scMinPostsIntervalMs)
            }
            HStack(spacing: 12) {
                manualField("xmux max concurrency", text: $store.manualNodeDraft.xmuxMaxConcurrency)
                manualField("xmux max connections", text: $store.manualNodeDraft.xmuxMaxConnections)
            }
            HStack(spacing: 12) {
                manualField("xmux C reuse times", text: $store.manualNodeDraft.xmuxCMaxReuseTimes)
                manualField("xmux H request times", text: $store.manualNodeDraft.xmuxHMaxRequestTimes)
                manualField("xmux H reusable secs", text: $store.manualNodeDraft.xmuxHMaxReusableSecs)
            }
        case .hysteria2:
            HStack(spacing: 12) {
                manualField("SNI / Peer", text: $store.manualNodeDraft.sni)
                picker("Obfs", selection: $store.manualNodeDraft.obfs, options: obfsOptions)
                    .frame(width: 170)
            }
            manualField("Obfs password", text: $store.manualNodeDraft.obfsPassword, secure: true)
            HStack(spacing: 12) {
                manualField("mport", text: $store.manualNodeDraft.mport)
                manualField("UDP timeout ms", text: $store.manualNodeDraft.udpTimeoutMs)
                picker("BBR profile", selection: $store.manualNodeDraft.bbrProfile, options: bbrProfileOptions)
            }
        case .anytls:
            manualField("SNI", text: $store.manualNodeDraft.sni)
            HStack(spacing: 12) {
                manualField("Idle session timeout", text: $store.manualNodeDraft.idleSessionTimeout)
                manualField("Min idle session", text: $store.manualNodeDraft.minIdleSession)
            }
        case .shadowsocks:
            picker("Cipher", selection: $store.manualNodeDraft.method, options: methodOptions)
            HStack(spacing: 12) {
                optionToggle("TCP fast open", isOn: $store.manualNodeDraft.tcpFastOpen)
                optionToggle("UDP relay", isOn: $store.manualNodeDraft.udpRelay)
                optionToggle("UDP over TCP", isOn: $store.manualNodeDraft.udpOverTcp)
                    .disabled(store.manualNodeDraft.shadowsocksPluginForcesUoT)
            }
            HStack(spacing: 12) {
                picker("Plugin", selection: $store.manualNodeDraft.plugin, options: shadowsocksPluginOptions)
                    .onChange(of: store.manualNodeDraft.plugin) {
                        store.manualNodeDraft.applyPluginDefaults()
                    }
                picker("Obfuscation", selection: $store.manualNodeDraft.ssObfuscation, options: shadowsocksObfuscationOptions)
            }
            if store.manualNodeDraft.shouldShowShadowsocksObfuscationTLS {
                optionToggle("TLS", isOn: $store.manualNodeDraft.ssObfuscationTLS)
            }
            if store.manualNodeDraft.shouldShowShadowsocksXHTTPFields {
                shadowsocksXHTTPFields
            }
            shadowsocksPluginFields
            manualField("Obfs host", text: $store.manualNodeDraft.obfsHost)
        case .shadowsocksr:
            HStack(spacing: 12) {
                picker("Cipher", selection: $store.manualNodeDraft.method, options: ssrMethodOptions)
                picker("SSR protocol", selection: $store.manualNodeDraft.ssrProtocol, options: ssrProtocolOptions)
            }
            manualField("Protocol parameter", text: $store.manualNodeDraft.ssrProtocolParam)
            HStack(spacing: 12) {
                optionToggle("TCP fast open", isOn: $store.manualNodeDraft.tcpFastOpen)
                optionToggle("UDP relay", isOn: $store.manualNodeDraft.udpRelay)
            }
            HStack(spacing: 12) {
                picker("Obfs", selection: $store.manualNodeDraft.obfs, options: ssrObfsOptions)
                    .onChange(of: store.manualNodeDraft.obfs) {
                        store.manualNodeDraft.applySSRObfsDefaults()
                    }
                manualField("Obfs parameter", text: $store.manualNodeDraft.obfsHost)
            }
            ssrObfsFields
        case .http:
            EmptyView()
        case .direct:
            EmptyView()
        }
    }

    @ViewBuilder
    private var ssrObfsFields: some View {
        switch store.manualNodeDraft.obfs.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "", "plain":
            EmptyView()
        case "http_simple", "http_post":
            HStack(spacing: 12) {
                manualField("Custom header", text: $store.manualNodeDraft.ssPluginHeaders)
            }
        case "random_head":
            EmptyView()
        case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
            EmptyView()
        default:
            EmptyView()
        }
    }

    @ViewBuilder
    private var shadowsocksPluginFields: some View {
        switch store.manualNodeDraft.plugin.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "", "none":
            EmptyView()
        case "v2ray-plugin":
            v2rayPluginFields
        case "gost", "gost-plugin":
            gostPluginFields
        case "shadow-tls", "shadow_tls":
            shadowTLSPluginFields
        case "cloak", "ck-client", "external-sip003", "external_sip003", "sip003":
            cloakPluginFields
        case "kcptun":
            kcptunPluginFields
        default:
            EmptyView()
        }
    }

    @ViewBuilder
    private var shadowsocksXHTTPFields: some View {
        HStack(spacing: 12) {
            picker("XHTTP mode", selection: $store.manualNodeDraft.xhttpMode, options: xhttpModeOptions)
            picker("HTTP version", selection: $store.manualNodeDraft.httpVersion, options: httpVersionOptions)
        }
        HStack(spacing: 12) {
            manualField("XHTTP post bytes", text: $store.manualNodeDraft.scMaxEachPostBytes)
            manualField("XHTTP post interval ms", text: $store.manualNodeDraft.scMinPostsIntervalMs)
        }
        if store.manualNodeDraft.ssObfuscationTLS {
            optionToggle("Skip certificate verification", isOn: $store.manualNodeDraft.ssPluginSkipCertVerify)
        }
    }

    @ViewBuilder
    private var v2rayPluginFields: some View {
        HStack(spacing: 12) {
            picker("Mode", selection: $store.manualNodeDraft.ssPluginMode, options: shadowsocksPluginModeOptions)
            manualField("Host", text: $store.manualNodeDraft.ssPluginHost)
            manualField("Path", text: $store.manualNodeDraft.ssPluginPath)
        }
        HStack(spacing: 12) {
            optionToggle("TLS", isOn: $store.manualNodeDraft.ssPluginTLS)
        }
    }

    @ViewBuilder
    private var gostPluginFields: some View {
        HStack(spacing: 12) {
            picker("Mode", selection: $store.manualNodeDraft.ssPluginMode, options: ["websocket"])
            manualField("Host", text: $store.manualNodeDraft.ssPluginHost)
            manualField("Path", text: $store.manualNodeDraft.ssPluginPath)
        }
        HStack(spacing: 12) {
            optionToggle("TLS", isOn: $store.manualNodeDraft.ssPluginTLS)
        }
    }

    @ViewBuilder
    private var tlsPluginFields: some View {
        HStack(spacing: 12) {
            manualField("Fingerprint", text: $store.manualNodeDraft.ssPluginFingerprint)
            manualField("Certificate", text: $store.manualNodeDraft.ssPluginCertificate)
            manualField("Private key", text: $store.manualNodeDraft.ssPluginPrivateKey)
        }
        optionToggle("Skip certificate verification", isOn: $store.manualNodeDraft.ssPluginSkipCertVerify)
    }

    @ViewBuilder
    private var shadowTLSPluginFields: some View {
        HStack(spacing: 12) {
            picker("Version", selection: $store.manualNodeDraft.shadowTLSVersion, options: shadowTLSVersionOptions)
            manualField("Host", text: $store.manualNodeDraft.shadowTLSHost)
            manualField("Password", text: $store.manualNodeDraft.shadowTLSPassword, secure: true)
        }
        HStack(spacing: 12) {
            manualField("ALPN", text: $store.manualNodeDraft.shadowTLSALPN)
        }
        optionToggle("Skip certificate verification", isOn: $store.manualNodeDraft.ssPluginSkipCertVerify)
    }

    @ViewBuilder
    private var cloakPluginFields: some View {
        HStack(spacing: 12) {
            manualField("Plugin program", text: $store.manualNodeDraft.ssPluginCertificate)
            manualField("Plugin options", text: $store.manualNodeDraft.ssPluginHeaders)
        }
    }

    @ViewBuilder
    private var kcptunPluginFields: some View {
        HStack(spacing: 12) {
            manualField("Key", text: $store.manualNodeDraft.kcpKey, secure: true)
            picker("Crypt", selection: $store.manualNodeDraft.kcpCrypt, options: kcpCryptOptions)
            picker("Mode", selection: $store.manualNodeDraft.kcpMode, options: kcpModeOptions)
        }
        HStack(spacing: 12) {
            manualField("Conn", text: $store.manualNodeDraft.kcpConn)
            manualField("Auto expire", text: $store.manualNodeDraft.kcpAutoExpire)
            manualField("Scavenge TTL", text: $store.manualNodeDraft.kcpScavengeTTL)
            manualField("MTU", text: $store.manualNodeDraft.kcpMTU)
        }
        HStack(spacing: 12) {
            manualField("Rate limit", text: $store.manualNodeDraft.kcpRateLimit)
            manualField("Send window", text: $store.manualNodeDraft.kcpSndWnd)
            manualField("Receive window", text: $store.manualNodeDraft.kcpRcvWnd)
        }
        HStack(spacing: 12) {
            manualField("Data shard", text: $store.manualNodeDraft.kcpDataShard)
            manualField("Parity shard", text: $store.manualNodeDraft.kcpParityShard)
            manualField("DSCP", text: $store.manualNodeDraft.kcpDSCP)
        }
        HStack(spacing: 12) {
            manualField("No delay", text: $store.manualNodeDraft.kcpNoDelay)
            manualField("Interval", text: $store.manualNodeDraft.kcpInterval)
            manualField("Resend", text: $store.manualNodeDraft.kcpResend)
        }
        HStack(spacing: 12) {
            manualField("Socket buffer", text: $store.manualNodeDraft.kcpSockBuf)
            manualField("SMux version", text: $store.manualNodeDraft.kcpSmuxVer)
            manualField("SMux buffer", text: $store.manualNodeDraft.kcpSmuxBuf)
        }
        HStack(spacing: 12) {
            manualField("Frame size", text: $store.manualNodeDraft.kcpFrameSize)
            manualField("Stream buffer", text: $store.manualNodeDraft.kcpStreamBuf)
            manualField("Keep alive", text: $store.manualNodeDraft.kcpKeepAlive)
        }
        HStack(spacing: 12) {
            optionToggle("Disable compression", isOn: $store.manualNodeDraft.kcpNoComp)
            optionToggle("ACK no delay", isOn: $store.manualNodeDraft.kcpAckNoDelay)
            optionToggle("No congestion", isOn: $store.manualNodeDraft.kcpNoCongestion)
        }
    }

    private func manualField(_ title: String, text: Binding<String>, secure: Bool = false, placeholder: String? = nil, required: Bool = false) -> some View {
        let prompt = placeholder ?? manualFieldPlaceholder(for: title, required: required)
        return VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.custom(NeonCoreTheme.fontName, size: 12).weight(.bold))
                .foregroundStyle(NeonCoreTheme.muted)
                .textCase(.uppercase)
            if secure {
                SecureField(title, text: text, prompt: Text(prompt))
                    .textFieldStyle(NeonTextFieldStyle())
            } else {
                TextField(title, text: text, prompt: Text(prompt))
                    .textFieldStyle(NeonTextFieldStyle())
            }
        }
    }

    private func manualFieldPlaceholder(for title: String, required: Bool) -> String {
        if required {
            switch title.lowercased() {
            case "port":
                return "Required, 1-65535"
            default:
                return "Required"
            }
        }

        switch title.lowercased() {
        case "port":
            return "Optional, 1-65535"
        case "sni", "sni / peer", "sni / host", "transport host", "host", "authority", "server name", "obfs host":
            return "Optional hostname"
        case "path":
            return "Optional, starts with /"
        case "flow":
            return "Optional, for example xtls-rprx-vision"
        case "reality public key", "reality short id", "public key", "private key", "uid", "key":
            return "Optional, required by that transport when used"
        case "service name":
            return "Optional gRPC service name"
        case "xhttp post bytes", "xhttp post interval ms", "xmux max concurrency", "xmux max connections", "xmux c reuse times", "xmux h request times", "xmux h reusable secs", "udp timeout ms", "min idle session", "conn", "auto expire", "scavenge ttl", "mtu", "rate limit", "send window", "receive window", "data shard", "parity shard", "dscp", "no delay", "interval", "resend", "socket buffer", "smux version", "smux buffer", "frame size", "stream buffer", "keep alive", "connections", "stream timeout":
            return "Optional, integer >= 0"
        case "idle session timeout":
            return "Optional duration, for example 30s"
        case "mport":
            return "Optional multi-port, for example 443,8443-8450"
        case "obfs password", "password":
            return "Optional password"
        case "protocol parameter":
            return "Optional SSR protocol_param"
        case "obfs parameter":
            return "Optional SSR obfs_param, host or host#header"
        case "custom header":
            return "Optional HTTP header block"
        case "alpn":
            return "Optional, comma-separated values"
        case "fingerprint":
            return "Optional TLS fingerprint"
        case "certificate":
            return "Optional PEM or path"
        default:
            return "Optional"
        }
    }

    private func optionToggle(_ title: String, isOn: Binding<Bool>) -> some View {
        Toggle(title, isOn: isOn)
            .toggleStyle(.switch)
            .font(.custom(NeonCoreTheme.fontName, size: 12).weight(.bold))
            .foregroundStyle(NeonCoreTheme.muted)
            .frame(maxWidth: .infinity, minHeight: 42, alignment: .leading)
            .padding(.horizontal, 10)
            .background(NeonCoreTheme.panel2)
            .overlay(Rectangle().stroke(NeonCoreTheme.lineBright, lineWidth: 1))
    }

    private func picker(_ title: String, selection: Binding<String>, options: [String]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.custom(NeonCoreTheme.fontName, size: 12).weight(.bold))
                .foregroundStyle(NeonCoreTheme.muted)
                .textCase(.uppercase)
            Picker(title, selection: selection) {
                ForEach(options, id: \.self) { option in
                    Text(option.isEmpty ? "none" : option).tag(option)
                }
            }
            .pickerStyle(.menu)
            .frame(maxWidth: .infinity, minHeight: 42)
            .background(NeonCoreTheme.panel2)
            .overlay(Rectangle().stroke(NeonCoreTheme.lineBright, lineWidth: 1))
        }
    }
}

private struct ProfilesPage: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(spacing: 18) {
            HStack(spacing: 10) {
                TextField("subscription.import.url_placeholder".localized, text: $store.subscriptionURL)
                    .textFieldStyle(NeonTextFieldStyle())
                Button("profiles.action.import_subscription".localized) {
                    Task { await store.importSubscription() }
                }
                .buttonStyle(NeonPrimaryButtonStyle(active: false))
            }
            VStack(spacing: 1) {
                ForEach(store.profiles) { profile in
                    DataRow(primary: profile.name, secondary: profile.detail, trailing: "routing.mode.rule".localized, tone: .good)
                        .padding(14)
                        .background(NeonCoreTheme.panel2)
                }
            }
            .neonPanel()
        }
    }
}

private struct RoutingPage: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(spacing: 18) {
            HStack(alignment: .top, spacing: 18) {
                VStack(alignment: .leading, spacing: 14) {
                    Text("routing.mode.rule".localized)
                        .font(.custom(NeonCoreTheme.fontName, size: 20).weight(.bold))
                    Picker("", selection: $store.routingMode) {
                        Text("routing.mode.global".localized).tag("Global")
                        Text("routing.mode.rule".localized).tag("Rule")
                        Text("routing.mode.direct".localized).tag("Direct")
                    }
                    .pickerStyle(.segmented)
                }
                .padding(18)
                .neonPanel()

                VStack(alignment: .leading, spacing: 14) {
                    Text("dns.title".localized)
                        .font(.custom(NeonCoreTheme.fontName, size: 20).weight(.bold))
                    Picker("", selection: $store.dnsMode) {
                        Text("dns.mode.system".localized).tag("System")
                        Text("dns.mode.remote".localized).tag("Remote")
                        Text("dns.mode.parallel".localized).tag("Parallel")
                    }
                    .pickerStyle(.segmented)
                    Toggle("dns.prefer_ipv6".localized, isOn: $store.preferIPv6)
                }
                .padding(18)
                .neonPanel()
            }

            VStack(spacing: 1) {
                ForEach($store.rules) { $rule in
                    Toggle(isOn: $rule.enabled) {
                        DataRow(primary: rule.name, secondary: rule.matcher, trailing: rule.action, tone: rule.enabled ? .good : .muted)
                    }
                    .toggleStyle(.switch)
                    .padding(14)
                    .background(NeonCoreTheme.panel2)
                }
                if store.rules.isEmpty {
                    EmptyState(titleKey: "routing.rules.empty.title", descriptionKey: "routing.rules.empty.description")
                        .padding(14)
                        .background(NeonCoreTheme.panel2)
                }
            }
            .neonPanel()
        }
    }
}

private struct LogsPage: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(titleKey: "logs.title", actionKey: "logs.action.clear", systemImage: "trash") {
                store.clearLogs()
            }
            if store.logs.isEmpty {
                EmptyState(titleKey: "logs.empty", descriptionKey: "empty.logs.description")
            } else {
                ForEach(store.logs) { log in
                    DataRow(primary: log.messageKey.localized, secondary: log.time.formatted(date: .abbreviated, time: .standard), trailing: log.level.uppercased(), tone: log.level == "warn" ? .warn : .muted)
                }
            }
        }
        .padding(18)
        .neonPanel()
    }
}

private struct DiagnosticsPage: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(spacing: 18) {
            PageActions(titleKey: "settings.advanced", primaryKey: "diagnostics.action.run", primaryIcon: "waveform.path.ecg") {
                Task { await store.runDiagnostics() }
            } secondaryKey: {
                "nodes.action.test_latency"
            } secondaryAction: {
                Task { await store.testLatency() }
            }
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                MetricCard(titleKey: "diagnostics.daemon", value: store.status == .connected ? "Running" : "Stopped", footKey: "metric.ready")
                MetricCard(titleKey: "diagnostics.profile", value: "\(store.profiles.count)", footKey: "metric.loaded")
                MetricCard(titleKey: "diagnostics.latency", value: store.lastLatencyRun, footKey: "metric.latest")
            }
        }
    }
}

private struct SettingsPage: View {
    @ObservedObject var store: NeonCoreStore

    var body: some View {
        VStack(spacing: 18) {
            VStack(alignment: .leading, spacing: 14) {
                Text("settings.title".localized)
                    .font(.custom(NeonCoreTheme.fontName, size: 24).weight(.bold))
                Toggle("settings.launch_at_login".localized, isOn: .constant(false))
                Toggle("settings.show_advanced".localized, isOn: .constant(true))
                Toggle("settings.debug_logs".localized, isOn: .constant(true))
            }
            .padding(18)
            .neonPanel()
        }
    }
}

private struct PageActions: View {
    let titleKey: String
    let primaryKey: String
    let primaryIcon: String
    let primaryAction: () -> Void
    let secondaryKey: () -> String
    let secondaryAction: () -> Void

    var body: some View {
        HStack {
            Text(titleKey.localized)
                .font(.custom(NeonCoreTheme.fontName, size: 26).weight(.bold))
                .textCase(.uppercase)
            Spacer()
            Button {
                secondaryAction()
            } label: {
                Label(secondaryKey().localized, systemImage: "arrow.clockwise")
            }
            .buttonStyle(NeonSecondaryButtonStyle())
            Button {
                primaryAction()
            } label: {
                Label(primaryKey.localized, systemImage: primaryIcon)
            }
            .buttonStyle(NeonPrimaryButtonStyle(active: false))
        }
        .padding(18)
        .neonPanel()
    }
}

private struct SectionHeader: View {
    let titleKey: String
    let actionKey: String
    let systemImage: String
    let action: () -> Void

    var body: some View {
        HStack {
            Text(titleKey.localized)
                .font(.custom(NeonCoreTheme.fontName, size: 22).weight(.bold))
                .textCase(.uppercase)
            Spacer()
            Button {
                action()
            } label: {
                Label(actionKey.localized, systemImage: systemImage)
            }
            .buttonStyle(NeonSecondaryButtonStyle())
        }
    }
}

private struct MetricCard: View {
    let titleKey: String
    let value: String
    let footKey: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(titleKey.localized)
                .font(.custom(NeonCoreTheme.fontName, size: 12).weight(.bold))
                .foregroundStyle(NeonCoreTheme.muted)
                .textCase(.uppercase)
            Text(value)
                .font(.custom(NeonCoreTheme.fontName, size: 30).weight(.bold))
            Text(footKey.localized)
                .font(.custom(NeonCoreTheme.fontName, size: 12).weight(.semibold))
                .foregroundStyle(NeonCoreTheme.muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
        .neonPanel()
    }
}

private struct DataRow: View {
    let primary: String
    let secondary: String
    let trailing: String
    let tone: NeonCoreTone

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(primary)
                    .font(.custom(NeonCoreTheme.fontName, size: 15).weight(.bold))
                Text(secondary)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundStyle(NeonCoreTheme.muted)
            }
            Spacer()
            StatusPill(key: trailing, tone: tone)
        }
    }
}

private struct EmptyState: View {
    let titleKey: String
    let descriptionKey: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(titleKey.localized)
                .font(.custom(NeonCoreTheme.fontName, size: 20).weight(.bold))
            Text(descriptionKey.localized)
                .foregroundStyle(NeonCoreTheme.muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
    }
}

private enum NeonCoreTone {
    case good
    case warn
    case muted
}

private struct StatusPill: View {
    let key: String
    let tone: NeonCoreTone

    var body: some View {
        Text(key.localized)
            .font(.custom(NeonCoreTheme.fontName, size: 11).weight(.bold))
            .padding(.horizontal, 10)
            .frame(minHeight: 28)
            .foregroundStyle(color)
            .textCase(.uppercase)
            .overlay(Rectangle().stroke(color.opacity(0.65), lineWidth: 1))
            .background(color.opacity(0.08))
    }

    private var color: Color {
        switch tone {
        case .good: NeonCoreTheme.cyan
        case .warn: NeonCoreTheme.warn
        case .muted: NeonCoreTheme.muted
        }
    }
}

private struct NeonCoreBackground: View {
    var body: some View {
        ZStack {
            Color.black
            GridPattern()
                .stroke(.white.opacity(0.055), lineWidth: 1)
            LinearGradient(colors: [.black.opacity(0.12), NeonCoreTheme.blue.opacity(0.08), .black.opacity(0.2)], startPoint: .topLeading, endPoint: .bottomTrailing)
        }
        .ignoresSafeArea()
    }
}

private struct GridPattern: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        let step: CGFloat = 68
        var x: CGFloat = 0
        while x <= rect.maxX {
            path.move(to: CGPoint(x: x, y: rect.minY))
            path.addLine(to: CGPoint(x: x, y: rect.maxY))
            x += step
        }
        var y: CGFloat = 0
        while y <= rect.maxY {
            path.move(to: CGPoint(x: rect.minX, y: y))
            path.addLine(to: CGPoint(x: rect.maxX, y: y))
            y += step
        }
        return path
    }
}

private enum NeonCoreTheme {
    static let fontName = "Rajdhani"
    static let panel = Color(red: 0.02, green: 0.027, blue: 0.05)
    static let panel2 = Color(red: 0.031, green: 0.051, blue: 0.086)
    static let line = Color(red: 0.13, green: 0.145, blue: 0.19)
    static let lineBright = Color(red: 0.247, green: 0.278, blue: 0.365)
    static let muted = Color(red: 0.663, green: 0.702, blue: 0.784)
    static let cyan = Color(red: 0, green: 0.965, blue: 1)
    static let blue = Color(red: 0.255, green: 0.412, blue: 1)
    static let violet = Color(red: 0.722, green: 0.2, blue: 1)
    static let warn = Color(red: 1, green: 0.737, blue: 0.259)
}

private enum NeonCoreFont {
    static func register() {
        for file in ["rajdhani-400", "rajdhani-600", "rajdhani-700"] {
            guard let url = Bundle.module.url(forResource: file, withExtension: "woff2", subdirectory: "Fonts") else {
                continue
            }
            CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
        }
    }
}

private extension View {
    func neonPanel(active: Bool = false) -> some View {
        self
            .background(active ? NeonCoreTheme.cyan.opacity(0.08) : NeonCoreTheme.panel.opacity(0.94))
            .overlay(Rectangle().stroke(active ? NeonCoreTheme.cyan : NeonCoreTheme.lineBright, lineWidth: 1))
            .shadow(color: active ? NeonCoreTheme.cyan.opacity(0.22) : .clear, radius: 18)
    }
}

private struct NeonNavButtonStyle: ButtonStyle {
    let active: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .frame(minHeight: 44)
            .padding(.horizontal, 13)
            .foregroundStyle(active ? NeonCoreTheme.cyan : NeonCoreTheme.muted)
            .background(active || configuration.isPressed ? Color(red: 0.027, green: 0.035, blue: 0.063) : .clear)
            .overlay(alignment: .leading) {
                Rectangle()
                    .fill(NeonCoreTheme.cyan)
                    .frame(width: 3)
                    .opacity(active ? 1 : 0)
                    .shadow(color: NeonCoreTheme.cyan.opacity(0.65), radius: 12)
            }
            .overlay(Rectangle().stroke(active ? NeonCoreTheme.lineBright : .clear, lineWidth: 1))
    }
}

private struct NeonPrimaryButtonStyle: ButtonStyle {
    let active: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.custom(NeonCoreTheme.fontName, size: 13).weight(.bold))
            .textCase(.uppercase)
            .tracking(0.7)
            .padding(.horizontal, 16)
            .frame(minHeight: 42)
            .foregroundStyle(active ? .white : .black)
            .background(active ? NeonCoreTheme.panel2 : NeonCoreTheme.cyan)
            .overlay(Rectangle().stroke(NeonCoreTheme.cyan, lineWidth: 1))
            .shadow(color: NeonCoreTheme.cyan.opacity(configuration.isPressed ? 0.16 : 0.28), radius: 14)
    }
}

private struct NeonSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.custom(NeonCoreTheme.fontName, size: 12).weight(.bold))
            .textCase(.uppercase)
            .tracking(0.6)
            .padding(.horizontal, 14)
            .frame(minHeight: 40)
            .foregroundStyle(NeonCoreTheme.cyan)
            .background(configuration.isPressed ? NeonCoreTheme.cyan.opacity(0.12) : NeonCoreTheme.panel2)
            .overlay(Rectangle().stroke(NeonCoreTheme.lineBright, lineWidth: 1))
    }
}

private struct NeonTextFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .textFieldStyle(.plain)
            .font(.custom(NeonCoreTheme.fontName, size: 14).weight(.semibold))
            .padding(.horizontal, 12)
            .frame(height: 42)
            .background(NeonCoreTheme.panel2)
            .overlay(Rectangle().stroke(NeonCoreTheme.lineBright, lineWidth: 1))
    }
}

private extension String {
    var localized: String {
        XCStringCatalog.shared.value(for: self)
    }
}

private final class XCStringCatalog: @unchecked Sendable {
    static let shared = XCStringCatalog()

    private let values: [String: String]

    private init() {
        guard let url = Bundle.module.url(forResource: "Localizable", withExtension: "xcstrings"),
              let data = try? Data(contentsOf: url),
              let catalog = try? JSONDecoder().decode(Catalog.self, from: data)
        else {
            values = [:]
            return
        }
        let locale = Self.preferredLocale()
        values = catalog.strings.mapValues { entry in
            entry.localizations[locale]?.stringUnit.value
                ?? entry.localizations["en-AU"]?.stringUnit.value
                ?? entry.localizations["zh-Hans"]?.stringUnit.value
                ?? ""
        }
    }

    func value(for key: String) -> String {
        guard let value = values[key], !value.isEmpty else { return key }
        return value
    }

    private static func preferredLocale() -> String {
        let identifier = Locale.current.identifier
        if identifier.lowercased().hasPrefix("zh") {
            return "zh-Hans"
        }
        return "en-AU"
    }

    private struct Catalog: Decodable {
        let strings: [String: Entry]
    }

    private struct Entry: Decodable {
        let localizations: [String: Localization]
    }

    private struct Localization: Decodable {
        let stringUnit: StringUnit
    }

    private struct StringUnit: Decodable {
        let value: String
    }
}
