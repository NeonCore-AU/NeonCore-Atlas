import Foundation
import Network
import CoreText
import SwiftUI

@main
struct NeonCoreMacApp: App {
    init() {
        NeonCoreFont.register()
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
    @Published var subscriptionURL = ""
    @Published var routingMode = "Rule"
    @Published var dnsMode = "System"
    @Published var preferIPv6 = false
    @Published var proxyBytesIn = 0
    @Published var proxyBytesOut = 0
    @Published var directBytesIn = 0
    @Published var directBytesOut = 0
    @Published var lastLatencyRun = "--"
    @Published var localProxyPort = 7890
    @Published var logs: [NeonCoreLog] = [
        .init(level: "info", messageKey: "log.app_ready"),
    ]
    @Published var nodes: [NeonCoreNode] = []
    @Published var profiles: [NeonCoreProfile] = []
    @Published var rules: [NeonCoreRule] = []

    private let engine = NeonCoreKernel()

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
        do {
            try engine.start(node: node, port: localProxyPort)
            try SystemProxy.enable(port: localProxyPort)
            status = .connected
            activeNodeID = node.id
            log("log.connected")
        } catch {
            status = .disconnected
            log("log.protocol_adapter_missing", level: "warn")
        }
    }

    private func disconnect() {
        engine.stop()
        try? SystemProxy.disable()
        status = .disconnected
        log("log.disconnected")
    }
}

private struct NeonCoreNode: Identifiable {
    let id = UUID()
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
}

private struct NeonCoreProfile: Identifiable {
    let id = UUID()
    var name: String
    var detail: String
}

private struct NeonCoreRule: Identifiable {
    let id = UUID()
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
            .compactMap { parseNode(String($0)) }
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

    private static func parseNode(_ line: String) -> NeonCoreNode? {
        if line.lowercased().hasPrefix("ss://") {
            return parseShadowsocksNode(line)
        }
        guard let components = URLComponents(string: line),
              let scheme = components.scheme?.lowercased(),
              let host = components.host,
              let port = components.port
        else { return nil }

        let userID = components.user ?? ""
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

    private static func parseShadowsocksNode(_ line: String) -> NeonCoreNode? {
        let fragment = URLComponents(string: line)?.percentEncodedFragment?.removingPercentEncoding
        let withoutScheme = String(line.dropFirst("ss://".count))
        let body = withoutScheme.split(separator: "#", maxSplits: 1).first.map(String.init) ?? withoutScheme
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
            query: ["method": method],
            latency: nil,
            tags: ["SS", method.uppercased()]
        )
    }

    private static func tagsFor(scheme: String, query: [String: String]) -> [String] {
        var tags = [scheme.uppercased()]
        if let security = query["security"], security != "none" { tags.append(security.uppercased()) }
        if query["flow"] != nil { tags.append("VISION") }
        return tags
    }

    private static func region(from name: String) -> String {
        if name.contains("澳大利亚") { return "AU" }
        if name.contains("美国") { return "US" }
        if name.contains("日本") { return "JP" }
        if name.contains("香港") { return "HK" }
        if name.contains("新加坡") { return "SG" }
        return "GLOBAL"
    }
}

private final class NeonCoreKernel {
    private var process: Process?
    private var configURL: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("neoncore-kernel-session.json")
    }

    var isAvailable: Bool {
        binaryURL != nil
    }

    func start(node: NeonCoreNode, port: Int) throws {
        stop()
        guard let binaryURL else { throw NeonCoreError.engineMissing }
        let session = try makeSession(node: node, port: port)
        try session.write(to: configURL)
        try checkSession(binaryURL: binaryURL)
        let process = Process()
        process.executableURL = binaryURL
        process.arguments = ["run", "--session", configURL.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        self.process = process
    }

    func stop() {
        process?.terminate()
        process = nil
    }

    private var binaryURL: URL? {
        let bundleURL = Bundle.main.resourceURL?.appendingPathComponent("neoncore-kernel")
        if let bundleURL, FileManager.default.isExecutableFile(atPath: bundleURL.path) {
            return bundleURL
        }
        let local = URL(fileURLWithPath: "/Users/neoncore/NeonCore Dev/neoncore-atlas/target/debug/neoncore-kernel")
        if FileManager.default.isExecutableFile(atPath: local.path) {
            return local
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
        [
            "protocol": node.protocolName,
            "server": node.host,
            "server_port": node.port,
            "user_id": node.userID,
            "parameters": node.query
        ]
    }

    private func checkSession(binaryURL: URL) throws {
        let process = Process()
        process.executableURL = binaryURL
        process.arguments = ["check", "--session", configURL.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        if process.terminationStatus != 0 {
            throw NeonCoreError.unsupportedProtocol
        }
    }
}

private enum SystemProxy {
    static func enable(port: Int) throws {
        for service in try activeServices() {
            try run("/usr/sbin/networksetup", ["-setsocksfirewallproxy", service, "127.0.0.1", "\(port)"])
            try run("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", service, "on"])
            try run("/usr/sbin/networksetup", ["-setwebproxy", service, "127.0.0.1", "\(port)"])
            try run("/usr/sbin/networksetup", ["-setwebproxystate", service, "on"])
            try run("/usr/sbin/networksetup", ["-setsecurewebproxy", service, "127.0.0.1", "\(port)"])
            try run("/usr/sbin/networksetup", ["-setsecurewebproxystate", service, "on"])
        }
    }

    static func disable() throws {
        for service in try activeServices() {
            try run("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", service, "off"])
            try run("/usr/sbin/networksetup", ["-setwebproxystate", service, "off"])
            try run("/usr/sbin/networksetup", ["-setsecurewebproxystate", service, "off"])
        }
    }

    private static func activeServices() throws -> [String] {
        let output = try capture("/usr/sbin/networksetup", ["-listallnetworkservices"])
        let services = output
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .filter { !$0.hasPrefix("An asterisk") && !$0.hasPrefix("*") }
        return services.isEmpty ? ["Wi-Fi"] : services
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
}

private final class ProbeState: @unchecked Sendable {
    private let lock = NSLock()
    private var finished = false

    func markFinished() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !finished else { return false }
        finished = true
        return true
    }
}

private enum NeonCoreError: Error {
    case invalidURL
    case subscriptionFailed
    case engineMissing
    case unsupportedProtocol
    case systemProxyFailed
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
            PageActions(titleKey: "nav.nodes", primaryKey: "profiles.action.import_subscription", primaryIcon: "square.and.arrow.down") {
                store.selectedPage = .profiles
            } secondaryKey: {
                "nodes.action.test_latency"
            } secondaryAction: {
                Task { await store.testLatency() }
            }
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
        let value = String(localized: String.LocalizationValue(self), bundle: .module)
        return value == self ? self : value
    }
}
