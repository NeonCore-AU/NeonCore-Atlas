import SwiftUI

@main
struct AtlasMacApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 1120, minHeight: 720)
        }
        .windowStyle(.hiddenTitleBar)
    }
}

private enum AtlasPage: String, CaseIterable, Identifiable {
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
private final class AtlasStore: ObservableObject {
    @Published var selectedPage: AtlasPage = .dashboard
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
    @Published var logs: [AtlasLog] = [
        .init(level: "info", messageKey: "log.app_ready"),
        .init(level: "info", messageKey: "log.daemon_mock_ready"),
    ]
    @Published var nodes: [AtlasNode] = [
        .init(name: "Sydney Edge", region: "AU", endpoint: "syd-atlas-01.local", latency: nil, tags: ["TLS", "UDP"]),
        .init(name: "Tokyo Relay", region: "JP", endpoint: "tyo-atlas-01.local", latency: nil, tags: ["TLS"]),
        .init(name: "Singapore Core", region: "SG", endpoint: "sin-atlas-01.local", latency: nil, tags: ["UDP"]),
    ]
    @Published var profiles: [AtlasProfile] = [
        .init(name: "Daily Driver", detail: "3 nodes · rule routing"),
        .init(name: "Diagnostics Lab", detail: "local mock profile"),
    ]
    @Published var rules: [AtlasRule] = [
        .init(name: "Local network", matcher: "192.168.0.0/16", action: "Direct", enabled: true),
        .init(name: "Media profile", matcher: "domain keyword", action: "Proxy", enabled: true),
        .init(name: "Blocked endpoint", matcher: "example.invalid", action: "Reject", enabled: false),
    ]
    @Published var rewrites: [RewriteItem] = [
        .init(name: "API version header", pattern: "^/api/v1", enabled: true),
        .init(name: "Debug marker", pattern: "X-Atlas-Debug", enabled: false),
    ]

    var activeNode: AtlasNode? {
        nodes.first { $0.id == activeNodeID } ?? nodes.first
    }

    var statusKey: String {
        status == .connected ? "connection.status.connected" : "connection.status.disconnected"
    }

    func toggleConnection() {
        if status == .connected {
            status = .disconnected
            activeNodeID = nil
            log("log.disconnected")
        } else {
            status = .connected
            activeNodeID = nodes.first?.id
            proxyBytesIn += 12_800_000
            proxyBytesOut += 3_600_000
            directBytesIn += 1_900_000
            directBytesOut += 760_000
            log("log.connected")
        }
    }

    func selectNode(_ node: AtlasNode) {
        activeNodeID = node.id
        status = .connected
        log("log.node_selected")
    }

    func importSubscription() {
        let value = subscriptionURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.hasPrefix("https://") || value.hasPrefix("http://") else {
            log("subscription.import.error_invalid_url", level: "warn")
            return
        }
        profiles.append(.init(name: "Imported Profile \(profiles.count + 1)", detail: "subscription · merge strategy"))
        subscriptionURL = ""
        log("subscription.import.success")
    }

    func addManualNode() {
        nodes.append(.init(name: "Manual Node \(nodes.count + 1)", region: "Custom", endpoint: "manual-\(nodes.count + 1).local", latency: nil, tags: ["TLS"]))
        log("log.node_added")
    }

    func testLatency() {
        for index in nodes.indices {
            nodes[index].latency = 34 + index * 41
        }
        lastLatencyRun = Date.now.formatted(date: .omitted, time: .shortened)
        log("log.latency_completed")
    }

    func addRule() {
        rules.append(.init(name: "Rule \(rules.count + 1)", matcher: "domain suffix", action: "Proxy", enabled: true))
        log("log.rule_added")
    }

    func addRewrite() {
        rewrites.append(.init(name: "Rewrite \(rewrites.count + 1)", pattern: "^/mock", enabled: true))
        log("log.rewrite_added")
    }

    func runDiagnostics() {
        log("log.diagnostics_completed")
    }

    func clearLogs() {
        logs.removeAll()
    }

    func log(_ messageKey: String, level: String = "info") {
        logs.insert(.init(level: level, messageKey: messageKey), at: 0)
    }
}

private struct AtlasNode: Identifiable {
    let id = UUID()
    var name: String
    var region: String
    var endpoint: String
    var latency: Int?
    var tags: [String]
}

private struct AtlasProfile: Identifiable {
    let id = UUID()
    var name: String
    var detail: String
}

private struct AtlasRule: Identifiable {
    let id = UUID()
    var name: String
    var matcher: String
    var action: String
    var enabled: Bool
}

private struct RewriteItem: Identifiable {
    let id = UUID()
    var name: String
    var pattern: String
    var enabled: Bool
}

private struct AtlasLog: Identifiable {
    let id = UUID()
    let time = Date.now
    var level: String
    var messageKey: String
}

struct ContentView: View {
    @StateObject private var store = AtlasStore()

    var body: some View {
        ZStack {
            AtlasBackground()
            HStack(spacing: 0) {
                Sidebar(store: store)
                Workspace(store: store)
            }
        }
        .preferredColorScheme(.dark)
    }
}

private struct Sidebar: View {
    @ObservedObject var store: AtlasStore

    var body: some View {
        VStack(spacing: 18) {
            VStack(spacing: 2) {
                Text("app.name".localized)
                    .font(.system(size: 24, weight: .black, design: .rounded))
                    .foregroundStyle(.white)
                Text("app.tagline".localized)
                    .font(.system(size: 11, weight: .bold, design: .rounded))
                    .foregroundStyle(AtlasTheme.muted)
                    .textCase(.uppercase)
            }
            .frame(maxWidth: .infinity, minHeight: 86)
            .overlay(alignment: .bottom) {
                Rectangle().fill(AtlasTheme.line).frame(height: 1)
            }

            VStack(spacing: 8) {
                ForEach(AtlasPage.allCases) { page in
                    Button {
                        store.selectedPage = page
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: page.symbol)
                                .frame(width: 20)
                            Text(page.titleKey.localized)
                                .font(.system(size: 13, weight: .heavy, design: .rounded))
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
                    .font(.system(size: 11, weight: .bold, design: .rounded))
                    .foregroundStyle(AtlasTheme.muted)
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
            Rectangle().fill(AtlasTheme.line).frame(width: 1)
        }
    }
}

private struct Workspace: View {
    @ObservedObject var store: AtlasStore

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
    @ObservedObject var store: AtlasStore

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("topbar.control_plane".localized)
                    .font(.system(size: 11, weight: .black, design: .rounded))
                    .foregroundStyle(AtlasTheme.cyan)
                    .textCase(.uppercase)
                Text(store.selectedPage.titleKey.localized)
                    .font(.system(size: 44, weight: .black, design: .rounded))
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
            Rectangle().fill(AtlasTheme.line).frame(height: 1)
        }
    }
}

private struct DashboardPage: View {
    @ObservedObject var store: AtlasStore

    var body: some View {
        VStack(spacing: 18) {
            HeroPanel(store: store)
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 14), count: 4), spacing: 14) {
                MetricCard(titleKey: "metric.nodes", value: "\(store.nodes.count)", footKey: "metric.ready")
                MetricCard(titleKey: "metric.profiles", value: "\(store.profiles.count)", footKey: "metric.loaded")
                MetricCard(titleKey: "metric.latency", value: store.nodes.compactMap(\.latency).first.map { "\($0) ms" } ?? "--", footKey: "metric.latest")
                MetricCard(titleKey: "metric.traffic", value: ByteCountFormatter.string(fromByteCount: Int64(store.proxyBytesIn + store.proxyBytesOut), countStyle: .binary), footKey: "metric.mock_runtime")
            }
            HStack(alignment: .top, spacing: 18) {
                NodesSummary(store: store)
                LogsSummary(store: store)
            }
        }
    }
}

private struct HeroPanel: View {
    @ObservedObject var store: AtlasStore

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("dashboard.hero.title".localized)
                        .font(.system(size: 58, weight: .black, design: .rounded))
                        .lineLimit(2)
                        .textCase(.uppercase)
                    Text("dashboard.hero.subtitle".localized)
                        .font(.system(size: 16, weight: .semibold, design: .rounded))
                        .foregroundStyle(AtlasTheme.muted)
                }
                Spacer()
                TrafficDial(store: store)
            }

            HStack(spacing: 10) {
                TextField("subscription.import.url_placeholder".localized, text: $store.subscriptionURL)
                    .textFieldStyle(NeonTextFieldStyle())
                Button {
                    store.importSubscription()
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
            LinearGradient(colors: [AtlasTheme.cyan, AtlasTheme.blue, AtlasTheme.violet], startPoint: .leading, endPoint: .trailing)
                .frame(height: 2)
        }
    }
}

private struct TrafficDial: View {
    @ObservedObject var store: AtlasStore

    var body: some View {
        ZStack {
            Circle()
                .stroke(.white.opacity(0.08), lineWidth: 18)
            Circle()
                .trim(from: 0, to: store.status == .connected ? 0.72 : 0.18)
                .stroke(AtlasTheme.cyan, style: StrokeStyle(lineWidth: 18, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .shadow(color: AtlasTheme.cyan.opacity(0.55), radius: 14)
            VStack(spacing: 2) {
                Text(store.status == .connected ? "72%" : "18%")
                    .font(.system(size: 34, weight: .black, design: .rounded))
                Text("metric.session".localized)
                    .font(.system(size: 11, weight: .bold, design: .rounded))
                    .foregroundStyle(AtlasTheme.muted)
                    .textCase(.uppercase)
            }
        }
        .frame(width: 156, height: 156)
    }
}

private struct NodesSummary: View {
    @ObservedObject var store: AtlasStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(titleKey: "nav.nodes", actionKey: "nodes.action.test_latency", systemImage: "timer") {
                store.testLatency()
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
    @ObservedObject var store: AtlasStore

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
    @ObservedObject var store: AtlasStore

    var body: some View {
        VStack(spacing: 18) {
            PageActions(titleKey: "nodes.empty.title", primaryKey: "nodes.action.add_manual", primaryIcon: "plus") {
                store.addManualNode()
            } secondaryKey: {
                "nodes.action.test_latency"
            } secondaryAction: {
                store.testLatency()
            }
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                ForEach(store.nodes) { node in
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(node.name)
                                    .font(.system(size: 20, weight: .black, design: .rounded))
                                Text(node.endpoint)
                                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                    .foregroundStyle(AtlasTheme.muted)
                            }
                            Spacer()
                            StatusPill(key: node.latency.map { "\($0) ms" } ?? "nodes.latency.unknown", tone: node.latency == nil ? .muted : .good)
                        }
                        HStack {
                            ForEach(node.tags, id: \.self) { tag in
                                Text(tag)
                                    .font(.system(size: 11, weight: .black, design: .rounded))
                                    .padding(.horizontal, 9)
                                    .frame(height: 26)
                                    .overlay(RoundedRectangle(cornerRadius: 0).stroke(AtlasTheme.lineBright))
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
        }
    }
}

private struct ProfilesPage: View {
    @ObservedObject var store: AtlasStore

    var body: some View {
        VStack(spacing: 18) {
            HStack(spacing: 10) {
                TextField("subscription.import.url_placeholder".localized, text: $store.subscriptionURL)
                    .textFieldStyle(NeonTextFieldStyle())
                Button("profiles.action.import_subscription".localized) {
                    store.importSubscription()
                }
                .buttonStyle(NeonPrimaryButtonStyle(active: false))
            }
            VStack(spacing: 1) {
                ForEach(store.profiles) { profile in
                    DataRow(primary: profile.name, secondary: profile.detail, trailing: "routing.mode.rule".localized, tone: .good)
                        .padding(14)
                        .background(AtlasTheme.panel2)
                }
            }
            .neonPanel()
        }
    }
}

private struct RoutingPage: View {
    @ObservedObject var store: AtlasStore

    var body: some View {
        VStack(spacing: 18) {
            HStack(alignment: .top, spacing: 18) {
                VStack(alignment: .leading, spacing: 14) {
                    Text("routing.mode.rule".localized)
                        .font(.system(size: 20, weight: .black, design: .rounded))
                    Picker("", selection: $store.routingMode) {
                        Text("routing.mode.global".localized).tag("Global")
                        Text("routing.mode.rule".localized).tag("Rule")
                        Text("routing.mode.direct".localized).tag("Direct")
                    }
                    .pickerStyle(.segmented)
                    Button {
                        store.addRule()
                    } label: {
                        Label("routing.action.add_rule".localized, systemImage: "plus")
                    }
                    .buttonStyle(NeonSecondaryButtonStyle())
                }
                .padding(18)
                .neonPanel()

                VStack(alignment: .leading, spacing: 14) {
                    Text("dns.title".localized)
                        .font(.system(size: 20, weight: .black, design: .rounded))
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
                    .background(AtlasTheme.panel2)
                }
            }
            .neonPanel()

            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(titleKey: "rewrite.title", actionKey: "rewrite.action.add", systemImage: "plus") {
                    store.addRewrite()
                }
                ForEach($store.rewrites) { $rewrite in
                    Toggle(isOn: $rewrite.enabled) {
                        DataRow(primary: rewrite.name, secondary: rewrite.pattern, trailing: rewrite.enabled ? "settings.enabled".localized : "settings.disabled".localized, tone: rewrite.enabled ? .good : .muted)
                    }
                    .toggleStyle(.switch)
                }
            }
            .padding(18)
            .neonPanel()
        }
    }
}

private struct LogsPage: View {
    @ObservedObject var store: AtlasStore

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
    @ObservedObject var store: AtlasStore

    var body: some View {
        VStack(spacing: 18) {
            PageActions(titleKey: "settings.advanced", primaryKey: "diagnostics.action.run", primaryIcon: "waveform.path.ecg") {
                store.runDiagnostics()
            } secondaryKey: {
                "nodes.action.test_latency"
            } secondaryAction: {
                store.testLatency()
            }
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                MetricCard(titleKey: "diagnostics.daemon", value: "Mock", footKey: "metric.ready")
                MetricCard(titleKey: "diagnostics.profile", value: "\(store.profiles.count)", footKey: "metric.loaded")
                MetricCard(titleKey: "diagnostics.latency", value: store.lastLatencyRun, footKey: "metric.latest")
            }
        }
    }
}

private struct SettingsPage: View {
    @ObservedObject var store: AtlasStore

    var body: some View {
        VStack(spacing: 18) {
            VStack(alignment: .leading, spacing: 14) {
                Text("settings.title".localized)
                    .font(.system(size: 24, weight: .black, design: .rounded))
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
                .font(.system(size: 26, weight: .black, design: .rounded))
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
                .font(.system(size: 22, weight: .black, design: .rounded))
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
                .font(.system(size: 12, weight: .black, design: .rounded))
                .foregroundStyle(AtlasTheme.muted)
                .textCase(.uppercase)
            Text(value)
                .font(.system(size: 30, weight: .black, design: .rounded))
            Text(footKey.localized)
                .font(.system(size: 12, weight: .semibold, design: .rounded))
                .foregroundStyle(AtlasTheme.muted)
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
    let tone: AtlasTone

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(primary)
                    .font(.system(size: 15, weight: .black, design: .rounded))
                Text(secondary)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundStyle(AtlasTheme.muted)
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
                .font(.system(size: 20, weight: .black, design: .rounded))
            Text(descriptionKey.localized)
                .foregroundStyle(AtlasTheme.muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
    }
}

private enum AtlasTone {
    case good
    case warn
    case muted
}

private struct StatusPill: View {
    let key: String
    let tone: AtlasTone

    var body: some View {
        Text(key.localized)
            .font(.system(size: 11, weight: .black, design: .rounded))
            .padding(.horizontal, 10)
            .frame(minHeight: 28)
            .foregroundStyle(color)
            .textCase(.uppercase)
            .overlay(Rectangle().stroke(color.opacity(0.65), lineWidth: 1))
            .background(color.opacity(0.08))
    }

    private var color: Color {
        switch tone {
        case .good: AtlasTheme.cyan
        case .warn: AtlasTheme.warn
        case .muted: AtlasTheme.muted
        }
    }
}

private struct AtlasBackground: View {
    var body: some View {
        ZStack {
            Color.black
            GridPattern()
                .stroke(.white.opacity(0.055), lineWidth: 1)
            LinearGradient(colors: [.black.opacity(0.12), AtlasTheme.blue.opacity(0.08), .black.opacity(0.2)], startPoint: .topLeading, endPoint: .bottomTrailing)
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

private enum AtlasTheme {
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

private extension View {
    func neonPanel(active: Bool = false) -> some View {
        self
            .background(active ? AtlasTheme.cyan.opacity(0.08) : AtlasTheme.panel.opacity(0.94))
            .overlay(Rectangle().stroke(active ? AtlasTheme.cyan : AtlasTheme.lineBright, lineWidth: 1))
            .shadow(color: active ? AtlasTheme.cyan.opacity(0.22) : .clear, radius: 18)
    }
}

private struct NeonNavButtonStyle: ButtonStyle {
    let active: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .frame(minHeight: 44)
            .padding(.horizontal, 13)
            .foregroundStyle(active ? AtlasTheme.cyan : AtlasTheme.muted)
            .background(active || configuration.isPressed ? Color(red: 0.027, green: 0.035, blue: 0.063) : .clear)
            .overlay(alignment: .leading) {
                Rectangle()
                    .fill(AtlasTheme.cyan)
                    .frame(width: 3)
                    .opacity(active ? 1 : 0)
                    .shadow(color: AtlasTheme.cyan.opacity(0.65), radius: 12)
            }
            .overlay(Rectangle().stroke(active ? AtlasTheme.lineBright : .clear, lineWidth: 1))
    }
}

private struct NeonPrimaryButtonStyle: ButtonStyle {
    let active: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .black, design: .rounded))
            .textCase(.uppercase)
            .tracking(0.7)
            .padding(.horizontal, 16)
            .frame(minHeight: 42)
            .foregroundStyle(active ? .white : .black)
            .background(active ? AtlasTheme.panel2 : AtlasTheme.cyan)
            .overlay(Rectangle().stroke(AtlasTheme.cyan, lineWidth: 1))
            .shadow(color: AtlasTheme.cyan.opacity(configuration.isPressed ? 0.16 : 0.28), radius: 14)
    }
}

private struct NeonSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .black, design: .rounded))
            .textCase(.uppercase)
            .tracking(0.6)
            .padding(.horizontal, 14)
            .frame(minHeight: 40)
            .foregroundStyle(AtlasTheme.cyan)
            .background(configuration.isPressed ? AtlasTheme.cyan.opacity(0.12) : AtlasTheme.panel2)
            .overlay(Rectangle().stroke(AtlasTheme.lineBright, lineWidth: 1))
    }
}

private struct NeonTextFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .textFieldStyle(.plain)
            .font(.system(size: 14, weight: .semibold, design: .rounded))
            .padding(.horizontal, 12)
            .frame(height: 42)
            .background(AtlasTheme.panel2)
            .overlay(Rectangle().stroke(AtlasTheme.lineBright, lineWidth: 1))
    }
}

private extension String {
    var localized: String {
        let value = String(localized: String.LocalizationValue(self), bundle: .module)
        return value == self ? self : value
    }
}
