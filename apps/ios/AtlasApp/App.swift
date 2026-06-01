import SwiftUI

@main
struct AtlasApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

struct ContentView: View {
    var body: some View {
        NavigationSplitView {
            List {
                Text("nav.dashboard")
                Text("nav.nodes")
                Text("nav.profiles")
                Text("nav.routing")
                Text("nav.logs")
                Text("nav.settings")
            }
            .navigationTitle(Text("app.name"))
        } detail: {
            VStack(alignment: .leading, spacing: 16) {
                Text("app.name").font(.largeTitle.bold())
                Text("connection.status.disconnected")
                    .font(.title2)
                    .padding()
                Button(String(localized: "connection.action.connect")) {}
                    .accessibilityLabel(Text("accessibility.connect_button"))
                    .help(String(localized: "tooltip.connect_button"))
                Text("nodes.empty.title").font(.headline)
                Text("nodes.empty.description")
                TextField(String(localized: "subscription.import.url_placeholder"), text: .constant(""))
            }
            .padding()
        }
    }
}
