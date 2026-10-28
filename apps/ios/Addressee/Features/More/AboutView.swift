import SwiftUI

struct AboutView: View {
    private var version: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1"
        return "\(version) (\(build))"
    }

    var body: some View {
        Form {
            Section {
                LabeledContent("about.version", value: version)
                Text("about.description")
                    .foregroundStyle(.secondary)
            }

            Section("about.integration") {
                Label("about.integration.unconnected", systemImage: "link.circle")
                Text("about.hardware")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("more.about")
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityIdentifier("screen.more.about")
    }
}
