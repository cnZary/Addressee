import SwiftUI

struct MoreView: View {
    @ObservedObject var model: OpenPgpApplicationModel

    var body: some View {
        NavigationStack {
            List {
                Section("more.section.navigation") {
                    NavigationLink {
                        HardwareKeyManagementView(model: model)
                    } label: {
                        Label("more.hardware", systemImage: "cpu")
                    }
                    .accessibilityIdentifier("navigation.more.hardware")

                    NavigationLink {
                        SecuritySettingsView(model: model)
                    } label: {
                        Label("more.security", systemImage: "lock.shield")
                    }
                    .accessibilityIdentifier("navigation.more.security")

                    NavigationLink {
                        ApplicationSettingsView()
                    } label: {
                        Label("more.application", systemImage: "gearshape")
                    }
                    .accessibilityIdentifier("navigation.more.application")

                    NavigationLink {
                        AboutView()
                    } label: {
                        Label("more.about", systemImage: "info.circle")
                    }
                    .accessibilityIdentifier("navigation.more.about")
                }
            }
            .navigationTitle("more.title")
            .accessibilityIdentifier("screen.more")
        }
    }
}
