import SwiftUI

struct ApplicationSettingsView: View {
    @AppStorage(AppAppearance.storageKey) private var appearanceRawValue = AppAppearance.system.rawValue
    @AppStorage(HardwareConnectionSettings.multipleHardwareKeysStorageKey)
    private var allowsMultipleHardwareKeys = false

    private var appearance: Binding<AppAppearance> {
        Binding {
            AppAppearance(rawValue: appearanceRawValue) ?? .system
        } set: { newValue in
            appearanceRawValue = newValue.rawValue
        }
    }

    var body: some View {
        Form {
            Section {
                Picker("application.appearance", selection: appearance) {
                    ForEach(AppAppearance.allCases) { appearance in
                        Text(appearance.title).tag(appearance)
                    }
                }
                .accessibilityIdentifier("settings.application.appearance")
            }
            Section {
                Toggle("application.multipleHardwareKeys", isOn: $allowsMultipleHardwareKeys)
                    .accessibilityIdentifier("settings.application.multipleHardwareKeys")
            } footer: {
                Text("application.multipleHardwareKeysNote")
            }
        }
        .navigationTitle("more.application")
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityIdentifier("screen.more.application")
    }
}
