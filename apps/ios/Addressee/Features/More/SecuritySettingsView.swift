import SwiftUI

struct SecuritySettingsView: View {
    @ObservedObject var model: OpenPgpApplicationModel
    @AppStorage(SecuritySettings.softwareExportStorageKey) private var allowSoftwareKeyExport = false

    var body: some View {
        Form {
            Section {
                Toggle("security.export.software", isOn: $allowSoftwareKeyExport)
                    .accessibilityIdentifier("settings.security.allowSoftwareExport")
            } header: {
                Text("security.export.title")
            } footer: {
                Text("security.export.footer")
            }

            Section("security.enclave.title") {
                Label("security.enclave.p256", systemImage: "lock.shield")
                Text("security.enclave.nonExportable")
                    .foregroundStyle(.secondary)
                Text("security.enclave.biometricAuthorization")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                LabeledContent(
                    "security.enclave.bindings",
                    value: String(model.secureEnclaveBindings.count)
                )
                LabeledContent(
                    "security.enclave.registrations",
                    value: String(model.secureEnclaveRegistrations.count)
                )
                if model.secureEnclavePendingOperation != nil {
                    Label("security.enclave.pendingRecovery", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
                if !model.secureEnclavePersistentStateAvailable {
                    Text("security.enclave.persistenceUnavailable")
                        .foregroundStyle(.orange)
                }
                if !model.canGenerateSecureEnclave {
                    Text("security.enclave.validationPending")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Button("security.enclave.retryRestore") {
                    Task {
                        try? await model.restoreSecureEnclave()
                    }
                }
                .disabled(model.isBusy)
                .accessibilityIdentifier("action.security.secureEnclave.restore")
                if model.isBusy {
                    ProgressView("operation.inProgress")
                }
                if let errorMessage = model.errorMessage {
                    Text(errorMessage)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }

            Section("security.hardware.title") {
                if model.cardRegistrations.isEmpty {
                    Text("security.hardware.noLinkedDevices")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.cardRegistrations, id: \.certificateFingerprint) { registration in
                        LabeledContent("card.identity", value: registration.identity.displayIdentifier)
                    }
                }
                Text("security.hardware.sessionPersistence")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("more.security")
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityIdentifier("screen.more.security")
    }
}
