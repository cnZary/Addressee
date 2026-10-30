import SwiftUI

struct HardwareKeyManagementView: View {
    @ObservedObject var model: OpenPgpApplicationModel
    @AppStorage(HardwareConnectionSettings.multipleHardwareKeysStorageKey)
    private var allowsMultipleHardwareKeys = false
    @State private var connection = CardConnectionSelection()
    @State private var information: CardInformationFfi?

    var body: some View {
        Form {
            Section("hardware.devices") {
                Text("hardware.standaloneManagement")
                    .accessibilityIdentifier("hardware.standaloneManagement")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                CardConnectionPicker(
                    model: model,
                    selection: $connection,
                    identifier: "hardware.management"
                )
                Button("hardware.inspect") {
                    Task { await inspect() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canInspect)
                .accessibilityIdentifier("action.hardware.connect")
            }

            if let information {
                Section("hardware.detectedDevice") {
                    NavigationLink {
                        CardDeviceManagementView(
                            model: model,
                            identity: information.identity,
                            information: information,
                            connection: connection
                        )
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(information.identity.displayIdentifier)
                            Text("hardware.manageDetected")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityIdentifier("navigation.hardware.device.\(information.identity.displayIdentifier)")
                }
            }

            Section("hardware.currentLimitations") {
                Text("hardware.validationPending")
            }

            if model.isBusy {
                ProgressView("operation.inProgress")
            }
            if let errorMessage = model.errorMessage {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
        .disabled(model.isBusy)
        .navigationTitle("more.hardware")
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("screen.more.hardware")
        .onChange(of: connection) { _ in information = nil }
    }

    private var canInspect: Bool {
        !model.isBusy
            && connection.isComplete(allowsMultipleHardwareKeys: allowsMultipleHardwareKeys)
            && (connection.method != .nfc || CardTransportFactory.nfcIsAvailable())
    }

    private func inspect() async {
        do {
            information = try await model.inspectHardware(connection: connection)
        } catch {}
    }
}
