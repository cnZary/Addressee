import SwiftUI

struct CardAssociationView: View {
    let summary: CertificateSummary
    @ObservedObject var model: OpenPgpApplicationModel
    @Environment(\.dismiss) private var dismiss
    @AppStorage(HardwareConnectionSettings.multipleHardwareKeysStorageKey)
    private var allowsMultipleHardwareKeys = false
    @State private var connection = CardConnectionSelection()
    @State private var hasInitializedSelection = false
    @State private var signingComponent = ""
    @State private var decryptionComponent = ""
    @State private var showLinkConfirmation = false

    var body: some View {
        Form {
            Section("hardware.certificate") {
                LabeledContent("keys.details.identity") {
                    Text(summary.displayName)
                }
                Text(summary.fingerprint)
                    .font(.caption)
                    .textSelection(.enabled)
                componentPicker(
                    title: "hardware.signingComponent",
                    identifier: "field.hardware.signingComponent",
                    components: signingComponents,
                    selection: $signingComponent
                )
                componentPicker(
                    title: "hardware.decryptionComponent",
                    identifier: "field.hardware.decryptionComponent",
                    components: decryptionComponents,
                    selection: $decryptionComponent
                )
            }

            CardConnectionPicker(
                model: model,
                selection: $connection,
                identifier: "keys.hardware.associate"
            )

            Section {
                Button("hardware.connect") {
                    Task { await connect() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canConnect)
                .accessibilityIdentifier("action.keys.hardware.connect")
            } footer: {
                Text("hardware.readOnlyConnectionNote")
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
        .navigationTitle("keys.hardware.link")
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityIdentifier("screen.keys.hardware.associate")
        .onAppear {
            guard !hasInitializedSelection else { return }
            hasInitializedSelection = true
            connection = model.preferredCardConnection(for: summary.fingerprint)
            selectComponents()
        }
        .alert("hardware.linkSucceeded", isPresented: $showLinkConfirmation) {
            Button("hardware.linkDone") { dismiss() }
        } message: {
            Text("hardware.linkSucceededMessage")
            Text(summary.displayName)
        }
    }

    private var signingComponents: [KeyMetadataSummary] {
        summary.subkeys.filter { $0.keyFlags.sign }
    }

    private var decryptionComponents: [KeyMetadataSummary] {
        summary.subkeys.filter {
            $0.keyFlags.encryptCommunications || $0.keyFlags.encryptStorage
        }
    }

    private var canConnect: Bool {
        !model.isBusy
            && (!signingComponent.isEmpty || !decryptionComponent.isEmpty)
            && connection.isComplete(allowsMultipleHardwareKeys: allowsMultipleHardwareKeys)
            && (connection.method != .nfc || CardTransportFactory.nfcIsAvailable())
    }

    @ViewBuilder
    private func componentPicker(
        title: LocalizedStringKey,
        identifier: String,
        components: [KeyMetadataSummary],
        selection: Binding<String>
    ) -> some View {
        if components.isEmpty {
            LabeledContent(title) {
                Text("hardware.component.none")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        } else {
            Picker(title, selection: selection) {
                Text("hardware.component.notConnected").tag("")
                ForEach(components, id: \.fingerprint) { component in
                    Text("\(component.algorithm.name) \(component.fingerprint.suffix(8))")
                        .tag(component.fingerprint)
                }
            }
            .accessibilityIdentifier(identifier)
        }
    }

    private func selectComponents() {
        signingComponent = signingComponents.count == 1 ? signingComponents[0].fingerprint : ""
        decryptionComponent = decryptionComponents.count == 1 ? decryptionComponents[0].fingerprint : ""
    }

    private func connect() async {
        do {
            _ = try await model.connectCard(
                certificateFingerprint: summary.fingerprint,
                signingComponent: signingComponent.isEmpty ? nil : signingComponent,
                decryptionComponent: decryptionComponent.isEmpty ? nil : decryptionComponent,
                method: connection.method,
                readerName: connection.readerName
            )
            showLinkConfirmation = true
        } catch {}
    }
}
