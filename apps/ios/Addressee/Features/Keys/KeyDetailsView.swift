import OpenPGPAppleSecureEnclave
import SwiftUI

struct KeyDetailsView: View {
    let summary: CertificateSummary
    @ObservedObject var model: OpenPgpApplicationModel
    @Environment(\.dismiss) private var dismiss
    @State private var exportedText: String?
    @State private var showDeleteConfirmation = false

    var body: some View {
        Form {
            Section("keys.details.identity") {
                Text(summary.displayName)
                LabeledContent("keys.fingerprint", value: summary.fingerprint)
                    .textSelection(.enabled)
                LabeledContent("keys.keyId", value: summary.keyId)
                LabeledContent("keys.version", value: String(describing: summary.keyVersion))
                LabeledContent("keys.storage") {
                    Text(model.protectionTitle(for: summary))
                }
            }

            Section("keys.details.primary") {
                keyView(summary.primary)
            }

            Section("keys.details.subkeys") {
                ForEach(summary.subkeys, id: \.fingerprint) { subkey in
                    keyView(subkey)
                }
            }

            if let accessControl = model.secureEnclaveAccessControls[summary.fingerprint] {
                Section("keys.details.secureEnclave") {
                    Text(accessControlNote(accessControl))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    if summary.primary.storage == .softwareSecret {
                        Text("keys.details.secureEnclave.softwarePrimary")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("keys.details.secureEnclave.hardwarePrimary")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if let registration = model.cardRegistrations.first(where: {
                $0.certificateFingerprint == summary.fingerprint
            }) {
                Section("keys.hardware") {
                    LabeledContent("card.identity", value: registration.identity.displayIdentifier)
                    ForEach(registration.components, id: \.componentFingerprint) { component in
                        LabeledContent(component.slot.title) {
                            Text(component.componentFingerprint)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    NavigationLink("keys.hardware.manage") {
                        CardDeviceManagementView(model: model, registration: registration)
                    }
                    .accessibilityIdentifier("navigation.keys.hardware.manage")
                    Button("keys.hardware.unlink") {
                        Task { await unlinkCard() }
                    }
                    .disabled(model.isBusy)
                    .accessibilityIdentifier("action.keys.hardware.unlink")
                    Text("keys.hardware.noCardModification")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } else if summary.storage == .publicOnly,
                      !model.hasSecureEnclaveBinding(fingerprint: summary.fingerprint) {
                Section("keys.hardware") {
                    NavigationLink("keys.hardware.link") {
                        CardAssociationView(summary: summary, model: model)
                    }
                    .accessibilityIdentifier("navigation.keys.hardware.link")
                    Text("keys.hardware.associationNote")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            Section("keys.export.title") {
                Button("keys.export.public") {
                    Task { await export(private: false) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isBusy)
                .accessibilityIdentifier("action.keys.export.public")
                if summary.privateExportPolicy == .allowed {
                    Button("keys.export.private") {
                        Task { await export(private: true) }
                    }
                    .buttonStyle(.bordered)
                    .disabled(model.isBusy)
                    .accessibilityIdentifier("action.keys.export.private")
                } else {
                    Text("keys.export.disabled")
                        .foregroundStyle(.secondary)
                }
            }
            if model.isBusy {
                ProgressView("operation.inProgress")
            }
            if let errorMessage = model.errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
            }
            Section {
                Button("action.keys.delete", role: .destructive) {
                    showDeleteConfirmation = true
                }
                .disabled(model.isBusy)
                .accessibilityIdentifier("action.keys.delete")
            }
        }
        .navigationTitle("keys.details.title")
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityIdentifier("screen.keys.details")
        .confirmationDialog(
            "keys.delete.title",
            isPresented: $showDeleteConfirmation,
            titleVisibility: .visible
        ) {
            Button("action.keys.delete.confirm", role: .destructive) {
                Task { await delete() }
            }
            .accessibilityIdentifier("action.keys.delete.confirm")
            Button("action.cancel", role: .cancel) {}
        } message: {
            Text(model.hasSecureEnclaveBinding(fingerprint: summary.fingerprint)
                ? "keys.delete.secureEnclaveMessage"
                : "keys.delete.message")
        }
        .sheet(isPresented: Binding(
            get: { exportedText != nil },
            set: { if !$0 { exportedText = nil } }
        )) {
            if let exportedText {
                ShareSheet(items: [exportedText])
            }
        }
    }

    @ViewBuilder
    private func keyView(_ key: KeyMetadataSummary) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(key.algorithm.name)
            if key.algorithm.policyAlgorithm?.hasPrefix("rsa-") == true,
               let bits = key.algorithm.bitSize {
                Text("RSA-\(bits)")
                    .foregroundStyle(.secondary)
            } else if let curve = key.algorithm.curve {
                Text(curve.name)
                    .foregroundStyle(.secondary)
            }
            Text(usageText(key.keyFlags))
                .font(.footnote)
                .foregroundStyle(.secondary)
            LabeledContent("keys.storage") {
                Text(model.protectionTitle(for: summary, component: key))
            }
            Text(Date(timeIntervalSince1970: TimeInterval(key.createdAt)), format: .dateTime)
                .font(.footnote)
                .foregroundStyle(.secondary)
            if let expiresAt = key.expiresAt {
                Text(Date(timeIntervalSince1970: TimeInterval(expiresAt)), format: .dateTime)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if !key.revocations.isEmpty {
                Text("keys.revoked")
                    .foregroundStyle(.red)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func accessControlNote(
        _ accessControl: SecureEnclaveAccessControl
    ) -> LocalizedStringKey {
        switch accessControl {
        case .deviceUnlocked: "keys.details.secureEnclave.deviceUnlocked"
        case .userPresence: "keys.details.secureEnclave.userPresence"
        case .biometryAny: "keys.details.secureEnclave.biometryAny"
        case .biometryCurrentSet: "keys.details.secureEnclave.biometryCurrentSet"
        }
    }

    private func usageText(_ flags: KeyUsageSummary) -> LocalizedStringKey {
        if flags.sign { return "usage.sign" }
        if flags.encryptCommunications || flags.encryptStorage { return "usage.encrypt" }
        if flags.authentication { return "usage.authenticate" }
        if flags.certify { return "usage.certify" }
        return "usage.other"
    }

    private func export(private isPrivate: Bool) async {
        do {
            let data = if isPrivate {
                try await model.exportPrivate(fingerprint: summary.fingerprint, format: .armored)
            } else {
                try await model.exportPublic(fingerprint: summary.fingerprint, format: .armored)
            }
            exportedText = String(data: data, encoding: .utf8)
        } catch {}
    }

    private func unlinkCard() async {
        do {
            try await model.disconnectCard(fingerprint: summary.fingerprint)
        } catch {}
    }

    private func delete() async {
        do {
            try await model.removeKey(fingerprint: summary.fingerprint)
            dismiss()
        } catch {}
    }
}
