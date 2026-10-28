import SwiftUI

struct HardwareKeyManagementView: View {
    @ObservedObject var model: OpenPgpApplicationModel

    var body: some View {
        Form {
            if model.cardRegistrations.isEmpty {
                Section {
                    Label("hardware.noLinkedDevices", systemImage: "creditcard")
                    Text("hardware.linkFromKeys")
                        .accessibilityIdentifier("hardware.linkFromKeys")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } else {
                Section("hardware.devices") {
                    ForEach(model.cardRegistrations, id: \.certificateFingerprint) { registration in
                        NavigationLink {
                            CardDeviceManagementView(model: model, registration: registration)
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(registration.identity.displayIdentifier)
                                Text(certificateName(registration.certificateFingerprint))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .accessibilityIdentifier("navigation.hardware.device.\(registration.certificateFingerprint)")
                    }
                }

                Section("hardware.linkedCertificates") {
                    ForEach(model.cardRegistrations, id: \.certificateFingerprint) { registration in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(certificateName(registration.certificateFingerprint))
                            Label("hardware.linkedReady", systemImage: "checkmark.circle")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                            ForEach(registration.components, id: \.componentFingerprint) { component in
                                LabeledContent {
                                    Text(component.componentFingerprint)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                } label: {
                                    Text(component.slot.title)
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
            }

            Section("hardware.currentLimitations") {
                Text("hardware.managementPending")
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
    }

    private func certificateName(_ fingerprint: String) -> String {
        model.keys.first { $0.fingerprint == fingerprint }?.displayName ?? fingerprint
    }
}
