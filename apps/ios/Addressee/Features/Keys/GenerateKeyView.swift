import SwiftUI

private enum KeyGenerationBackend: String, CaseIterable, Identifiable {
    case software
    case secureEnclave

    var id: String { rawValue }
    var title: LocalizedStringKey {
        switch self {
        case .software: "generation.storage.software"
        case .secureEnclave: "generation.storage.secureEnclave"
        }
    }
}

struct GenerateKeyView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: OpenPgpApplicationModel

    @State private var userID = ""
    @State private var password = ""
    @State private var confirmation = ""
    @State private var profile: GenerationProfileFfi = .modernV6
    @State private var backend = KeyGenerationBackend.software
    @State private var allowExport = false
    @State private var legacyAcknowledged = false

    var body: some View {
        Form {
            Section("generation.identity") {
                TextField("generation.userId", text: $userID)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("field.generation.userId")
            }

            Section("generation.storage") {
                Picker("generation.backend", selection: $backend) {
                    ForEach(KeyGenerationBackend.allCases) { backend in
                        Text(backend.title).tag(backend)
                    }
                }
                .accessibilityIdentifier("field.generation.backend")
            }

            if backend == .software {
                Section("generation.algorithm") {
                    Picker("generation.profile", selection: $profile) {
                        ForEach(model.availableGenerationProfiles) { profile in
                            Text(profile.title).tag(profile)
                        }
                    }
                    .accessibilityIdentifier("field.generation.profile")
                    if profile.isLegacyCompatibilityProfile {
                        Text("generation.legacyWarning")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        Toggle("generation.legacyAcknowledge", isOn: $legacyAcknowledged)
                            .accessibilityIdentifier("field.generation.legacyAcknowledge")
                    }
                }
            } else {
                Section("generation.secureEnclave") {
                    Label("generation.secureEnclave.p256", systemImage: "lock.shield")
                    Text("generation.secureEnclave.hybrid")
                    Text("generation.secureEnclave.primaryLifecycle")
                    Text("generation.secureEnclave.recoveryWarning")
                    if !model.canGenerateSecureEnclave {
                        Text("security.enclave.validationPending")
                            .foregroundStyle(.orange)
                    }
                }
                .font(.footnote)
            }

            if backend == .software {
                Section("generation.protection") {
                    SecureField("generation.password", text: $password)
                        .textContentType(passwordContentType)
                        .accessibilityIdentifier("field.generation.password")
                    SecureField("generation.confirmPassword", text: $confirmation)
                        .textContentType(passwordContentType)
                        .accessibilityIdentifier("field.generation.confirmPassword")
                    Text("generation.protectionNote")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            if backend == .software {
                Section("generation.export") {
                    Toggle("generation.allowPrivateExport", isOn: $allowExport)
                        .accessibilityIdentifier("field.generation.allowExport")
                    Text("generation.exportNote")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } else {
                Section("generation.export") {
                    Text("generation.secureEnclave.nonExportable")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                Button("action.keys.generate") {
                    Task { await generate() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!isValid || model.isBusy)
                .accessibilityIdentifier("action.keys.generate.confirm")
            }
            if model.isBusy {
                ProgressView("operation.inProgress")
            }
            if let errorMessage = model.errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
            }
        }
        .navigationTitle("generation.title")
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityIdentifier("screen.keys.generate")
        .dismissKeyboard()
        .onAppear {
            allowExport = model.allowsSoftwareExportByDefault
        }
    }

    private var passwordContentType: UITextContentType {
        #if DEBUG
        // Password-manager pairing must not replace simulator UI test input.
        if ProcessInfo.processInfo.arguments.contains("-DisablePasswordAutofill") {
            return .oneTimeCode
        }
        #endif
        return .password
    }

    private var isValid: Bool {
        guard !userID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return false
        }
        switch backend {
        case .software:
            return !password.isEmpty
                && password == confirmation
                && model.availableGenerationProfiles.contains(profile)
                && (!profile.isLegacyCompatibilityProfile || legacyAcknowledged)
        case .secureEnclave:
            return model.canGenerateSecureEnclave
        }
    }

    private func generate() async {
        do {
            let identity = userID.trimmingCharacters(in: .whitespacesAndNewlines)
            switch backend {
            case .software:
                _ = try await model.generate(
                    profile: profile,
                    userID: identity,
                    password: password,
                    exportPolicy: allowExport ? .allowed : .disabled
                )
            case .secureEnclave:
                _ = try await model.generateSecureEnclave(userID: identity)
            }
            dismiss()
        } catch {}
    }
}
