import SwiftUI
import UniformTypeIdentifiers

struct EncryptionView: View {
    @ObservedObject var model: OpenPgpApplicationModel
    @State private var mode = EncryptionMode.encrypt

    @State private var encryptSource = MessageInputSource.text
    @State private var encryptText = ""
    @State private var encryptFile: URL?
    @State private var selectedRecipients: Set<String> = []
    @State private var encryptionSigningKey = ""
    @State private var encryptionSigningPassword = ""
    @State private var encryptionSigningConnection = CardConnectionSelection()
    @State private var encryptionProfile = EncryptionProfile.modern
    @State private var encryptArmored = true
    @State private var encryptionOutput: MessageOutput?

    @State private var decryptSource = MessageInputSource.text
    @State private var decryptText = ""
    @State private var decryptFile: URL?
    @State private var decryptionKey = ""
    @State private var decryptionPassword = ""
    @State private var decryptionConnection = CardConnectionSelection()
    @State private var decryptionReport: DecryptionReportFfi?
    @State private var decryptionPlaintext: String?
    @State private var decryptionOutput: MessageOutput?

    @State private var fileRole: EncryptionFileRole?
    @State private var shareURL: URL?

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                Picker("encryption.mode.picker", selection: $mode) {
                    ForEach(EncryptionMode.allCases) { mode in
                        Text(mode.title)
                            .tag(mode)
                            .accessibilityIdentifier(mode.accessibilityIdentifier)
                    }
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("mode.encryption.picker")

                if mode == .encrypt {
                    encryptPanel
                } else {
                    decryptPanel
                }

                if model.isBusy {
                    ProgressView("operation.inProgress")
                }
                if let errorMessage = model.errorMessage {
                    Text(errorMessage)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                }
            }
            .padding()
            .navigationTitle("encryption.title")
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("screen.encryption")
        }
        .onAppear {
            if decryptionKey.isEmpty {
                decryptionKey = model.decryptionKeys.first?.fingerprint ?? ""
            }
            decryptionConnection = model.preferredCardConnection(for: decryptionKey)
            encryptionSigningConnection = model.preferredCardConnection(for: encryptionSigningKey)
        }
        .onChange(of: decryptionKey) { fingerprint in
            decryptionConnection = model.preferredCardConnection(for: fingerprint)
            clearDecryption()
        }
        .onChange(of: encryptionSigningKey) { fingerprint in
            encryptionSigningConnection = model.preferredCardConnection(for: fingerprint)
            encryptionOutput = nil
        }
        .onChange(of: mode) { _ in
            model.errorMessage = nil
        }
        .onChange(of: encryptSource) { _ in
            encryptionOutput = nil
        }
        .fileImporter(
            isPresented: Binding(
                get: { fileRole != nil },
                set: { if !$0 { fileRole = nil } }
            ),
            allowedContentTypes: [.data, .text],
            allowsMultipleSelection: false
        ) { result in
            handleFileSelection(result)
        }
        .sheet(isPresented: Binding(
            get: { shareURL != nil },
            set: { if !$0 { shareURL = nil } }
        )) {
            if let shareURL {
                ShareSheet(items: [shareURL])
            }
        }
    }

    private var encryptPanel: some View {
        Form {
            Section("encryption.encrypt.input") {
                MessageInputPicker(
                    title: "message.input.source",
                    identifier: "field.encryption.encryptSource",
                    selection: $encryptSource
                )
                if encryptSource == .text {
                    LongTextEditor(
                        text: $encryptText,
                        identifier: "field.encryption.encryptText"
                    )
                } else {
                    filePicker(url: encryptFile, role: .encryptInput)
                }
            }

            Section("encryption.encrypt.recipients") {
                if model.encryptionRecipientKeys.isEmpty {
                    Text("encryption.encrypt.noRecipients")
                        .foregroundStyle(.secondary)
                }
                ForEach(model.encryptionRecipientKeys, id: \.fingerprint) { key in
                    Button {
                        toggleRecipient(key.fingerprint)
                    } label: {
                        HStack {
                            VStack(alignment: .leading) {
                                Text(key.displayName)
                                Text(key.fingerprint)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            Spacer()
                            if selectedRecipients.contains(key.fingerprint) {
                                Image(systemName: "checkmark")
                                    .foregroundStyle(.tint)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("field.encryption.recipient.\(key.fingerprint)")
                }
            }

            Section("encryption.encrypt.signing") {
                CertificatePicker(
                    title: "encryption.encrypt.signingKey",
                    identifier: "field.encryption.signingKey",
                    keys: model.signingKeys,
                    selection: $encryptionSigningKey,
                    allowsNone: true
                )
                PrivateKeySecretField(
                    model: model,
                    fingerprint: encryptionSigningKey,
                    operation: .signing,
                    password: $encryptionSigningPassword,
                    identifier: "field.encryption.signingPassword"
                )
                Text("encryption.encrypt.signingNote")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            if model.privateKeyAccess(
                fingerprint: encryptionSigningKey,
                operation: .signing
            ) == .smartCard {
                CardConnectionPicker(
                    model: model,
                    selection: $encryptionSigningConnection,
                    identifier: "encryption.sign"
                )
            }

            Section("encryption.encrypt.format") {
                Picker("encryption.config", selection: $encryptionProfile) {
                    ForEach(EncryptionProfile.allCases) { profile in
                        Text(profile.title).tag(profile)
                    }
                }
                .accessibilityIdentifier("field.encryption.config")
                Toggle("message.asciiArmor", isOn: $encryptArmored)
                    .accessibilityIdentifier("field.encryption.armor")
            }

            Section {
                Button(mode.actionTitle) {
                    Task { await performEncrypt() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canEncrypt || model.isBusy)
                .accessibilityIdentifier("action.encryption.encrypt")
            }

            if let encryptionOutput {
                MessageOutputView(
                    output: encryptionOutput,
                    copyText: encryptSource == .text ? encryptionOutput.preview : nil
                ) {
                    shareURL = encryptionOutput.url
                }
            }
        }
        .accessibilityIdentifier("panel.encryption.encrypt")
        .dismissKeyboard()
        .disabled(model.isBusy)
    }

    private var decryptPanel: some View {
        Form {
            Section("encryption.decrypt.input") {
                MessageInputPicker(
                    title: "message.input.source",
                    identifier: "field.encryption.decryptSource",
                    selection: $decryptSource
                )
                if decryptSource == .text {
                    LongTextEditor(
                        text: $decryptText,
                        identifier: "field.encryption.decryptText",
                        minHeight: 140
                    )
                } else {
                    filePicker(url: decryptFile, role: .decryptInput)
                }
            }

            Section("encryption.decrypt.key") {
                if model.decryptionKeys.isEmpty {
                    Text("encryption.decrypt.noKeys")
                        .foregroundStyle(.secondary)
                }
                CertificatePicker(
                    title: "encryption.decrypt.decryptionKey",
                    identifier: "field.encryption.decryptionKey",
                    keys: model.decryptionKeys,
                    selection: $decryptionKey
                )
                PrivateKeySecretField(
                    model: model,
                    fingerprint: decryptionKey,
                    operation: .decryption,
                    password: $decryptionPassword,
                    identifier: "field.encryption.decryptionPassword"
                )
            }

            if model.privateKeyAccess(
                fingerprint: decryptionKey,
                operation: .decryption
            ) == .smartCard {
                CardConnectionPicker(
                    model: model,
                    selection: $decryptionConnection,
                    identifier: "encryption.decrypt"
                )
            }

            Section {
                Button(mode.actionTitle) {
                    Task { await performDecrypt() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canDecrypt || model.isBusy)
                .accessibilityIdentifier("action.encryption.decrypt")
            }

            if let decryptionReport {
                DecryptionReportView(report: decryptionReport)
            }
            if let decryptionPlaintext {
                MessagePlaintextView(text: decryptionPlaintext)
            }
            if let decryptionOutput {
                MessageOutputView(output: decryptionOutput) {
                    shareURL = decryptionOutput.url
                }
            }
            if decryptionReport != nil && decryptionPlaintext == nil && decryptionOutput == nil {
                Text("encryption.decrypt.noPlaintext")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityIdentifier("panel.encryption.decrypt")
        .dismissKeyboard()
        .disabled(model.isBusy)
    }

    private var canEncrypt: Bool {
        let signingIsUsable = encryptionSigningKey.isEmpty
            || (model.signingKeys.contains { $0.fingerprint == encryptionSigningKey }
                && model.canSubmitPrivateKeyOperation(
                    fingerprint: encryptionSigningKey,
                    password: encryptionSigningPassword,
                    connection: encryptionSigningConnection
                ))
        return hasInput(source: encryptSource, text: encryptText, file: encryptFile)
            && !selectedRecipients.isEmpty
            && signingIsUsable
    }

    private var canDecrypt: Bool {
        hasInput(source: decryptSource, text: decryptText, file: decryptFile)
            && model.decryptionKeys.contains { $0.fingerprint == decryptionKey }
            && model.canSubmitPrivateKeyOperation(
                fingerprint: decryptionKey,
                password: decryptionPassword,
                operation: .decryption,
                connection: decryptionConnection
            )
    }

    private func hasInput(source: MessageInputSource, text: String, file: URL?) -> Bool {
        source == .text ? !text.isEmpty : file != nil
    }

    private func toggleRecipient(_ fingerprint: String) {
        if selectedRecipients.contains(fingerprint) {
            selectedRecipients.remove(fingerprint)
        } else {
            selectedRecipients.insert(fingerprint)
        }
        encryptionOutput = nil
    }

    @ViewBuilder
    private func filePicker(url: URL?, role: EncryptionFileRole) -> some View {
        Button("message.input.chooseFile") {
            fileRole = role
        }
        .accessibilityIdentifier("action.encryption.file.\(role.rawValue)")
        if let url {
            Text(url.lastPathComponent)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private func handleFileSelection(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard let url = urls.first, let role = fileRole else { return }
            switch role {
            case .encryptInput:
                encryptFile = url
                encryptionOutput = nil
            case .decryptInput:
                decryptFile = url
                clearDecryption()
            }
        case .failure(let error):
            model.errorMessage = ErrorPresenter.message(for: error)
        }
    }

    private func performEncrypt() async {
        model.errorMessage = nil
        encryptionOutput = nil
        defer { encryptionSigningPassword = "" }
        do {
            let at = UInt64(Date().timeIntervalSince1970)
            let recipients = selectedRecipients.sorted()
            let config = encryptionProfile.config
            let messageFormat: MessageFormatFfi = encryptArmored ? .armored : .binary
            let sourceName = encryptSource == .file
                ? encryptFile?.lastPathComponent ?? "message.bin"
                : "message.txt"
            let outputName = MessageFiles.encryptedFileName(
                source: sourceName,
                armored: encryptArmored
            )

            if encryptSource == .file {
                guard let input = encryptFile else { return }
                let output = try MessageFiles.makeOutputURL(named: outputName)
                var metadata: SignatureMetadataFfi?
                if encryptionSigningKey.isEmpty {
                    try await withSecurityScopedResources([input]) {
                        try await model.encryptFile(
                            recipients: recipients,
                            atUnixSeconds: at,
                            config: config,
                            inputPath: input.path,
                            outputPath: output.path,
                            format: messageFormat
                        )
                    }
                } else {
                    metadata = try await withSecurityScopedResources([input]) {
                        try await model.signAndEncryptFile(
                            request: SignEncryptFileRequestFfi(
                                signingKey: encryptionSigningKey,
                                password: encryptionSigningPassword,
                                recipients: recipients,
                                atUnixSeconds: at,
                                config: config,
                                inputPath: input.path,
                                outputPath: output.path,
                                format: messageFormat
                            ),
                            connection: encryptionSigningConnection
                        )
                    }
                }
                encryptionOutput = MessageOutput(url: output, metadata: metadata)
            } else {
                let text = encryptText.openPgpCanonicalLineEndings
                let encryptedData: Data
                var metadata: SignatureMetadataFfi?
                if encryptionSigningKey.isEmpty {
                    encryptedData = try await model.encryptText(
                        recipients: recipients,
                        atUnixSeconds: at,
                        config: config,
                        text: text,
                        format: messageFormat
                    )
                } else {
                    let artifact = try await model.signAndEncryptText(
                        request: SignEncryptTextRequestFfi(
                            signingKey: encryptionSigningKey,
                            password: encryptionSigningPassword,
                            recipients: recipients,
                            atUnixSeconds: at,
                            config: config,
                            text: text,
                            format: messageFormat
                        ),
                        connection: encryptionSigningConnection
                    )
                    encryptedData = artifact.artifact
                    metadata = artifact.metadata
                }
                let output = try MessageFiles.write(encryptedData, named: outputName)
                encryptionOutput = MessageOutput(
                    url: output,
                    preview: encryptArmored ? String(data: encryptedData, encoding: .utf8) : nil,
                    metadata: metadata,
                    byteCount: encryptedData.count
                )
            }
        } catch {
            present(error)
        }
    }

    private func performDecrypt() async {
        model.errorMessage = nil
        clearDecryption()
        defer { decryptionPassword = "" }
        do {
            let at = UInt64(Date().timeIntervalSince1970)
            if decryptSource == .text {
                let result = try await model.decryptText(
                    decryptionKey: decryptionKey,
                    password: decryptionPassword,
                    atUnixSeconds: at,
                    input: Data(decryptText.utf8),
                    connection: decryptionConnection
                )
                decryptionReport = result.report
                if allowsPlaintext(result.report) {
                    decryptionPlaintext = result.text
                }
            } else {
                guard let input = decryptFile else { return }
                let output = try MessageFiles.makeOutputURL(
                    named: MessageFiles.decryptedFileName(source: input.lastPathComponent)
                )
                let report = try await withSecurityScopedResources([input]) {
                    try await model.decryptFile(
                        decryptionKey: decryptionKey,
                        password: decryptionPassword,
                        atUnixSeconds: at,
                        inputPath: input.path,
                        outputPath: output.path,
                        connection: decryptionConnection
                    )
                }
                decryptionReport = report
                if allowsPlaintext(report), FileManager.default.fileExists(atPath: output.path) {
                    decryptionOutput = MessageOutput(url: output)
                }
            }
        } catch {
            present(error)
        }
    }

    private func allowsPlaintext(_ report: DecryptionReportFfi) -> Bool {
        report.mayCommitStaging
            && report.status != .decryptionFailed
            && report.status != .integrityFailed
    }

    private func clearDecryption() {
        decryptionReport = nil
        decryptionPlaintext = nil
        decryptionOutput = nil
    }

    private func present(_ error: Error) {
        if model.errorMessage == nil {
            model.errorMessage = ErrorPresenter.message(for: error)
        }
    }
}

private enum EncryptionFileRole: String, Identifiable {
    case encryptInput
    case decryptInput

    var id: String { rawValue }
}
