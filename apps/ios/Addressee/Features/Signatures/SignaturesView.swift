import SwiftUI
import UniformTypeIdentifiers

struct SignaturesView: View {
    @ObservedObject var model: OpenPgpApplicationModel
    @State private var mode = SignatureMode.sign

    @State private var signSource = MessageInputSource.text
    @State private var signText = ""
    @State private var signFile: URL?
    @State private var signingKey = ""
    @State private var signingPassword = ""
    @State private var signingConnection = CardConnectionSelection()
    @State private var signFormat = SignatureFormat.detached
    @State private var signArmored = true
    @State private var signOutput: MessageOutput?

    @State private var verifyFormat = SignatureFormat.detached
    @State private var verifyDataSource = MessageInputSource.text
    @State private var verifyDataText = ""
    @State private var verifyDataFile: URL?
    @State private var signatureSource = MessageInputSource.text
    @State private var signatureText = ""
    @State private var signatureFile: URL?
    @State private var verifyMessageSource = MessageInputSource.text
    @State private var verifyMessageText = ""
    @State private var verifyMessageFile: URL?
    @State private var verificationOutcome: VerificationOutcomeFfi?
    @State private var verificationPlaintext: String?
    @State private var verificationOutput: MessageOutput?

    @State private var fileRole: SignatureFileRole?
    @State private var shareURL: URL?

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                Picker("signatures.mode.picker", selection: $mode) {
                    ForEach(SignatureMode.allCases) { mode in
                        Text(mode.title)
                            .tag(mode)
                            .accessibilityIdentifier(mode.accessibilityIdentifier)
                    }
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("mode.signature.picker")

                if mode == .sign {
                    signPanel
                } else {
                    verifyPanel
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
            .navigationTitle("signatures.title")
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("screen.signatures")
        }
        .onAppear {
            if signingKey.isEmpty {
                signingKey = model.signingKeys.first?.fingerprint ?? ""
            }
            signingConnection = model.preferredCardConnection(for: signingKey)
        }
        .onChange(of: signingKey) { fingerprint in
            signingConnection = model.preferredCardConnection(for: fingerprint)
            signOutput = nil
        }
        .onChange(of: mode) { _ in
            model.errorMessage = nil
        }
        .onChange(of: signSource) { _ in
            if signSource == .file && signFormat == .cleartext {
                signFormat = .attached
            }
            signOutput = nil
        }
        .onChange(of: signFormat) { _ in
            signOutput = nil
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

    private var signPanel: some View {
        Form {
            Section("signature.sign.input") {
                MessageInputPicker(
                    title: "message.input.source",
                    identifier: "field.signature.signSource",
                    selection: $signSource
                )
                if signSource == .text {
                    LongTextEditor(
                        text: $signText,
                        identifier: "field.signature.signText"
                    )
                } else {
                    filePicker(url: signFile, role: .signInput)
                }
            }

            Section("signature.sign.key") {
                if model.signingKeys.isEmpty {
                    Text("signature.sign.noKeys")
                        .foregroundStyle(.secondary)
                }
                CertificatePicker(
                    title: "signature.sign.signingKey",
                    identifier: "field.signature.signingKey",
                    keys: model.signingKeys,
                    selection: $signingKey
                )
                PrivateKeySecretField(
                    model: model,
                    fingerprint: signingKey,
                    operation: .signing,
                    password: $signingPassword,
                    identifier: "field.signature.signPassword"
                )
            }

            if model.privateKeyAccess(fingerprint: signingKey, operation: .signing) == .smartCard {
                CardConnectionPicker(
                    model: model,
                    selection: $signingConnection,
                    identifier: "signature.sign"
                )
            }

            Section("signature.sign.format") {
                Picker("signature.format", selection: $signFormat) {
                    ForEach(availableSignFormats) { format in
                        Text(format.title).tag(format)
                    }
                }
                .accessibilityIdentifier("field.signature.signFormat")
                if signFormat != .cleartext {
                    Toggle("message.asciiArmor", isOn: $signArmored)
                        .accessibilityIdentifier("field.signature.signArmor")
                }
            }

            Section {
                Button(mode.actionTitle) {
                    Task { await performSign() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canSign || model.isBusy)
                .accessibilityIdentifier("action.signature.sign")
            }

            if let signOutput {
                MessageOutputView(
                    output: signOutput,
                    copyText: signSource == .text ? signOutput.preview : nil
                ) {
                    shareURL = signOutput.url
                }
            }
        }
        .accessibilityIdentifier("panel.signature.sign")
        .dismissKeyboard()
        .disabled(model.isBusy)
    }

    private var verifyPanel: some View {
        Form {
            Section("signature.verify.format") {
                Picker("signature.format", selection: $verifyFormat) {
                    ForEach(SignatureFormat.allCases) { format in
                        Text(format.title).tag(format)
                    }
                }
                .accessibilityIdentifier("field.signature.verifyFormat")
            }

            if verifyFormat == .detached {
                Section("signature.verify.originalData") {
                    MessageInputPicker(
                        title: "message.input.source",
                        identifier: "field.signature.verifyDataSource",
                        selection: $verifyDataSource
                    )
                    if verifyDataSource == .text {
                        LongTextEditor(
                            text: $verifyDataText,
                            identifier: "field.signature.verifyDataText",
                            minHeight: 100
                        )
                    } else {
                        filePicker(url: verifyDataFile, role: .verifyData)
                    }
                }

                Section("signature.verify.detachedSignature") {
                    MessageInputPicker(
                        title: "message.input.source",
                        identifier: "field.signature.signatureSource",
                        selection: $signatureSource
                    )
                    if signatureSource == .text {
                        LongTextEditor(
                            text: $signatureText,
                            identifier: "field.signature.signatureText"
                        )
                    } else {
                        filePicker(url: signatureFile, role: .verifySignature)
                    }
                }
            } else {
                Section(verifyFormat == .attached ? "signature.verify.attachedMessage" : "signature.verify.cleartextMessage") {
                    MessageInputPicker(
                        title: "message.input.source",
                        identifier: "field.signature.verifyMessageSource",
                        selection: $verifyMessageSource
                    )
                    if verifyMessageSource == .text {
                        LongTextEditor(
                            text: $verifyMessageText,
                            identifier: "field.signature.verifyMessageText",
                            minHeight: 140
                        )
                    } else {
                        filePicker(url: verifyMessageFile, role: .verifyMessage)
                    }
                }
            }

            Section {
                Button(mode.actionTitle) {
                    Task { await performVerify() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canVerify || model.isBusy)
                .accessibilityIdentifier("action.signature.verify")
            }

            if let verificationOutcome {
                VerificationOutcomeView(outcome: verificationOutcome)
            }
            if let verificationPlaintext {
                MessagePlaintextView(text: verificationPlaintext)
            }
            if let verificationOutput {
                MessageOutputView(output: verificationOutput) {
                    shareURL = verificationOutput.url
                }
            }
        }
        .accessibilityIdentifier("panel.signature.verify")
        .dismissKeyboard()
        .disabled(model.isBusy)
    }

    private var availableSignFormats: [SignatureFormat] {
        signSource == .file ? [.detached, .attached] : SignatureFormat.allCases
    }

    private var canSign: Bool {
        hasInput(source: signSource, text: signText, file: signFile)
            && model.signingKeys.contains { $0.fingerprint == signingKey }
            && model.canSubmitPrivateKeyOperation(
                fingerprint: signingKey,
                password: signingPassword,
                connection: signingConnection
            )
            && (signSource == .text || signFormat != .cleartext)
    }

    private var canVerify: Bool {
        if verifyFormat == .detached {
            return hasInput(source: verifyDataSource, text: verifyDataText, file: verifyDataFile)
                && hasInput(source: signatureSource, text: signatureText, file: signatureFile)
        }
        return hasInput(source: verifyMessageSource, text: verifyMessageText, file: verifyMessageFile)
    }

    private func hasInput(source: MessageInputSource, text: String, file: URL?) -> Bool {
        source == .text ? !text.isEmpty : file != nil
    }

    @ViewBuilder
    private func filePicker(url: URL?, role: SignatureFileRole) -> some View {
        Button("message.input.chooseFile") {
            fileRole = role
        }
        .accessibilityIdentifier("action.signature.file.\(role.rawValue)")
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
            case .signInput:
                signFile = url
                signOutput = nil
            case .verifyData:
                verifyDataFile = url
                clearVerification()
            case .verifySignature:
                signatureFile = url
                clearVerification()
            case .verifyMessage:
                verifyMessageFile = url
                clearVerification()
            }
        case .failure(let error):
            model.errorMessage = ErrorPresenter.message(for: error)
        }
    }

    private func performSign() async {
        model.errorMessage = nil
        signOutput = nil
        defer { signingPassword = "" }
        do {
            let at = UInt64(Date().timeIntervalSince1970)
            let sourceName = signSource == .file
                ? signFile?.lastPathComponent ?? "message.bin"
                : "message.txt"
            let outputName = MessageFiles.signatureFileName(
                source: sourceName,
                format: signFormat,
                armored: signArmored
            )
            let messageFormat: MessageFormatFfi = signArmored ? .armored : .binary

            if signSource == .file {
                guard let input = signFile, signFormat != .cleartext else { return }
                let output = try MessageFiles.makeOutputURL(named: outputName)
                let metadata = try await withSecurityScopedResources([input]) {
                    switch signFormat {
                    case .detached:
                        return try await model.signDetachedFile(
                            signingKey: signingKey,
                            password: signingPassword,
                            atUnixSeconds: at,
                            inputPath: input.path,
                            outputPath: output.path,
                            format: messageFormat,
                            connection: signingConnection
                        )
                    case .attached:
                        return try await model.signAttachedFile(
                            signingKey: signingKey,
                            password: signingPassword,
                            atUnixSeconds: at,
                            inputPath: input.path,
                            outputPath: output.path,
                            format: messageFormat,
                            connection: signingConnection
                        )
                    case .cleartext:
                        throw AddresseeError.InvalidInput
                    }
                }
                signOutput = MessageOutput(url: output, metadata: metadata)
            } else {
                let artifact: SignatureArtifactFfi
                switch signFormat {
                case .detached:
                    artifact = try await model.signDetached(
                        signingKey: signingKey,
                        password: signingPassword,
                        atUnixSeconds: at,
                        data: Data(signText.utf8),
                        format: messageFormat,
                        connection: signingConnection
                    )
                case .attached:
                    artifact = try await model.signAttached(
                        signingKey: signingKey,
                        password: signingPassword,
                        atUnixSeconds: at,
                        data: Data(signText.utf8),
                        format: messageFormat,
                        connection: signingConnection
                    )
                case .cleartext:
                    artifact = try await model.signCleartext(
                        signingKey: signingKey,
                        password: signingPassword,
                        atUnixSeconds: at,
                        text: signText,
                        connection: signingConnection
                    )
                }
                let output = try MessageFiles.write(artifact.artifact, named: outputName)
                let preview = signArmored || signFormat == .cleartext
                    ? String(data: artifact.artifact, encoding: .utf8)
                    : nil
                signOutput = MessageOutput(
                    url: output,
                    preview: preview,
                    metadata: artifact.metadata,
                    byteCount: artifact.artifact.count
                )
            }
        } catch {
            present(error)
        }
    }

    private func performVerify() async {
        model.errorMessage = nil
        clearVerification()
        do {
            let at = UInt64(Date().timeIntervalSince1970)
            switch verifyFormat {
            case .detached:
                try await verifyDetached(at: at)
            case .attached:
                try await verifyAttached(at: at)
            case .cleartext:
                try await verifyCleartext(at: at)
            }
        } catch {
            present(error)
        }
    }

    private func verifyDetached(at: UInt64) async throws {
        if verifyDataSource == .text {
            let signature: Data
            if signatureSource == .text {
                signature = Data(signatureText.utf8)
            } else {
                guard let signatureFile else { return }
                signature = try await FileInput.readData(from: signatureFile)
            }
            verificationOutcome = try await model.verifyDetached(
                data: Data(verifyDataText.utf8),
                signature: signature,
                atUnixSeconds: at
            )
        } else {
            guard let dataFile = verifyDataFile else { return }
            let signatureURL: URL
            if signatureSource == .text {
                signatureURL = try MessageFiles.write(
                    Data(signatureText.utf8),
                    named: "detached-signature.asc"
                )
            } else {
                guard let signatureFile else { return }
                signatureURL = signatureFile
            }
            verificationOutcome = try await withSecurityScopedResources([dataFile, signatureURL]) {
                try await model.verifyDetachedFile(
                    dataPath: dataFile.path,
                    signaturePath: signatureURL.path,
                    atUnixSeconds: at
                )
            }
        }
    }

    private func verifyAttached(at: UInt64) async throws {
        if verifyMessageSource == .text {
            let result = try await model.verifyAttached(
                input: Data(verifyMessageText.utf8),
                atUnixSeconds: at
            )
            verificationOutcome = result.outcome
            guard allowsPlaintext(result.outcome.status), let plaintext = result.plaintext else {
                return
            }
            if let text = String(data: plaintext, encoding: .utf8) {
                verificationPlaintext = text
            } else {
                let output = try MessageFiles.write(plaintext, named: "verified-message.bin")
                verificationOutput = MessageOutput(url: output, byteCount: plaintext.count)
            }
        } else {
            guard let input = verifyMessageFile else { return }
            let output = try MessageFiles.makeOutputURL(
                named: MessageFiles.verifiedFileName(source: input.lastPathComponent)
            )
            let outcome = try await withSecurityScopedResources([input]) {
                try await model.verifyAttachedFile(
                    inputPath: input.path,
                    outputPath: output.path,
                    atUnixSeconds: at
                )
            }
            verificationOutcome = outcome
            if allowsPlaintext(outcome.status), FileManager.default.fileExists(atPath: output.path) {
                verificationOutput = MessageOutput(url: output)
            }
        }
    }

    private func verifyCleartext(at: UInt64) async throws {
        let input: Data
        if verifyMessageSource == .text {
            input = Data(verifyMessageText.utf8)
        } else {
            guard let verifyMessageFile else { return }
            input = try await FileInput.readData(from: verifyMessageFile)
        }
        let result = try await model.verifyCleartext(input: input, atUnixSeconds: at)
        verificationOutcome = result.outcome
        verificationPlaintext = result.text
    }

    private func allowsPlaintext(_ status: VerificationStatusFfi) -> Bool {
        status == .unsigned || status == .valid
    }

    private func clearVerification() {
        verificationOutcome = nil
        verificationPlaintext = nil
        verificationOutput = nil
    }

    private func present(_ error: Error) {
        if model.errorMessage == nil {
            model.errorMessage = ErrorPresenter.message(for: error)
        }
    }
}

private enum SignatureFileRole: String, Identifiable {
    case signInput
    case verifyData
    case verifySignature
    case verifyMessage

    var id: String { rawValue }
}
