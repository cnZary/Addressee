import SwiftUI
import UIKit
import UniformTypeIdentifiers

private struct LongTextPasteControl: UIViewRepresentable {
    @Binding var text: String

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    func makeUIView(context: Context) -> UIPasteControl {
        let configuration = UIPasteControl.Configuration()
        configuration.displayMode = .iconOnly
        configuration.baseForegroundColor = .tintColor
        configuration.baseBackgroundColor = .clear
        let control = UIPasteControl(configuration: configuration)
        control.target = context.coordinator
        control.setContentHuggingPriority(.required, for: .horizontal)
        control.setContentHuggingPriority(.required, for: .vertical)
        return control
    }

    func updateUIView(_ control: UIPasteControl, context: Context) {
        context.coordinator.text = $text
        control.target = context.coordinator
    }

    @MainActor
    final class Coordinator: NSObject, UIPasteConfigurationSupporting {
        var text: Binding<String>
        var pasteConfiguration: UIPasteConfiguration? = UIPasteConfiguration(
            acceptableTypeIdentifiers: [UTType.plainText.identifier]
        )

        init(text: Binding<String>) {
            self.text = text
        }

        func canPaste(_ itemProviders: [NSItemProvider]) -> Bool {
            itemProviders.contains {
                $0.hasItemConformingToTypeIdentifier(UTType.plainText.identifier)
            }
        }

        func paste(itemProviders: [NSItemProvider]) {
            guard let provider = itemProviders.first(where: {
                $0.hasItemConformingToTypeIdentifier(UTType.plainText.identifier)
            }) else { return }
            provider.loadObject(ofClass: NSString.self) { [weak self] value, _ in
                guard let pastedText = value as? NSString else { return }
                let immutableText = pastedText as String
                Task { @MainActor [weak self] in
                    self?.text.wrappedValue = immutableText
                }
            }
        }
    }
}

struct MessageInputPicker: View {
    let title: LocalizedStringKey
    let identifier: String
    @Binding var selection: MessageInputSource

    var body: some View {
        Picker(title, selection: $selection) {
            ForEach(MessageInputSource.allCases) { source in
                Text(source.title).tag(source)
            }
        }
        .pickerStyle(.segmented)
        .accessibilityIdentifier(identifier)
    }
}

struct LongTextEditor: View {
    @Binding var text: String
    let identifier: String
    let minHeight: CGFloat

    init(text: Binding<String>, identifier: String, minHeight: CGFloat = 120) {
        self._text = text
        self.identifier = identifier
        self.minHeight = minHeight
    }

    var body: some View {
        TextEditor(text: $text)
            .accessibilityIdentifier(identifier)
            .font(.system(.body, design: .monospaced))
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .frame(minHeight: minHeight)
            .safeAreaInset(edge: .bottom, alignment: .trailing) {
                HStack(spacing: 0) {
                    Button {
                        text = ""
                    } label: {
                        Image(systemName: "xmark.circle")
                            .frame(width: 44, height: 44)
                            .accessibilityHidden(true)
                    }
                    .buttonStyle(.borderless)
                    .disabled(text.isEmpty)
                    .accessibilityLabel("input.clear")
                    .accessibilityIdentifier("\(identifier).clear")
                    LongTextPasteControl(text: $text)
                        .frame(width: 44, height: 44)
                        .accessibilityLabel("input.paste")
                        .accessibilityHint("input.pasteHint")
                        .accessibilityIdentifier("\(identifier).paste")
                }
                .padding(.trailing, 4)
            }
    }
}

struct CertificatePicker: View {
    let title: LocalizedStringKey
    let identifier: String
    let keys: [CertificateSummary]
    let allowsNone: Bool
    @Binding var selection: String

    init(
        title: LocalizedStringKey,
        identifier: String,
        keys: [CertificateSummary],
        selection: Binding<String>,
        allowsNone: Bool = false
    ) {
        self.title = title
        self.identifier = identifier
        self.keys = keys
        self._selection = selection
        self.allowsNone = allowsNone
    }

    var body: some View {
        Picker(title, selection: $selection) {
            if allowsNone {
                Text("message.noSigningKey").tag("")
            }
            ForEach(keys, id: \.fingerprint) { key in
                Text(key.displayName).tag(key.fingerprint)
            }
        }
        .accessibilityIdentifier(identifier)
    }
}

struct PrivateKeySecretField: View {
    @ObservedObject var model: OpenPgpApplicationModel
    let fingerprint: String
    let operation: PrivateKeyOperation
    @Binding var password: String
    let identifier: String

    var body: some View {
        if fingerprint.isEmpty {
            EmptyView()
        } else {
            switch model.privateKeyAccess(fingerprint: fingerprint, operation: operation) {
            case .softwarePassword:
                SecureField("message.keyPassword", text: $password)
                    .textContentType(.password)
                    .accessibilityIdentifier(identifier)
            case .smartCard:
                Label("message.cardPinRequired", systemImage: "creditcard")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            case .secureEnclave:
                Label("message.secureEnclaveRequired", systemImage: "lock.shield")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            case .unavailable:
                Label(
                    model.hasSecureEnclaveBinding(fingerprint: fingerprint)
                        ? "message.secureEnclaveUnavailable"
                        : "message.cardDisconnected",
                    systemImage: "exclamationmark.triangle"
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
        }
    }
}

struct MessageOutputView: View {
    let output: MessageOutput
    let copyText: String?
    let share: () -> Void

    init(output: MessageOutput, copyText: String? = nil, share: @escaping () -> Void) {
        self.output = output
        self.copyText = copyText
        self.share = share
    }

    var body: some View {
        Section("message.output.title") {
            if let metadata = output.metadata {
                SignatureMetadataView(metadata: metadata)
            }
            if let preview = output.preview {
                ScrollView {
                    Text(preview)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("message.output.preview")
                }
                .frame(minHeight: 100, maxHeight: 260)
            }
            LabeledContent("message.output.file", value: output.url.lastPathComponent)
            if let byteCount = resolvedByteCount {
                LabeledContent(
                    "message.output.size",
                    value: ByteCountFormatter.string(fromByteCount: Int64(byteCount), countStyle: .file)
                )
            }
            HStack {
                if let copyText {
                    Button("message.output.copy") {
                        UIPasteboard.general.string = copyText
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("action.message.copy")
                }
                Button("message.output.share", action: share)
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("action.message.share")
            }
        }
    }

    private var resolvedByteCount: Int? {
        if let byteCount = output.byteCount {
            return byteCount
        }
        let attributes = try? FileManager.default.attributesOfItem(atPath: output.url.path)
        return (attributes?[.size] as? NSNumber)?.intValue
    }
}

struct MessagePlaintextView: View {
    let text: String

    var body: some View {
        Section("message.plaintext") {
            ScrollView {
                Text(text)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 80, maxHeight: 240)
            .accessibilityIdentifier("message.plaintext.preview")
        }
    }
}

struct VerificationOutcomeView: View {
    let outcome: VerificationOutcomeFfi

    var body: some View {
        Section("verification.result") {
            MessageStatusBanner(
                title: outcome.policyPresentation?.title ?? outcome.status.title,
                systemImage: outcome.policyPresentation?.systemImage ?? outcome.status.systemImage,
                color: outcome.policyPresentation?.color ?? outcome.status.color
            )
            if let presentation = outcome.policyPresentation {
                LegacyPolicyNotice(presentation: presentation)
            }
            if outcome.signatures.isEmpty {
                Text("verification.noSignatures")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(outcome.signatures.indices, id: \.self) { index in
                    SignatureVerificationView(signature: outcome.signatures[index])
                }
                IdentityTrustNote(trust: outcome.signatures[0].trust)
            }
        }
    }
}

struct DecryptionReportView: View {
    let report: DecryptionReportFfi

    var body: some View {
        Section("decryption.result") {
            MessageStatusBanner(
                title: report.policyPresentation?.title ?? report.status.title,
                systemImage: report.policyPresentation?.systemImage ?? report.status.systemImage,
                color: report.policyPresentation?.color ?? report.status.color
            )
            if let presentation = report.policyPresentation {
                LegacyPolicyNotice(presentation: presentation)
            }
            if let detail = report.detail, !detail.isEmpty {
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            ForEach(report.signatures.indices, id: \.self) { index in
                SignatureVerificationView(signature: report.signatures[index])
            }
            if !report.signatures.isEmpty {
                IdentityTrustNote(trust: report.trust)
            }
        }
    }
}

private struct MessageStatusBanner: View {
    let title: LocalizedStringKey
    let systemImage: String
    let color: Color

    var body: some View {
        Label(title, systemImage: systemImage)
            .font(.headline)
            .foregroundStyle(color)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(color.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("message.status.banner")
    }
}

private struct SignatureVerificationView: View {
    let signature: SignatureVerificationFfi

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("verification.signature")
                .font(.headline)
            LabeledContent("verification.status") {
                Text(signature.status.title)
            }
            if let valid = signature.cryptographicallyValid {
                LabeledContent("verification.cryptographicValidity") {
                    if valid {
                        Text("verification.cryptographicallyValid")
                            .foregroundStyle(.green)
                    } else {
                        Text("verification.cryptographicallyInvalid")
                            .foregroundStyle(.red)
                    }
                }
            } else {
                LabeledContent("verification.cryptographicValidity") {
                    Text("verification.notEvaluated")
                }
            }
            if let fingerprint = signature.signerFingerprint {
                LabeledContent("verification.signerFingerprint", value: fingerprint)
                    .textSelection(.enabled)
            }
            if let fingerprint = signature.certificateFingerprint {
                LabeledContent("verification.certificateFingerprint", value: fingerprint)
                    .textSelection(.enabled)
            }
            if let keyID = signature.signerKeyId {
                LabeledContent("verification.signerKeyId", value: keyID)
                    .textSelection(.enabled)
            }
            if let algorithm = signature.algorithm {
                LabeledContent("verification.algorithm", value: algorithm.name)
            }
            if let hashAlgorithm = signature.hashAlgorithm {
                LabeledContent("verification.hashAlgorithm", value: hashAlgorithm)
            }
            if let presentation = messagePolicyPresentation(for: [signature.legacyDecision]) {
                LegacyPolicyNotice(presentation: presentation)
            }
            if let createdAt = signature.createdAt {
                LabeledContent("verification.createdAt") {
                    Text(Date(timeIntervalSince1970: TimeInterval(createdAt)), format: .dateTime)
                }
            }
            if let validity = signature.keyValidity {
                KeyValidityView(validity: validity)
            }
        }
        .padding(.vertical, 4)
    }
}

private struct SignatureMetadataView: View {
    let metadata: SignatureMetadataFfi

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            LabeledContent("verification.signerFingerprint", value: metadata.signerFingerprint)
                .textSelection(.enabled)
            LabeledContent("verification.certificateFingerprint", value: metadata.certificateFingerprint)
                .textSelection(.enabled)
            LabeledContent("verification.algorithm", value: metadata.algorithm.name)
            LabeledContent("verification.hashAlgorithm", value: metadata.hashAlgorithm)
            if let createdAt = metadata.createdAt {
                LabeledContent("verification.createdAt") {
                    Text(Date(timeIntervalSince1970: TimeInterval(createdAt)), format: .dateTime)
                }
            }
        }
    }
}

private struct KeyValidityView: View {
    let validity: KeyValidityFfi

    var body: some View {
        if validity.notYetValid {
            Text("verification.key.notYetValid")
                .foregroundStyle(.red)
        }
        if validity.expired {
            Text("verification.key.expired")
                .foregroundStyle(.red)
        }
        if validity.revoked {
            Text("verification.key.revoked")
                .foregroundStyle(.red)
        }
        if !validity.hasCurrentBinding {
            Text("verification.key.noCurrentBinding")
                .foregroundStyle(.red)
        }
        if let expiresAt = validity.expiresAt {
            LabeledContent("verification.key.expiresAt") {
                Text(Date(timeIntervalSince1970: TimeInterval(expiresAt)), format: .dateTime)
            }
        }
    }
}

private struct IdentityTrustNote: View {
    let trust: IdentityTrustFfi

    var body: some View {
        switch trust {
        case .unknown:
            Label("verification.identityTrustUnknown", systemImage: "questionmark.circle")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

enum MessagePolicyLevel: Equatable {
    case warning
    case rejected
}

struct MessagePolicyPresentation: Equatable {
    let level: MessagePolicyLevel
    let kind: LegacyWarningKindFfi?
    let algorithm: String?

    init(level: MessagePolicyLevel, kind: LegacyWarningKindFfi?, algorithm: String?) {
        self.level = level
        self.kind = kind
        self.algorithm = algorithm
    }

    init?(_ decision: LegacyPolicyDecisionFfi) {
        guard decision.disposition == .reject || decision.warning != nil else { return nil }
        level = decision.disposition == .reject ? .rejected : .warning
        kind = decision.warning?.kind
        algorithm = decision.warning.map { Self.displayAlgorithm($0.algorithm) }
    }

    var title: LocalizedStringKey {
        switch level {
        case .warning: "verification.policy.warning"
        case .rejected: "verification.policy.rejected"
        }
    }

    var systemImage: String {
        switch level {
        case .warning: "exclamationmark.triangle.fill"
        case .rejected: "hand.raised.fill"
        }
    }

    var color: Color {
        switch level {
        case .warning: .orange
        case .rejected: .red
        }
    }

    private static func displayAlgorithm(_ identifier: String) -> String {
        switch identifier {
        case "sha1": "SHA-1"
        case "sha224": "SHA-224"
        case "sha256": "SHA-256"
        case "sha384": "SHA-384"
        case "sha512": "SHA-512"
        case "sha3-256": "SHA3-256"
        case "sha3-512": "SHA3-512"
        case "triple-des": "3DES"
        case "cast5": "CAST5"
        case "aes-128": "AES-128"
        case "aes-192": "AES-192"
        case "aes-256": "AES-256"
        default: identifier.uppercased()
        }
    }
}

func messagePolicyPresentation(
    for decisions: [LegacyPolicyDecisionFfi]
) -> MessagePolicyPresentation? {
    let presentations = decisions.compactMap(MessagePolicyPresentation.init)
    return presentations.first(where: { $0.level == .rejected }) ?? presentations.first
}

extension VerificationOutcomeFfi {
    var policyPresentation: MessagePolicyPresentation? {
        messagePolicyPresentation(for: signatures.map(\.legacyDecision))
    }
}

extension DecryptionReportFfi {
    var policyPresentation: MessagePolicyPresentation? {
        messagePolicyPresentation(for: [legacyDecision] + signatures.map(\.legacyDecision))
    }
}

private struct LegacyPolicyNotice: View {
    let presentation: MessagePolicyPresentation

    var body: some View {
        Label {
            switch (presentation.level, presentation.kind) {
            case (.warning, .weakSignatureHash):
                Text("verification.policy.weakHashWarning \(presentation.algorithm ?? "unknown")")
            case (.rejected, .weakSignatureHash):
                Text("verification.policy.weakHashRejected \(presentation.algorithm ?? "unknown")")
            case (.warning, .legacySymmetricCipher):
                Text("verification.policy.legacyCipherWarning \(presentation.algorithm ?? "unknown")")
            case (.rejected, .legacySymmetricCipher):
                Text("verification.policy.legacyCipherRejected \(presentation.algorithm ?? "unknown")")
            case (.rejected, nil):
                Text("verification.policy.unrecognizedRejected")
            case (.warning, nil):
                Text("verification.policy.unrecognizedWarning")
            }
        } icon: {
            Image(systemName: presentation.systemImage)
        }
        .font(.footnote)
        .foregroundStyle(presentation.color)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("message.policy.notice")
    }
}

private extension VerificationStatusFfi {
    var title: LocalizedStringKey {
        switch self {
        case .unsigned: "verification.status.unsigned"
        case .valid: "verification.status.valid"
        case .invalid: "verification.status.invalid"
        case .unknownSigner: "verification.status.unknownSigner"
        }
    }

    var systemImage: String {
        switch self {
        case .unsigned: "minus.circle"
        case .valid: "checkmark.seal.fill"
        case .invalid: "xmark.octagon.fill"
        case .unknownSigner: "questionmark.circle"
        }
    }

    var color: Color {
        switch self {
        case .unsigned: .secondary
        case .valid: .green
        case .invalid: .red
        case .unknownSigner: .orange
        }
    }
}

private extension DecryptionStatusFfi {
    var title: LocalizedStringKey {
        switch self {
        case .unsigned: "decryption.status.unsigned"
        case .valid: "decryption.status.valid"
        case .invalid: "decryption.status.invalid"
        case .unknownSigner: "decryption.status.unknownSigner"
        case .decryptionFailed: "decryption.status.decryptionFailed"
        case .integrityFailed: "decryption.status.integrityFailed"
        }
    }

    var systemImage: String {
        switch self {
        case .unsigned: "lock.open"
        case .valid: "checkmark.seal.fill"
        case .invalid: "xmark.octagon.fill"
        case .unknownSigner: "exclamationmark.triangle.fill"
        case .decryptionFailed: "lock.slash"
        case .integrityFailed: "exclamationmark.shield.fill"
        }
    }

    var color: Color {
        switch self {
        case .unsigned: .secondary
        case .valid: .green
        case .invalid, .decryptionFailed, .integrityFailed: .red
        case .unknownSigner: .orange
        }
    }
}
