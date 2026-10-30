import Foundation
import OpenPGPAppleSecureEnclave
import SwiftUI

enum PrivateKeyOperation {
    case signing
    case decryption
}

enum PrivateKeyAccess {
    case softwarePassword
    case smartCard
    case secureEnclave
    case unavailable
}

@MainActor
final class OpenPgpApplicationModel: ObservableObject {
    @Published private(set) var keys: [CertificateSummary] = []
    @Published private(set) var capabilityRegistry: AlgorithmCapabilityRegistry?
    @Published private(set) var cardRegistrations: [CardRegistrationFfi] = []
    @Published private(set) var secureEnclaveBindings: [SecureEnclaveBindingFfi] = []
    @Published private(set) var secureEnclaveRegistrations: [SecureEnclaveBindingFfi] = []
    @Published private(set) var secureEnclaveAccessControls: [String: SecureEnclaveAccessControl] = [:]
    @Published private(set) var secureEnclavePendingOperation: PendingSecureEnclaveOperation?
    @Published private(set) var secureEnclavePersistentStateAvailable = false
    @Published private(set) var isBusy = false
    @Published var errorMessage: String?

    private let engine: OpenPgpEngine
    private let persistence: SoftwareKeyPersistence?
    private let hardwareConnectionSettings: HardwareConnectionSettings
    let cardInteraction: CardInteractionCoordinator
    let cardSessions: any CardSessionManaging
    let secureEnclaveSessions: any SecureEnclaveSessionManaging

    init(
        engine: OpenPgpEngine = OpenPgpEngine(),
        persistence: SoftwareKeyPersistence? = nil,
        cardInteraction: CardInteractionCoordinator? = nil,
        cardSessions: (any CardSessionManaging)? = nil,
        secureEnclaveSessions: (any SecureEnclaveSessionManaging)? = nil,
        hardwareConnectionSettings: HardwareConnectionSettings = HardwareConnectionSettings()
    ) {
        self.engine = engine
        self.persistence = persistence
        self.hardwareConnectionSettings = hardwareConnectionSettings
        let interaction = cardInteraction ?? CardInteractionCoordinator()
        self.cardInteraction = interaction
        let sessions = cardSessions ?? CardSessionManager(
            engine: engine,
            interaction: interaction,
            store: persistence == nil ? .inMemory() : .live()
        )
        self.cardSessions = sessions
        cardRegistrations = sessions.registrations
        let persistSnapshot: @MainActor @Sendable () async throws -> Void = {
            guard let persistence else { return }
            let records = try await Task.detached(priority: .userInitiated) { [engine] in
                try engine.storageSnapshot()
            }.value
            try await persistence.save(records)
        }
        let enclave = secureEnclaveSessions ?? SecureEnclaveSessionManager(
            engine: engine,
            store: persistence == nil ? .inMemory() : .live(),
            persist: persistSnapshot
        )
        self.secureEnclaveSessions = enclave
        secureEnclaveBindings = enclave.bindings
        secureEnclaveRegistrations = enclave.registrations
        secureEnclaveAccessControls = enclave.accessControls
        secureEnclavePendingOperation = enclave.pendingOperation
        secureEnclavePersistentStateAvailable = enclave.persistentStateAvailable
        enclave.onChange = { [weak self] in
            guard let self else { return }
            secureEnclaveBindings = enclave.bindings
            secureEnclaveRegistrations = enclave.registrations
            secureEnclaveAccessControls = enclave.accessControls
            secureEnclavePendingOperation = enclave.pendingOperation
            secureEnclavePersistentStateAvailable = enclave.persistentStateAvailable
            refreshKeysAfterCardChange()
        }
        sessions.onChange = { [weak self] registrations in
            self?.cardRegistrations = registrations
            self?.refreshKeysAfterCardChange()
        }
    }

    static func live(
        cardInteraction: CardInteractionCoordinator? = nil
    ) -> OpenPgpApplicationModel {
        // UI tests opt out of on-device persistence so every launch starts from
        // an empty, deterministic keyring and leaves no test keys behind.
        if ProcessInfo.processInfo.arguments.contains("-DisableKeyPersistence") {
            return OpenPgpApplicationModel(cardInteraction: cardInteraction)
        }
        return OpenPgpApplicationModel(
            persistence: .live(),
            cardInteraction: cardInteraction
        )
    }

    var availableGenerationProfiles: [GenerationProfileFfi] {
        GenerationProfileFfi.allCases.filter { $0.isEnabled(in: capabilityRegistry) }
    }

    var canGenerateSecureEnclave: Bool {
        guard secureEnclavePersistentStateAvailable && secureEnclaveSessions.isAvailable else {
            return false
        }
        for (algorithm, operation) in [
            ("nist-p256-ecdsa", CapabilityOperation.generate),
            ("nist-p256-ecdsa", .useAsSigningSubkey),
            ("nist-p256-ecdh", .generate),
            ("nist-p256-ecdh", .useAsEncryptionSubkey),
        ] {
            guard capabilityRegistry?.entry(
                algorithm: algorithm,
                backend: "secure-enclave",
                keyVersion: "v4"
            )?.isOperationEnabled(operation) == true else { return false }
        }
        return true
    }

    func load() async {
        do {
            if capabilityRegistry == nil {
                async let registry = AlgorithmCapabilityService.loadRegistry()
                async let loadedKeys = Task.detached(priority: .userInitiated) { [engine, persistence] in
                    if let persistence {
                        let records = try await persistence.load()
                        if !records.isEmpty {
                            try engine.restoreStorage(records: records)
                        }
                    }
                    return try engine.listKeys()
                }.value
                capabilityRegistry = try await registry
                keys = try await loadedKeys
                try await secureEnclaveSessions.restore()
            }
            try await cardSessions.restore()
        } catch {
            errorMessage = ErrorPresenter.message(for: error)
        }
    }

    func readerNames() async throws -> [String] {
        do {
            return try await cardSessions.readerNames()
        } catch {
            errorMessage = ErrorPresenter.message(for: error)
            throw error
        }
    }

    func connectCard(
        certificateFingerprint: String,
        signingComponent: String?,
        decryptionComponent: String?,
        method: CardConnectionMethod,
        readerName: String?
    ) async throws -> CardRegistrationFfi {
        try await perform { [cardSessions] in
            try await cardSessions.connect(
                certificateFingerprint: certificateFingerprint,
                signingComponent: signingComponent,
                decryptionComponent: decryptionComponent,
                method: method,
                readerName: readerName
            )
        }
    }

    func disconnectCard(fingerprint: String) async throws {
        try await perform { [cardSessions] in
            try await cardSessions.disconnect(certificateFingerprint: fingerprint)
        }
    }

    func preferredCardConnection(for fingerprint: String) -> CardConnectionSelection {
        cardSessions.preferredConnection(for: fingerprint)
    }

    func inspectHardware(
        identity: CardIdentityFfi? = nil,
        connection: CardConnectionSelection
    ) async throws -> CardInformationFfi {
        try await perform(refresh: false) { [cardSessions] in
            try await cardSessions.withUnboundCardManagementSession(
                expectedIdentity: identity,
                connection: connection
            ) { session in
                try session.inspect()
            }
        }
    }

    func changeHardwarePin(
        identity: CardIdentityFfi,
        kind: CardPinKind,
        current: String,
        new: String,
        connection: CardConnectionSelection
    ) async throws -> CardInformationFfi {
        try await perform(refresh: false) { [cardSessions] in
            try await cardSessions.withUnboundCardManagementSession(
                expectedIdentity: identity,
                connection: connection
            ) { session in
                try session.changePin(kind: kind, current: current, new: new)
                return try session.inspect()
            }
        }
    }

    func setHardwareTouchPolicy(
        identity: CardIdentityFfi,
        slot: CardSlot,
        policy: CardTouchPolicyFfi,
        adminPin: String,
        connection: CardConnectionSelection
    ) async throws -> CardInformationFfi {
        try await perform(refresh: false) { [cardSessions] in
            try await cardSessions.withUnboundCardManagementSession(
                expectedIdentity: identity,
                connection: connection
            ) { session in
                try session.setTouchPolicy(slot: slot, policy: policy, adminPin: adminPin)
                return try session.inspect()
            }
        }
    }

    func hasCardBinding(fingerprint: String) -> Bool {
        cardRegistrations.contains { $0.certificateFingerprint == fingerprint }
    }

    func hasSecureEnclaveBinding(fingerprint: String) -> Bool {
        secureEnclaveBindings.contains { $0.certificateFingerprint == fingerprint }
    }

    func hasSecureEnclaveSession(fingerprint: String) -> Bool {
        secureEnclaveRegistrations.contains { $0.certificateFingerprint == fingerprint }
    }

    func hasSecureEnclaveComponent(certificate: String, component: String) -> Bool {
        secureEnclaveBindings.contains {
            $0.certificateFingerprint == certificate
                && ($0.signingComponentFingerprint == component
                    || $0.encryptionComponentFingerprint == component
                    || ($0.certification != nil && $0.certificateFingerprint == component))
        }
    }

    func isSoftwarePasswordRequired(
        fingerprint: String,
        operation: PrivateKeyOperation = .signing
    ) -> Bool {
        privateKeyAccess(fingerprint: fingerprint, operation: operation) == .softwarePassword
    }

    var allowsSoftwareExportByDefault: Bool {
        UserDefaults.standard.bool(forKey: SecuritySettings.softwareExportStorageKey)
    }

    func generate(
        profile: GenerationProfileFfi,
        userID: String,
        password: String,
        exportPolicy: ExportPolicyFfi
    ) async throws -> GeneratedKeyFfi {
        guard profile.isEnabled(in: capabilityRegistry) else {
            throw AddresseeError.UnsupportedOperation
        }
        return try await perform { [engine] in
            let generated = try engine.generateKey(
                profile: profile,
                userId: userID,
                password: password,
                exportPolicy: exportPolicy
            )
            return generated
        }
    }

    func generateSecureEnclave(userID: String) async throws -> GeneratedKeyFfi {
        guard canGenerateSecureEnclave else {
            throw AddresseeError.UnsupportedOperation
        }
        return try await perform { [secureEnclaveSessions] in
            try await secureEnclaveSessions.generate(userID: userID).generated
        }
    }

    func restoreSecureEnclave() async throws {
        try await perform(refresh: false) { [secureEnclaveSessions] in
            try await secureEnclaveSessions.restore()
        }
    }

    func importPublic(_ input: Data) async throws -> ImportResultFfi {
        try await perform { [engine] in
            let result = try engine.importPublicKey(input: input)
            return result
        }
    }

    func importPrivate(
        _ input: Data,
        currentPassword: String?,
        newPassword: String,
        exportPolicy: ExportPolicyFfi
    ) async throws -> ImportResultFfi {
        try await perform { [engine] in
            let result = try engine.importPrivateKey(
                input: input,
                currentPassword: currentPassword,
                newPassword: newPassword,
                exportPolicy: exportPolicy
            )
            return result
        }
    }

    func exportPublic(fingerprint: String, format: ExportFormatFfi) async throws -> Data {
        try await perform { [engine] in
            try engine.exportPublicKey(fingerprint: fingerprint, format: format)
        }
    }

    func exportPrivate(fingerprint: String, format: ExportFormatFfi) async throws -> Data {
        guard keys.first(where: { $0.fingerprint == fingerprint })?.privateExportPolicy != .notApplicable else {
            throw AddresseeError.PublicKeyOnly
        }
        guard keys.first(where: { $0.fingerprint == fingerprint })?.privateExportPolicy == .allowed else {
            throw AddresseeError.ExportDisabled
        }
        return try await perform { [engine] in
            try engine.exportPrivateKey(fingerprint: fingerprint, format: format)
        }
    }

    func removeKey(fingerprint: String) async throws {
        let needsDisconnect = hasCardBinding(fingerprint: fingerprint)
        let needsSecureEnclaveDeletion = hasSecureEnclaveBinding(fingerprint: fingerprint)
        try await perform { [engine, cardSessions, secureEnclaveSessions] in
            if needsDisconnect {
                try await cardSessions.disconnect(certificateFingerprint: fingerprint)
            }
            if needsSecureEnclaveDeletion {
                try await secureEnclaveSessions.delete(certificateFingerprint: fingerprint)
            } else {
                try engine.removeKey(fingerprint: fingerprint)
            }
        }
    }

    private func refreshKeys() throws {
        keys = try engine.listKeys()
    }

    private func refreshKeysAfterCardChange() {
        do {
            try refreshKeys()
        } catch {
            errorMessage = ErrorPresenter.message(for: error)
        }
    }

    private func persist() async throws {
        guard let persistence else { return }
        let snapshot = try await Task.detached(priority: .userInitiated) { [engine] in
            try engine.storageSnapshot()
        }.value
        try await persistence.save(snapshot)
    }

    private func perform<T: Sendable>(
        refresh: Bool = true,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        do {
            let result = try await Task.detached(priority: .userInitiated) {
                try await operation()
            }.value
            if refresh {
                try refreshKeys()
                try await persist()
            }
            return result
        } catch {
            errorMessage = ErrorPresenter.message(for: error)
            throw error
        }
    }

    private func performPrivateKey<T: Sendable>(
        fingerprint: String,
        kind: PrivateKeyOperation,
        connection: CardConnectionSelection?,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        let cardBound = hasCardBinding(fingerprint: fingerprint)
        let connection = connection ?? preferredCardConnection(for: fingerprint)
        return try await perform(refresh: false) { [cardSessions] in
            if cardBound {
                return try await cardSessions.withCardSession(
                    certificateFingerprint: fingerprint,
                    operation: kind,
                    connection: connection,
                    body: operation
                )
            }
            return try await operation()
        }
    }
}

extension OpenPgpApplicationModel {
    func canSubmitPrivateKeyOperation(
        fingerprint: String,
        password: String,
        operation: PrivateKeyOperation = .signing,
        connection: CardConnectionSelection? = nil
    ) -> Bool {
        switch privateKeyAccess(fingerprint: fingerprint, operation: operation) {
        case .softwarePassword:
            return !password.isEmpty
        case .smartCard:
            return (connection ?? cardSessions.preferredConnection(for: fingerprint))
                .isComplete(allowsMultipleHardwareKeys: hardwareConnectionSettings.allowsMultipleHardwareKeys)
        case .secureEnclave:
            return true
        case .unavailable:
            return false
        }
    }

    func privateKeyAccess(
        fingerprint: String,
        operation: PrivateKeyOperation
    ) -> PrivateKeyAccess {
        if let pending = secureEnclavePendingOperation {
            switch pending {
            case .generation(let journal):
                if journal.candidate?.certificateFingerprint == fingerprint { return .unavailable }
            case .deletion(let journal):
                if journal.binding.certificateFingerprint == fingerprint { return .unavailable }
            }
        }
        guard let key = keys.first(where: { $0.fingerprint == fingerprint }) else {
            return .unavailable
        }
        let matches: (KeyMetadataSummary) -> Bool = switch operation {
        case .signing: { $0.keyFlags.sign }
        case .decryption: isEncryptionCapable
        }
        switch operation {
        case .signing:
            if hasBoundComponent(key, slot: .signing, matching: matches) { return .smartCard }
        case .decryption:
            if hasBoundComponent(key, slot: .decryption, matching: matches) { return .smartCard }
        }
        if let registration = secureEnclaveRegistrations.first(where: {
            $0.certificateFingerprint == fingerprint
        }) {
            let component = operation == .signing
                ? registration.signingComponentFingerprint
                : registration.encryptionComponentFingerprint
            if keyComponents(key).contains(where: { matches($0) && $0.fingerprint == component }) {
                return .secureEnclave
            }
        }
        if keyComponents(key).contains(where: { matches($0) && $0.storage == .softwareSecret }) {
            return .softwarePassword
        }
        if let binding = secureEnclaveBindings.first(where: {
            $0.certificateFingerprint == fingerprint
        }) {
            let component = operation == .signing
                ? binding.signingComponentFingerprint
                : binding.encryptionComponentFingerprint
            if keyComponents(key).contains(where: { matches($0) && $0.fingerprint == component }) {
                return .unavailable
            }
        }
        return .unavailable
    }

    var signingKeys: [CertificateSummary] {
        keys.filter { privateKeyAccess(fingerprint: $0.fingerprint, operation: .signing) != .unavailable }
    }

    var decryptionKeys: [CertificateSummary] {
        keys.filter { privateKeyAccess(fingerprint: $0.fingerprint, operation: .decryption) != .unavailable }
    }

    func protectionTitle(for key: CertificateSummary) -> LocalizedStringKey {
        if hasCardBinding(fingerprint: key.fingerprint) { return "keys.protection.smartCard" }
        if hasSecureEnclaveBinding(fingerprint: key.fingerprint) {
            return hasSecureEnclaveSession(fingerprint: key.fingerprint)
                ? "keys.protection.secureEnclave"
                : "keys.protection.secureEnclaveUnavailable"
        }
        return key.protectionTitle
    }

    func protectionTitle(
        for key: CertificateSummary,
        component: KeyMetadataSummary
    ) -> LocalizedStringKey {
        if let registration = cardRegistrations.first(where: {
            $0.certificateFingerprint == key.fingerprint
        }), registration.components.contains(where: {
            $0.componentFingerprint == component.fingerprint
        }) {
            return "keys.protection.smartCard"
        }
        if hasSecureEnclaveComponent(
            certificate: key.fingerprint,
            component: component.fingerprint
        ) {
            return hasSecureEnclaveSession(fingerprint: key.fingerprint)
                ? "keys.protection.secureEnclave"
                : "keys.protection.secureEnclaveUnavailable"
        }
        return component.storage == .softwareSecret
            ? "keys.protection.software"
            : "keys.protection.publicOnly"
    }

    var encryptionRecipientKeys: [CertificateSummary] {
        keys.filter { keyComponents($0).contains(where: isEncryptionCapable) }
    }

    private func hasBoundComponent(
        _ key: CertificateSummary,
        slot: CardSlot,
        matching predicate: (KeyMetadataSummary) -> Bool
    ) -> Bool {
        guard key.storage == .publicOnly,
              let registration = cardRegistrations.first(where: {
                  $0.certificateFingerprint == key.fingerprint
              }) else { return false }
        return key.subkeys.contains { component in
            predicate(component) && registration.components.contains {
                $0.slot == slot && $0.componentFingerprint == component.fingerprint
            }
        }
    }

    func signDetached(
        signingKey: String,
        password: String,
        atUnixSeconds: UInt64,
        data: Data,
        format: MessageFormatFfi,
        connection: CardConnectionSelection? = nil
    ) async throws -> SignatureArtifactFfi {
        try await performPrivateKey(
            fingerprint: signingKey,
            kind: .signing,
            connection: connection
        ) { [engine] in
            try engine.signDetached(
                signingKey: signingKey,
                password: password,
                atUnixSeconds: atUnixSeconds,
                data: data,
                format: format
            )
        }
    }

    func signAttached(
        signingKey: String,
        password: String,
        atUnixSeconds: UInt64,
        data: Data,
        format: MessageFormatFfi,
        connection: CardConnectionSelection? = nil
    ) async throws -> SignatureArtifactFfi {
        try await performPrivateKey(
            fingerprint: signingKey,
            kind: .signing,
            connection: connection
        ) { [engine] in
            try engine.signAttached(
                signingKey: signingKey,
                password: password,
                atUnixSeconds: atUnixSeconds,
                data: data,
                format: format
            )
        }
    }

    func signCleartext(
        signingKey: String,
        password: String,
        atUnixSeconds: UInt64,
        text: String,
        connection: CardConnectionSelection? = nil
    ) async throws -> SignatureArtifactFfi {
        try await performPrivateKey(
            fingerprint: signingKey,
            kind: .signing,
            connection: connection
        ) { [engine] in
            try engine.signCleartext(
                signingKey: signingKey,
                password: password,
                atUnixSeconds: atUnixSeconds,
                text: text
            )
        }
    }

    func verifyDetached(
        data: Data,
        signature: Data,
        atUnixSeconds: UInt64
    ) async throws -> VerificationOutcomeFfi {
        try await perform(refresh: false) { [engine] in
            try engine.verifyDetached(data: data, signature: signature, atUnixSeconds: atUnixSeconds)
        }
    }

    func verifyAttached(input: Data, atUnixSeconds: UInt64) async throws -> VerificationResultFfi {
        try await perform(refresh: false) { [engine] in
            try engine.verifyAttached(input: input, atUnixSeconds: atUnixSeconds)
        }
    }

    func verifyCleartext(input: Data, atUnixSeconds: UInt64) async throws -> CleartextVerificationFfi {
        try await perform(refresh: false) { [engine] in
            try engine.verifyCleartext(input: input, atUnixSeconds: atUnixSeconds)
        }
    }

    func encrypt(
        recipients: [String],
        atUnixSeconds: UInt64,
        config: EncryptionConfigFfi,
        data: Data,
        format: MessageFormatFfi
    ) async throws -> Data {
        try await perform(refresh: false) { [engine] in
            try engine.encrypt(
                recipients: recipients,
                atUnixSeconds: atUnixSeconds,
                config: config,
                data: data,
                format: format
            )
        }
    }

    func encryptText(
        recipients: [String],
        atUnixSeconds: UInt64,
        config: EncryptionConfigFfi,
        text: String,
        format: MessageFormatFfi
    ) async throws -> Data {
        try await perform(refresh: false) { [engine] in
            try engine.encryptText(
                recipients: recipients,
                atUnixSeconds: atUnixSeconds,
                config: config,
                text: text,
                format: format
            )
        }
    }

    func signAndEncrypt(
        request: SignEncryptRequestFfi,
        connection: CardConnectionSelection? = nil
    ) async throws -> SignatureArtifactFfi {
        try await performPrivateKey(
            fingerprint: request.signingKey,
            kind: .signing,
            connection: connection
        ) { [engine] in
            try engine.signAndEncrypt(request: request)
        }
    }

    func signAndEncryptText(
        request: SignEncryptTextRequestFfi,
        connection: CardConnectionSelection? = nil
    ) async throws -> SignatureArtifactFfi {
        try await performPrivateKey(
            fingerprint: request.signingKey,
            kind: .signing,
            connection: connection
        ) { [engine] in
            try engine.signAndEncryptText(request: request)
        }
    }

    func decrypt(
        decryptionKey: String,
        password: String,
        atUnixSeconds: UInt64,
        input: Data,
        connection: CardConnectionSelection? = nil
    ) async throws -> DecryptedMessageFfi {
        try await performPrivateKey(
            fingerprint: decryptionKey,
            kind: .decryption,
            connection: connection
        ) { [engine] in
            try engine.decrypt(
                decryptionKey: decryptionKey,
                password: password,
                atUnixSeconds: atUnixSeconds,
                input: input
            )
        }
    }

    func decryptText(
        decryptionKey: String,
        password: String,
        atUnixSeconds: UInt64,
        input: Data,
        connection: CardConnectionSelection? = nil
    ) async throws -> DecryptedTextFfi {
        try await performPrivateKey(
            fingerprint: decryptionKey,
            kind: .decryption,
            connection: connection
        ) { [engine] in
            try engine.decryptText(
                decryptionKey: decryptionKey,
                password: password,
                atUnixSeconds: atUnixSeconds,
                input: input
            )
        }
    }

    func signDetachedFile(
        signingKey: String,
        password: String,
        atUnixSeconds: UInt64,
        inputPath: String,
        outputPath: String,
        format: MessageFormatFfi,
        connection: CardConnectionSelection? = nil
    ) async throws -> SignatureMetadataFfi {
        try await performPrivateKey(
            fingerprint: signingKey,
            kind: .signing,
            connection: connection
        ) { [engine] in
            try engine.signDetachedFile(
                signingKey: signingKey,
                password: password,
                atUnixSeconds: atUnixSeconds,
                inputPath: inputPath,
                outputPath: outputPath,
                format: format
            )
        }
    }

    func signAttachedFile(
        signingKey: String,
        password: String,
        atUnixSeconds: UInt64,
        inputPath: String,
        outputPath: String,
        format: MessageFormatFfi,
        connection: CardConnectionSelection? = nil
    ) async throws -> SignatureMetadataFfi {
        try await performPrivateKey(
            fingerprint: signingKey,
            kind: .signing,
            connection: connection
        ) { [engine] in
            try engine.signAttachedFile(
                signingKey: signingKey,
                password: password,
                atUnixSeconds: atUnixSeconds,
                inputPath: inputPath,
                outputPath: outputPath,
                format: format
            )
        }
    }

    func verifyDetachedFile(
        dataPath: String,
        signaturePath: String,
        atUnixSeconds: UInt64
    ) async throws -> VerificationOutcomeFfi {
        try await perform(refresh: false) { [engine] in
            try engine.verifyDetachedFile(
                dataPath: dataPath,
                signaturePath: signaturePath,
                atUnixSeconds: atUnixSeconds
            )
        }
    }

    func verifyAttachedFile(
        inputPath: String,
        outputPath: String,
        atUnixSeconds: UInt64
    ) async throws -> VerificationOutcomeFfi {
        try await perform(refresh: false) { [engine] in
            try engine.verifyAttachedFile(
                inputPath: inputPath,
                outputPath: outputPath,
                atUnixSeconds: atUnixSeconds
            )
        }
    }

    func encryptFile(
        recipients: [String],
        atUnixSeconds: UInt64,
        config: EncryptionConfigFfi,
        inputPath: String,
        outputPath: String,
        format: MessageFormatFfi
    ) async throws {
        let _: Void = try await perform(refresh: false) { [engine] in
            try engine.encryptFile(
                recipients: recipients,
                atUnixSeconds: atUnixSeconds,
                config: config,
                inputPath: inputPath,
                outputPath: outputPath,
                format: format
            )
        }
    }

    func signAndEncryptFile(
        request: SignEncryptFileRequestFfi,
        connection: CardConnectionSelection? = nil
    ) async throws -> SignatureMetadataFfi {
        try await performPrivateKey(
            fingerprint: request.signingKey,
            kind: .signing,
            connection: connection
        ) { [engine] in
            try engine.signAndEncryptFile(request: request)
        }
    }

    func decryptFile(
        decryptionKey: String,
        password: String,
        atUnixSeconds: UInt64,
        inputPath: String,
        outputPath: String,
        connection: CardConnectionSelection? = nil
    ) async throws -> DecryptionReportFfi {
        try await performPrivateKey(
            fingerprint: decryptionKey,
            kind: .decryption,
            connection: connection
        ) { [engine] in
            try engine.decryptFile(
                decryptionKey: decryptionKey,
                password: password,
                atUnixSeconds: atUnixSeconds,
                inputPath: inputPath,
                outputPath: outputPath
            )
        }
    }

    private func keyComponents(_ key: CertificateSummary) -> [KeyMetadataSummary] {
        [key.primary] + key.subkeys
    }

    private func isEncryptionCapable(_ key: KeyMetadataSummary) -> Bool {
        key.keyFlags.encryptCommunications || key.keyFlags.encryptStorage
    }
}
