import Foundation
import OpenPGPAppleSecureEnclave

@MainActor
protocol SecureEnclaveSessionManaging: AnyObject, Sendable {
    var bindings: [SecureEnclaveBindingFfi] { get }
    var registrations: [SecureEnclaveBindingFfi] { get }
    var accessControls: [String: SecureEnclaveAccessControl] { get }
    var pendingOperation: PendingSecureEnclaveOperation? { get }
    var persistentStateAvailable: Bool { get }
    var isAvailable: Bool { get }
    var onChange: (() -> Void)? { get set }

    func restore() async throws
    func generate(userID: String) async throws -> SecureEnclaveGeneratedKeyFfi
    func delete(certificateFingerprint: String) async throws
}

@MainActor
final class SecureEnclaveSessionManager: SecureEnclaveSessionManaging {
    private(set) var bindings: [SecureEnclaveBindingFfi] = []
    private(set) var registrations: [SecureEnclaveBindingFfi] = []
    private(set) var accessControls: [String: SecureEnclaveAccessControl] = [:]
    private(set) var pendingOperation: PendingSecureEnclaveOperation?
    private(set) var persistentStateAvailable = false
    private(set) var isAvailable = false
    var onChange: (() -> Void)?

    private let engine: OpenPgpEngine
    private let lifecycle: any SecureEnclaveLifecycle
    private let store: SecureEnclaveBindingStore
    private let persist: @MainActor @Sendable () async throws -> Void
    private var isTransitioning = false

    init(
        engine: OpenPgpEngine,
        lifecycle: any SecureEnclaveLifecycle = SecureEnclaveBridge(),
        store: SecureEnclaveBindingStore,
        persist: @escaping @MainActor @Sendable () async throws -> Void
    ) {
        self.engine = engine
        self.lifecycle = lifecycle
        self.store = store
        self.persist = persist
    }

    func restore() async throws {
        try beginTransition()
        defer { isTransitioning = false }
        isAvailable = await lifecycle.isAvailable()
        var firstFailure: Error?
        do {
            let snapshot = try await store.snapshot()
            if let pending = snapshot.pending {
                do {
                    switch pending {
                    case .generation:
                        try await rollbackGeneration()
                    case .deletion(let journal):
                        try await performDeletion(journal)
                    }
                } catch {
                    firstFailure = error
                }
            }
            let current = try await store.snapshot()
            let deleting = deletionFingerprint(current.pending)
            var active: [SecureEnclaveBindingFfi] = []
            for binding in current.bindings where binding.certificateFingerprint != deleting {
                do {
                    active.append(try await register(binding))
                } catch {
                    if firstFailure == nil { firstFailure = error }
                }
            }
            bindings = current.bindings
            accessControls = current.accessControls
            pendingOperation = current.pending
            registrations = active.sorted { $0.certificateFingerprint < $1.certificateFingerprint }
            persistentStateAvailable = true
            onChange?()
        } catch {
            bindings = []
            registrations = []
            accessControls = [:]
            pendingOperation = nil
            persistentStateAvailable = false
            onChange?()
            throw error
        }
        if let firstFailure { throw firstFailure }
    }

    func generate(userID: String) async throws -> SecureEnclaveGeneratedKeyFfi {
        try beginTransition()
        defer { isTransitioning = false }
        isAvailable = await lifecycle.isAvailable()
        guard isAvailable else { throw AddresseeError.RemoteKeyUnavailable }
        let certificationIdentifier = try await lifecycle.nextIdentifier(for: .signing)
        let signingIdentifier = try await lifecycle.nextIdentifier(for: .signing)
        let encryptionIdentifier = try await lifecycle.nextIdentifier(for: .keyAgreement)
        try await store.beginGeneration(
            certificationIdentifier: certificationIdentifier,
            signingIdentifier: signingIdentifier,
            encryptionIdentifier: encryptionIdentifier
        )
        var generated: SecureEnclaveGeneratedKeyFfi?
        do {
            let certification = try await lifecycle.generateReference(
                usage: .signing,
                identifier: certificationIdentifier
            )
            let signing = try await lifecycle.generateReference(
                usage: .signing,
                identifier: signingIdentifier
            )
            let encryption = try await lifecycle.generateReference(
                usage: .keyAgreement,
                identifier: encryptionIdentifier
            )
            generated = try await engineCall { [lifecycle] engine in
                try engine.generateSecureEnclaveKey(
                    userId: userID,
                    certification: certification,
                    signing: signing,
                    encryption: encryption,
                    provider: lifecycle
                )
            }
            guard let generated else { throw SecureEnclaveLifecycleError.conflictingRecord }
            try await lifecycle.registerComponentFingerprints(binding: generated.binding)
            try await store.recordGenerationCandidate(generated.binding)
            try await persist()
            try await store.commitGeneration(generated.binding)
            registrations.removeAll {
                $0.certificateFingerprint == generated.binding.certificateFingerprint
            }
            registrations.append(generated.binding)
            registrations.sort { $0.certificateFingerprint < $1.certificateFingerprint }
            try await publish()
            return generated
        } catch {
            do {
                try await rollbackGeneration(generatedBinding: generated?.binding)
                try await publish()
            } catch {
                try? await publish()
                throw SecureEnclaveLifecycleError.cleanupFailed
            }
            throw error
        }
    }

    func delete(certificateFingerprint: String) async throws {
        try beginTransition()
        defer { isTransitioning = false }
        try await store.beginDeletion(certificateFingerprint: certificateFingerprint)
        let snapshot = try await store.snapshot()
        guard case .deletion(let journal) = snapshot.pending else {
            throw SecureEnclaveLifecycleError.conflictingRecord
        }
        do {
            try await performDeletion(journal)
            try await publish()
        } catch {
            registrations.removeAll { $0.certificateFingerprint == certificateFingerprint }
            try? await publish()
            throw error
        }
    }

    private func beginTransition() throws {
        guard !isTransitioning else { throw AddresseeError.RemoteKeyUnavailable }
        isTransitioning = true
    }

    private func register(_ binding: SecureEnclaveBindingFfi) async throws -> SecureEnclaveBindingFfi {
        try await lifecycle.registerComponentFingerprints(binding: binding)
        let existing = try await engineCall { engine in
            try engine.secureEnclaveRegistrations()
        }
        if let current = existing.first(where: {
            $0.certificateFingerprint == binding.certificateFingerprint
        }) {
            guard SecureEnclaveBindingRecord(current) == SecureEnclaveBindingRecord(binding) else {
                throw SecureEnclaveLifecycleError.conflictingRecord
            }
            return current
        }
        return try await engineCall { [lifecycle] engine in
            try engine.registerSecureEnclave(binding: binding, provider: lifecycle)
        }
    }

    private func rollbackGeneration(
        generatedBinding: SecureEnclaveBindingFfi? = nil
    ) async throws {
        let snapshot = try await store.snapshot()
        guard case .generation(let journal) = snapshot.pending else { return }
        if let persisted = journal.candidate, let generatedBinding,
           persisted != SecureEnclaveBindingRecord(generatedBinding) {
            throw SecureEnclaveLifecycleError.conflictingRecord
        }
        let candidate = journal.candidate
            ?? generatedBinding.map { SecureEnclaveBindingRecord($0) }
        var failed = false
        if let candidate {
            do {
                try await removeEngineRecord(candidate.ffi())
            } catch {
                failed = true
            }
        }
        for (identifier, usage, reference, fingerprint) in [
            (
                journal.certificationIdentifier,
                SecureEnclaveUsageFfi.signing,
                candidate?.certification,
                candidate?.certificateFingerprint
            ),
            (
                journal.signingIdentifier,
                SecureEnclaveUsageFfi.signing,
                candidate?.signing,
                candidate?.signingComponentFingerprint
            ),
            (
                journal.encryptionIdentifier,
                SecureEnclaveUsageFfi.keyAgreement,
                candidate?.encryption,
                candidate?.encryptionComponentFingerprint
            ),
        ] {
            do {
                if let reference {
                    try await lifecycle.deleteReference(reference.ffi(), componentFingerprint: fingerprint)
                } else if let identifier {
                    try await lifecycle.deleteUnboundIdentifier(identifier, usage: usage)
                }
            } catch {
                failed = true
            }
        }
        guard !failed else { throw SecureEnclaveLifecycleError.cleanupFailed }
        try await store.cancelGeneration()
    }

    private func performDeletion(_ journal: SecureEnclaveDeletionJournal) async throws {
        let binding = journal.binding.ffi()
        try await removeEngineRecord(binding)
        registrations.removeAll { $0.certificateFingerprint == binding.certificateFingerprint }
        let references = [
            journal.binding.certification,
            journal.binding.signing,
            journal.binding.encryption,
        ].compactMap { $0 }
        for reference in references {
            if journal.deletedIdentifiers.contains(reference.id) { continue }
            let fingerprint = if reference.id == journal.binding.certification?.id {
                journal.binding.certificateFingerprint
            } else if reference.usage == .signing {
                journal.binding.signingComponentFingerprint
            } else {
                journal.binding.encryptionComponentFingerprint
            }
            try await lifecycle.deleteReference(reference.ffi(), componentFingerprint: fingerprint)
            try await store.markDeleted(identifier: reference.id)
        }
        try await store.finishDeletion(certificateFingerprint: binding.certificateFingerprint)
    }

    private func removeEngineRecord(_ binding: SecureEnclaveBindingFfi) async throws {
        let fingerprint = binding.certificateFingerprint
        let current = try await engineCall { engine in
            try engine.secureEnclaveRegistrations()
        }
        if let registration = current.first(where: { $0.certificateFingerprint == fingerprint }) {
            guard SecureEnclaveBindingRecord(registration) == SecureEnclaveBindingRecord(binding) else {
                throw SecureEnclaveLifecycleError.conflictingRecord
            }
            _ = try await engineCall { engine in
                try engine.detachSecureEnclave(certificateFingerprint: fingerprint)
            }
        }
        let matching = try await engineCall { engine in
            try engine.listKeys().first(where: { $0.fingerprint == fingerprint })
        }
        if let matching {
            let hasExpectedPrimaryStorage = binding.certification == nil
                || matching.primary.storage == .publicOnly
            guard matching.privateExportPolicy != .allowed,
                  hasExpectedPrimaryStorage,
                  matching.subkeys.allSatisfy({ $0.storage == .publicOnly }) else {
                throw SecureEnclaveLifecycleError.conflictingRecord
            }
            let certificate = try await engineCall { engine in
                try engine.exportPublicKey(fingerprint: fingerprint, format: .binary)
            }
            guard certificate == binding.publicCertificate else {
                throw SecureEnclaveLifecycleError.conflictingRecord
            }
            try await engineCall { engine in
                try engine.removeKey(fingerprint: fingerprint)
            }
        }
        try await persist()
    }

    private func publish() async throws {
        let snapshot = try await store.snapshot()
        bindings = snapshot.bindings
        accessControls = snapshot.accessControls
        pendingOperation = snapshot.pending
        persistentStateAvailable = true
        onChange?()
    }

    private func deletionFingerprint(_ pending: PendingSecureEnclaveOperation?) -> String? {
        guard case .deletion(let journal) = pending else { return nil }
        return journal.binding.certificateFingerprint
    }

    private func engineCall<Value: Sendable>(
        _ operation: @escaping @Sendable (OpenPgpEngine) throws -> Value
    ) async throws -> Value {
        try await Task.detached(priority: .userInitiated) { [engine] in
            try operation(engine)
        }.value
    }
}
