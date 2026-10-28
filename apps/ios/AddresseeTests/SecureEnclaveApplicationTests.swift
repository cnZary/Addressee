import CryptoKit
import OpenPGPAppleSecureEnclave
import OpenPGPKeyProvider
import Security
import XCTest
@testable import Addressee

@MainActor
final class SecureEnclaveApplicationTests: XCTestCase {
    private var directory: URL!

    override func setUp() async throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SecureEnclaveApplicationTests-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testBridgeConvertsDERSignatureAndUsesExactSHA256Digest() async throws {
        let provider = SoftwareP256Provider()
        let bridge = SecureEnclaveBridge(provider: provider)
        let identifier = try await bridge.nextIdentifier(for: .signing)
        let reference = try await bridge.generateReference(usage: .signing, identifier: identifier)
        let message = Data("Exact SHA-256 digest through the native bridge".utf8)
        let digest = Data(SHA256.hash(data: message))

        let raw = try await offMain {
            try bridge.signSha256(reference: reference, digest: digest)
        }
        XCTAssertEqual(raw.count, 64)
        let observedDigest = await provider.lastDigest
        XCTAssertEqual(observedDigest, digest)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        let publicKey = try P256.Signing.PublicKey(x963Representation: reference.publicKeyX963)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
        XCTAssertFalse(publicKey.isValidSignature(signature, for: Data("Tampered".utf8)))
    }

    func testBridgeECDHMatchesIndependentCryptoKitPeer() async throws {
        let provider = SoftwareP256Provider()
        let bridge = SecureEnclaveBridge(provider: provider)
        let identifier = try await bridge.nextIdentifier(for: .keyAgreement)
        let reference = try await bridge.generateReference(usage: .keyAgreement, identifier: identifier)
        let peer = P256.KeyAgreement.PrivateKey()

        let actual = try await offMain {
            try bridge.ecdh(reference: reference, peerPublicKey: peer.publicKey.x963Representation)
        }
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: reference.publicKeyX963)
        let expected = try peer.sharedSecretFromKeyAgreement(with: publicKey)
        XCTAssertEqual(actual.count, 32)
        XCTAssertEqual(actual, expected.withUnsafeBytes { Data($0) })
    }

    func testHybridCertificateSupportsMessagesWithoutSoftwarePassword() async throws {
        let provider = SoftwareP256Provider()
        let snapshots = TestSnapshots()
        let engine = OpenPgpEngine()
        let manager = makeManager(
            engine: engine,
            provider: provider,
            store: .inMemory(),
            snapshots: snapshots
        )
        let model = OpenPgpApplicationModel(engine: engine, secureEnclaveSessions: manager)
        await model.load()
        let generated = try await manager.generate(
            userID: "Native P-256 <native-p256@example.invalid>"
        )
        let fingerprint = generated.generated.summary.fingerprint
        let requestedAccessControls = await provider.accessControls
        XCTAssertEqual(requestedAccessControls[.signing], .biometryAny)
        XCTAssertEqual(requestedAccessControls[.keyAgreement], .biometryAny)
        XCTAssertEqual(manager.accessControls[fingerprint], .biometryAny)
        XCTAssertEqual(model.secureEnclaveRegistrations.count, 1)
        XCTAssertEqual(generated.generated.summary.primary.storage, .softwareSecret)
        XCTAssertTrue(generated.generated.summary.subkeys.allSatisfy { $0.storage == .publicOnly })
        XCTAssertEqual(model.privateKeyAccess(fingerprint: fingerprint, operation: .signing), .secureEnclave)
        XCTAssertEqual(model.privateKeyAccess(fingerprint: fingerprint, operation: .decryption), .secureEnclave)
        XCTAssertTrue(model.canSubmitPrivateKeyOperation(fingerprint: fingerprint, password: ""))
        XCTAssertTrue(model.canSubmitPrivateKeyOperation(
            fingerprint: fingerprint,
            password: "",
            operation: .decryption
        ))

        let at = UInt64(Date().timeIntervalSince1970) + 60
        let data = Data("Native P-256 detached signature\0payload".utf8)
        let detached = try await model.signDetached(
            signingKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            data: data,
            format: .armored
        )
        XCTAssertEqual(detached.metadata.signerFingerprint, generated.binding.signingComponentFingerprint)
        let verified = try await model.verifyDetached(
            data: data,
            signature: detached.artifact,
            atUnixSeconds: at
        )
        XCTAssertEqual(verified.status, .valid)

        let attached = try await model.signAttached(
            signingKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            data: data,
            format: .binary
        )
        let attachedResult = try await model.verifyAttached(input: attached.artifact, atUnixSeconds: at)
        XCTAssertEqual(attachedResult.outcome.status, .valid)
        XCTAssertEqual(attachedResult.plaintext, data)

        let cleartext = try await model.signCleartext(
            signingKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            text: "first line\r\nsecond line\r\n"
        )
        let cleartextResult = try await model.verifyCleartext(input: cleartext.artifact, atUnixSeconds: at)
        XCTAssertEqual(cleartextResult.outcome.status, .valid)

        let config = EncryptionConfigFfi.seipdV1(cipher: .aes256)
        let encrypted = try await model.encryptText(
            recipients: [fingerprint],
            atUnixSeconds: at,
            config: config,
            text: "hardware encryption",
            format: .armored
        )
        let decrypted = try await model.decryptText(
            decryptionKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            input: encrypted
        )
        XCTAssertEqual(decrypted.report.status, .unsigned)
        XCTAssertEqual(decrypted.text, "hardware encryption")

        let combined = try await model.signAndEncryptText(
            request: SignEncryptTextRequestFfi(
                signingKey: fingerprint,
                password: "",
                recipients: [fingerprint],
                atUnixSeconds: at,
                config: config,
                text: "hardware sign then encrypt",
                format: .armored
            )
        )
        let combinedResult = try await model.decryptText(
            decryptionKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            input: combined.artifact
        )
        XCTAssertEqual(combinedResult.report.status, .valid)
        XCTAssertEqual(combinedResult.text, "hardware sign then encrypt")

        do {
            _ = try await model.exportPrivate(fingerprint: fingerprint, format: .binary)
            XCTFail("The hybrid certificate must not expose private export")
        } catch let error as AddresseeError {
            XCTAssertEqual(error, .ExportDisabled)
        }
        XCTAssertTrue(model.canGenerateSecureEnclave)
    }

    func testGenerationRequiresRuntimeAvailabilityAndRestoredState() async throws {
        let provider = SoftwareP256Provider()
        let snapshots = TestSnapshots()
        let availability = TestAvailability()
        let engine = OpenPgpEngine()
        let manager = makeManager(
            engine: engine,
            provider: provider,
            store: .inMemory(),
            snapshots: snapshots,
            availability: { availability.value }
        )
        let model = OpenPgpApplicationModel(engine: engine, secureEnclaveSessions: manager)
        XCTAssertFalse(model.canGenerateSecureEnclave)
        await model.load()
        XCTAssertNil(model.errorMessage)
        XCTAssertTrue(model.canGenerateSecureEnclave)

        availability.set(false)
        try await manager.restore()
        XCTAssertFalse(model.canGenerateSecureEnclave)
        do {
            _ = try await manager.generate(
                userID: "Unavailable Secure Enclave"
            )
            XCTFail("Unavailable hardware must not fall back to software key generation")
        } catch let error as AddresseeError {
            XCTAssertEqual(error, .RemoteKeyUnavailable)
        }
        let count = await provider.storedKeyCount
        XCTAssertEqual(count, 0)
    }

    func testPersistedBindingRestoresIntoNewEngineAndModel() async throws {
        let provider = SoftwareP256Provider()
        let snapshots = TestSnapshots()
        let store = SecureEnclaveBindingStore(directory: directory)
        let firstEngine = OpenPgpEngine()
        let firstManager = makeManager(
            engine: firstEngine,
            provider: provider,
            store: store,
            snapshots: snapshots
        )
        let first = OpenPgpApplicationModel(engine: firstEngine, secureEnclaveSessions: firstManager)
        await first.load()
        let generated = try await firstManager.generate(
            userID: "Restored P-256 <restored-p256@example.invalid>"
        )
        let fingerprint = generated.generated.summary.fingerprint

        let secondEngine = OpenPgpEngine()
        let records = snapshots.records
        try await offMain {
            try secondEngine.restoreStorage(records: records)
        }
        let secondManager = makeManager(
            engine: secondEngine,
            provider: provider,
            store: store,
            snapshots: snapshots
        )
        let second = OpenPgpApplicationModel(engine: secondEngine, secureEnclaveSessions: secondManager)
        await second.load()
        XCTAssertNil(second.errorMessage)
        XCTAssertEqual(second.keys.map(\.fingerprint), [fingerprint])
        XCTAssertEqual(second.secureEnclaveBindings.count, 1)
        XCTAssertEqual(second.secureEnclaveRegistrations.count, 1)
        XCTAssertEqual(second.secureEnclaveAccessControls[fingerprint], .biometryAny)
        XCTAssertEqual(second.privateKeyAccess(fingerprint: fingerprint, operation: .signing), .secureEnclave)

        let at = UInt64(Date().timeIntervalSince1970) + 60
        let signature = try await second.signDetached(
            signingKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            data: Data("restored device binding".utf8),
            format: .binary
        )
        let result = try await second.verifyDetached(
            data: Data("restored device binding".utf8),
            signature: signature.artifact,
            atUnixSeconds: at
        )
        XCTAssertEqual(result.status, .valid)

        try await second.removeKey(fingerprint: fingerprint)
        XCTAssertTrue(second.keys.isEmpty)
        XCTAssertTrue(snapshots.records.isEmpty)
        let count = await provider.storedKeyCount
        XCTAssertEqual(count, 0)
        let saved = try await store.snapshot()
        XCTAssertTrue(saved.bindings.isEmpty)
        XCTAssertNil(saved.pending)
    }

    func testLegacyBindingWithoutAccessControlRetainsDeviceUnlockedPolicy() async throws {
        let provider = SoftwareP256Provider()
        let snapshots = TestSnapshots()
        let store = SecureEnclaveBindingStore(directory: directory)
        let manager = makeManager(
            engine: OpenPgpEngine(),
            provider: provider,
            store: store,
            snapshots: snapshots
        )
        let generated = try await manager.generate(userID: "Legacy binding migration")
        let fingerprint = generated.generated.summary.fingerprint
        let current = try await store.snapshot()
        XCTAssertEqual(current.accessControls[fingerprint], .biometryAny)
        let manifestURL = directory.appendingPathComponent("manifest.json")
        var manifest = try XCTUnwrap(JSONSerialization.jsonObject(
            with: Data(contentsOf: manifestURL)
        ) as? [String: Any])
        var bindings = try XCTUnwrap(manifest["bindings"] as? [[String: Any]])
        XCTAssertEqual(bindings.count, 1)
        bindings[0].removeValue(forKey: "accessControl")
        manifest["bindings"] = bindings
        try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
            .write(to: manifestURL, options: .atomic)

        let restored = try await SecureEnclaveBindingStore(directory: directory).snapshot()
        XCTAssertEqual(restored.bindings, current.bindings)
        XCTAssertEqual(restored.accessControls[fingerprint], .deviceUnlocked)
        XCTAssertNil(restored.pending)
    }

    func testBindingFailureRollsBackCertificateAndBothAllocatedKeys() async throws {
        let provider = SoftwareP256Provider()
        await provider.failNextRegistration()
        let snapshots = TestSnapshots()
        let engine = OpenPgpEngine()
        let store = SecureEnclaveBindingStore(directory: directory)
        let manager = makeManager(
            engine: engine,
            provider: provider,
            store: store,
            snapshots: snapshots
        )

        do {
            _ = try await manager.generate(
                userID: "Rollback P-256"
            )
            XCTFail("Expected provider registration failure")
        } catch {}
        try await assertEmptyAfterRollback(
            engine: engine,
            manager: manager,
            store: store,
            provider: provider,
            snapshots: snapshots
        )
    }

    func testSnapshotFailureAfterCandidateRollsBackEverything() async throws {
        let provider = SoftwareP256Provider()
        let snapshots = TestSnapshots()
        snapshots.failNextSave = true
        let engine = OpenPgpEngine()
        let store = SecureEnclaveBindingStore(directory: directory)
        let manager = makeManager(
            engine: engine,
            provider: provider,
            store: store,
            snapshots: snapshots
        )

        do {
            _ = try await manager.generate(
                userID: "Snapshot rollback P-256"
            )
            XCTFail("Expected snapshot persistence failure")
        } catch {}
        try await assertEmptyAfterRollback(
            engine: engine,
            manager: manager,
            store: store,
            provider: provider,
            snapshots: snapshots
        )
    }

    func testInterruptedDeletionResumesWithOriginalBindingAfterRestart() async throws {
        let provider = SoftwareP256Provider()
        let snapshots = TestSnapshots()
        let store = SecureEnclaveBindingStore(directory: directory)
        let engine = OpenPgpEngine()
        let manager = makeManager(
            engine: engine,
            provider: provider,
            store: store,
            snapshots: snapshots
        )
        let generated = try await manager.generate(
            userID: "Deletion recovery P-256"
        )
        let fingerprint = generated.generated.summary.fingerprint
        await provider.failNextDeletion()
        do {
            try await manager.delete(certificateFingerprint: fingerprint)
            XCTFail("Expected injected deletion failure")
        } catch {}
        XCTAssertNotNil(manager.pendingOperation)

        let restoredEngine = OpenPgpEngine()
        let restored = makeManager(
            engine: restoredEngine,
            provider: provider,
            store: store,
            snapshots: snapshots
        )
        try await restored.restore()
        XCTAssertNil(restored.pendingOperation)
        XCTAssertTrue(restored.bindings.isEmpty)
        XCTAssertTrue(restored.registrations.isEmpty)
        let count = await provider.storedKeyCount
        XCTAssertEqual(count, 0)
        let saved = try await store.snapshot()
        XCTAssertNil(saved.pending)
        XCTAssertTrue(saved.bindings.isEmpty)
    }

    func testMissingDeviceKeyDoesNotRequestSoftwarePassword() async throws {
        let provider = SoftwareP256Provider()
        let snapshots = TestSnapshots()
        let store = SecureEnclaveBindingStore(directory: directory)
        let engine = OpenPgpEngine()
        let manager = makeManager(
            engine: engine,
            provider: provider,
            store: store,
            snapshots: snapshots
        )
        let generated = try await manager.generate(
            userID: "Missing device key P-256"
        )
        let fingerprint = generated.generated.summary.fingerprint
        try await provider.delete(identifier: generated.binding.signing.id, usage: .signing)

        let restoredEngine = OpenPgpEngine()
        let records = snapshots.records
        try await offMain {
            try restoredEngine.restoreStorage(records: records)
        }
        let restoredManager = makeManager(
            engine: restoredEngine,
            provider: provider,
            store: store,
            snapshots: snapshots
        )
        let restored = OpenPgpApplicationModel(
            engine: restoredEngine,
            secureEnclaveSessions: restoredManager
        )
        await restored.load()
        XCTAssertNotNil(restored.errorMessage)
        XCTAssertTrue(restored.secureEnclavePersistentStateAvailable)
        XCTAssertEqual(restored.secureEnclaveBindings.count, 1)
        XCTAssertTrue(restored.secureEnclaveRegistrations.isEmpty)
        XCTAssertEqual(restored.privateKeyAccess(fingerprint: fingerprint, operation: .signing), .unavailable)
        XCTAssertEqual(restored.privateKeyAccess(fingerprint: fingerprint, operation: .decryption), .unavailable)
        XCTAssertFalse(restored.isSoftwarePasswordRequired(fingerprint: fingerprint))
        XCTAssertFalse(restored.canSubmitPrivateKeyOperation(
            fingerprint: fingerprint,
            password: ""
        ))
    }

    private func makeManager(
        engine: OpenPgpEngine,
        provider: SoftwareP256Provider,
        store: SecureEnclaveBindingStore,
        snapshots: TestSnapshots,
        availability: @escaping @Sendable () -> Bool = { true }
    ) -> SecureEnclaveSessionManager {
        SecureEnclaveSessionManager(
            engine: engine,
            lifecycle: SecureEnclaveBridge(provider: provider, availability: availability),
            store: store,
            persist: { try await snapshots.save(engine) }
        )
    }

    private func assertEmptyAfterRollback(
        engine: OpenPgpEngine,
        manager: SecureEnclaveSessionManager,
        store: SecureEnclaveBindingStore,
        provider: SoftwareP256Provider,
        snapshots: TestSnapshots
    ) async throws {
        let keys = try await offMain { try engine.listKeys() }
        XCTAssertTrue(keys.isEmpty)
        let remote = try await offMain { try engine.secureEnclaveRegistrations() }
        XCTAssertTrue(remote.isEmpty)
        XCTAssertNil(manager.pendingOperation)
        XCTAssertTrue(manager.bindings.isEmpty)
        XCTAssertTrue(snapshots.records.isEmpty)
        let count = await provider.storedKeyCount
        XCTAssertEqual(count, 0)
        let saved = try await store.snapshot()
        XCTAssertNil(saved.pending)
        XCTAssertTrue(saved.bindings.isEmpty)
    }

    private func offMain<Value: Sendable>(
        _ operation: @escaping @Sendable () throws -> Value
    ) async throws -> Value {
        try await Task.detached(priority: .userInitiated, operation: operation).value
    }
}

private final class TestAvailability: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = true

    var value: Bool {
        lock.withLock { stored }
    }

    func set(_ value: Bool) {
        lock.withLock { stored = value }
    }
}

@MainActor
private final class TestSnapshots {
    var records: [StorageRecordFfi] = []
    var failNextSave = false

    func save(_ engine: OpenPgpEngine) async throws {
        if failNextSave {
            failNextSave = false
            throw TestFailure.injected
        }
        records = try await Task.detached(priority: .userInitiated) {
            try engine.storageSnapshot()
        }.value
    }
}

private enum TestFailure: Error {
    case injected
}

private actor SoftwareP256Provider: SecureEnclaveKeyProviding {
    private enum Entry {
        case signing(P256.Signing.PrivateKey)
        case keyAgreement(P256.KeyAgreement.PrivateKey)

        var usage: SecureEnclaveKeyUsage {
            switch self {
            case .signing: .signing
            case .keyAgreement: .keyAgreement
            }
        }

        var publicKeyX963: Data {
            switch self {
            case .signing(let key): key.publicKey.x963Representation
            case .keyAgreement(let key): key.publicKey.x963Representation
            }
        }
    }

    private var entries: [String: Entry] = [:]
    private var fingerprints: [String: String] = [:]
    private var shouldFailRegistration = false
    private var shouldFailDeletion = false
    private(set) var lastDigest: Data?
    private(set) var accessControls: [SecureEnclaveKeyUsage: SecureEnclaveAccessControl] = [:]

    var storedKeyCount: Int { entries.count }

    func makeIdentifier(for usage: SecureEnclaveKeyUsage) -> String {
        "app.addressee.tests.software-p256.\(usage.rawValue).\(UUID().uuidString)"
    }

    func generate(
        usage: SecureEnclaveKeyUsage,
        accessControl: SecureEnclaveAccessControl,
        identifier: String
    ) throws -> ProviderKeyReference {
        guard entries[identifier] == nil else { throw SecureEnclaveError.invalidReference }
        accessControls[usage] = accessControl
        let entry: Entry = switch usage {
        case .signing: .signing(P256.Signing.PrivateKey())
        case .keyAgreement: .keyAgreement(P256.KeyAgreement.PrivateKey())
        }
        entries[identifier] = entry
        return reference(identifier: identifier, usage: usage)
    }

    func register(
        _ reference: SecureEnclaveKeyReference,
        fingerprint: String?
    ) throws -> ProviderKeyReference {
        guard let entry = entries[reference.id],
              entry.usage == reference.usage,
              entry.publicKeyX963 == reference.publicKeyX963 else {
            throw SecureEnclaveError.publicKeyMismatch
        }
        if shouldFailRegistration {
            shouldFailRegistration = false
            throw SecureEnclaveError.unavailable
        }
        fingerprints[reference.id] = fingerprint
        return self.reference(identifier: reference.id, usage: reference.usage, fingerprint: fingerprint)
    }

    func publicKey(for reference: ProviderKeyReference) throws -> Data {
        try resolve(reference).publicKeyX963
    }

    func sign(_ request: SignatureRequest, with reference: ProviderKeyReference) throws -> Data {
        guard case .signing(let key) = try resolve(reference),
              request.hashAlgorithm == .sha256,
              request.digest.count == 32 else {
            throw SecureEnclaveError.invalidUsage
        }
        lastDigest = request.digest
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(
            key.x963Representation as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            if let error { throw error.takeRetainedValue() }
            throw TestFailure.injected
        }
        let algorithm = SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw TestFailure.injected
        }
        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            request.digest as CFData,
            &error
        ) else {
            if let error { throw error.takeRetainedValue() }
            throw TestFailure.injected
        }
        return signature as Data
    }

    func sharedSecret(
        _ request: KeyAgreementRequest,
        with reference: ProviderKeyReference
    ) throws -> SecretBytes {
        guard case .keyAgreement(let key) = try resolve(reference),
              request.algorithm == .nistP256ECDH else {
            throw SecureEnclaveError.invalidUsage
        }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: request.peerPublicKey)
        let secret = try key.sharedSecretFromKeyAgreement(with: peer)
        return SecretBytes(secret.withUnsafeBytes { Data($0) })
    }

    func delete(_ reference: ProviderKeyReference) throws {
        let entry = try resolve(reference)
        if shouldFailDeletion, entry.usage == .keyAgreement {
            shouldFailDeletion = false
            throw SecureEnclaveError.unavailable
        }
        entries.removeValue(forKey: reference.id)
        fingerprints.removeValue(forKey: reference.id)
    }

    func delete(identifier: String, usage: SecureEnclaveKeyUsage) throws {
        if let entry = entries[identifier], entry.usage != usage {
            throw SecureEnclaveError.invalidUsage
        }
        entries.removeValue(forKey: identifier)
        fingerprints.removeValue(forKey: identifier)
    }

    func failNextRegistration() {
        shouldFailRegistration = true
    }

    func failNextDeletion() {
        shouldFailDeletion = true
    }

    private func resolve(_ reference: ProviderKeyReference) throws -> Entry {
        guard reference.backend == .secureEnclave,
              reference.exportPolicy == .hardwareNonExportable,
              reference.fingerprint == fingerprints[reference.id],
              let entry = entries[reference.id] else {
            throw SecureEnclaveError.keyNotFound
        }
        switch (entry.usage, reference.algorithm) {
        case (.signing, .nistP256ECDSA), (.keyAgreement, .nistP256ECDH):
            return entry
        default:
            throw SecureEnclaveError.invalidUsage
        }
    }

    private func reference(
        identifier: String,
        usage: SecureEnclaveKeyUsage,
        fingerprint: String? = nil
    ) -> ProviderKeyReference {
        ProviderKeyReference(
            id: identifier,
            fingerprint: fingerprint,
            algorithm: usage == .signing ? .nistP256ECDSA : .nistP256ECDH,
            backend: .secureEnclave,
            exportPolicy: .hardwareNonExportable
        )
    }
}
