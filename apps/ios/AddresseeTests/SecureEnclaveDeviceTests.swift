import CryptoKit
import Foundation
import OpenPGPAppleSecureEnclave
import OpenPGPKeyProvider
import XCTest
@testable import Addressee

@MainActor
final class SecureEnclaveDeviceTests: XCTestCase {
    private var provider: SecureEnclaveKeyProvider!

    override func setUp() async throws {
        let environment = ProcessInfo.processInfo.environment
        let arguments = ProcessInfo.processInfo.arguments
        let authorized = environment["ADDRESSEE_SE_HARDWARE_TESTS"] == "1"
            || arguments.contains("--secure-enclave-hardware-tests")
        guard authorized else {
            throw XCTSkip("Physical Secure Enclave tests require explicit opt-in")
        }
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave is unavailable on this host")
        }
        provider = SecureEnclaveKeyProvider(
            namespace: "app.addressee.device-tests.\(UUID().uuidString)"
        )
    }

    func testSHA256DigestSignatureMatchesCryptoKit() async throws {
        let reference = try await provider.generate(usage: .signing)
        addTeardownBlock { [provider] in
            try await provider?.delete(reference)
        }
        let message = Data("Secure Enclave OpenPGP digest validation".utf8)
        let signature = try await provider.signSHA256Digest(
            Data(SHA256.hash(data: message)),
            with: reference
        )
        let publicKey = try P256.Signing.PublicKey(x963Representation: reference.publicKeyX963)
        let parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
        XCTAssertTrue(publicKey.isValidSignature(parsed, for: message))
        XCTAssertFalse(publicKey.isValidSignature(parsed, for: Data("Tampered message".utf8)))
    }

    func testECDHMatchesCryptoKitSoftwarePeer() async throws {
        let reference = try await provider.generate(usage: .keyAgreement)
        addTeardownBlock { [provider] in
            try await provider?.delete(reference)
        }
        let peer = P256.KeyAgreement.PrivateKey()
        let hardwareSecret = try await provider.sharedSecret(
            with: peer.publicKey.x963Representation,
            reference: reference
        )
        let hardwarePublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: reference.publicKeyX963
        )
        let softwareSecret = try peer.sharedSecretFromKeyAgreement(with: hardwarePublicKey)
        let hardwareBytes = hardwareSecret.withUnsafeBytes { Data($0) }
        let softwareBytes = softwareSecret.withUnsafeBytes { Data($0) }
        XCTAssertEqual(hardwareBytes.count, 32)
        XCTAssertEqual(hardwareBytes, softwareBytes)
    }

    func testExplicitIdentifiersRestoreAndDeleteAcrossProviders() async throws {
        let namespace = "app.addressee.device-tests.lifecycle.\(UUID().uuidString)"
        let first = SecureEnclaveKeyProvider(namespace: namespace)
        let second = SecureEnclaveKeyProvider(namespace: namespace)
        let identifier = await first.identifier(for: .signing)
        let generated = try await first.generate(
            usage: .signing,
            accessControl: .deviceUnlocked,
            identifier: identifier
        )
        addTeardownBlock {
            try? await second.delete(identifier: identifier, usage: .signing)
        }
        XCTAssertEqual(generated.id, identifier)
        let restoredPublicKey = try await second.publicKey(for: generated)
        XCTAssertEqual(restoredPublicKey, generated.publicKeyX963)
        let signature = try await second.signSHA256Digest(
            Data(SHA256.hash(data: Data("Restored Secure Enclave reference".utf8))),
            with: generated
        )
        let publicKey = try P256.Signing.PublicKey(x963Representation: generated.publicKeyX963)
        XCTAssertTrue(publicKey.isValidSignature(
            try P256.Signing.ECDSASignature(derRepresentation: signature),
            for: Data("Restored Secure Enclave reference".utf8)
        ))
        try await second.delete(identifier: identifier, usage: .signing)
        do {
            _ = try await second.publicKey(for: generated)
            XCTFail("The explicitly identified key must be deleted")
        } catch let error as SecureEnclaveError {
            XCTAssertEqual(error, .keyNotFound)
        }
    }

    func testBiometricPrivateKeyOperations() async throws {
        let signing = try await provider.generate(
            usage: .signing,
            accessControl: .biometryAny
        )
        addTeardownBlock { [provider] in
            try await provider?.delete(signing)
        }
        let message = Data("Biometric Secure Enclave authorization".utf8)
        let signature = try await provider.signSHA256Digest(
            Data(SHA256.hash(data: message)),
            with: signing
        )
        let publicKey = try P256.Signing.PublicKey(x963Representation: signing.publicKeyX963)
        XCTAssertTrue(publicKey.isValidSignature(
            try P256.Signing.ECDSASignature(derRepresentation: signature),
            for: message
        ))

        let encryption = try await provider.generate(
            usage: .keyAgreement,
            accessControl: .biometryAny
        )
        addTeardownBlock { [provider] in
            try await provider?.delete(encryption)
        }
        let peer = P256.KeyAgreement.PrivateKey()
        let secret = try await provider.sharedSecret(
            with: peer.publicKey.x963Representation,
            reference: encryption
        )
        let encryptionPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: encryption.publicKeyX963
        )
        XCTAssertEqual(
            secret.withUnsafeBytes { Data($0) },
            try peer.sharedSecretFromKeyAgreement(with: encryptionPublicKey).withUnsafeBytes { Data($0) }
        )
    }

    func testBiometricCancellationDoesNotFallBackToSoftware() async throws {
        guard ProcessInfo.processInfo.arguments.contains(
            "--secure-enclave-biometric-cancel-tests"
        ) else {
            throw XCTSkip("Biometric cancellation requires an explicit interactive test run")
        }
        let bridge = SecureEnclaveBridge(
            provider: SecureEnclaveProvider(engine: provider)
        )
        let identifier = try await bridge.nextIdentifier(for: .signing)
        let reference = try await bridge.generateReference(usage: .signing, identifier: identifier)
        addTeardownBlock { [provider] in
            try await provider?.delete(identifier: reference.id, usage: .signing)
        }
        do {
            _ = try await offMain {
                try bridge.signSha256(reference: reference, digest: Data(repeating: 1, count: 32))
            }
            XCTFail("Cancel biometric authorization instead of approving it")
        } catch let error as SecureEnclaveErrorFfi {
            XCTAssertEqual(error, .Cancelled)
        }
    }

    func testNativeOpenPGPSigningAndDecryptionUseSecureEnclaveSubkeys() async throws {
        let peerFixture = try peerFixture()
        let preparesPeer = ProcessInfo.processInfo.arguments.contains("--prepare-gpg-peer")
        if preparesPeer || peerFixture != nil {
            provider = SecureEnclaveKeyProvider(namespace: "app.addressee.device-tests.gpg-peer-v1")
        }
        let provider = try XCTUnwrap(provider)
        let directory: URL
        if preparesPeer || peerFixture != nil {
            let base = try XCTUnwrap(FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first)
            directory = base.appendingPathComponent(
                "AddresseeTests/SecureEnclaveGPGPeer",
                isDirectory: true
            )
        } else {
            directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("SecureEnclaveDeviceTests-\(UUID().uuidString)", isDirectory: true)
        }
        let store = SecureEnclaveBindingStore(directory: directory)
        let preparationMarker = directory.appendingPathComponent("gpg-peer-preparation.json")
        addTeardownBlock { [provider] in
            if preparesPeer, FileManager.default.fileExists(atPath: preparationMarker.path) {
                return
            }
            let snapshot = try? await store.snapshot()
            var references = (snapshot?.bindings ?? []).flatMap { [$0.signing, $0.encryption] }
            if let pending = snapshot?.pending {
                switch pending {
                case .generation(let journal):
                    if let candidate = journal.candidate {
                        references.append(candidate.signing.ffi())
                        references.append(candidate.encryption.ffi())
                    } else {
                        references.append(SecureEnclaveReferenceFfi(
                            id: journal.signingIdentifier,
                            usage: .signing,
                            publicKeyX963: Data()
                        ))
                        references.append(SecureEnclaveReferenceFfi(
                            id: journal.encryptionIdentifier,
                            usage: .keyAgreement,
                            publicKeyX963: Data()
                        ))
                    }
                case .deletion(let journal):
                    references.append(journal.binding.signing.ffi())
                    references.append(journal.binding.encryption.ffi())
                }
            }
            for reference in references {
                try? await provider.delete(
                    identifier: reference.id,
                    usage: reference.usage == .signing ? .signing : .keyAgreement
                )
            }
            try? FileManager.default.removeItem(at: directory)
        }

        let engine = OpenPgpEngine()
        let manager = SecureEnclaveSessionManager(
            engine: engine,
            lifecycle: SecureEnclaveBridge(provider: SecureEnclaveProvider(engine: provider)),
            store: store,
            persist: {}
        )
        let model = OpenPgpApplicationModel(engine: engine, secureEnclaveSessions: manager)
        await model.load()
        if preparesPeer || peerFixture != nil {
            guard model.errorMessage == nil,
                  model.secureEnclavePendingOperation == nil,
                  model.secureEnclaveRegistrations.count <= 1 else {
                throw PeerFixtureError.inconsistentState
            }
        }
        let binding: SecureEnclaveBindingFfi
        let fingerprint: String
        if let existing = model.secureEnclaveRegistrations.first {
            binding = existing
            fingerprint = existing.certificateFingerprint
        } else if peerFixture != nil {
            throw PeerFixtureError.missingBinding
        } else {
            let result = try await manager.generate(
                userID: "Secure Enclave Device <se-device@example.invalid>"
            )
            binding = result.binding
            fingerprint = result.generated.summary.fingerprint
        }
        XCTAssertEqual(model.privateKeyAccess(fingerprint: fingerprint, operation: .signing), .secureEnclave)
        XCTAssertEqual(model.privateKeyAccess(fingerprint: fingerprint, operation: .decryption), .secureEnclave)
        let at = UInt64(Date().timeIntervalSince1970) + 60

        let signature = try await model.signDetached(
            signingKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            data: Data("Physical Secure Enclave OpenPGP".utf8),
            format: .binary
        )
        let verification = try await model.verifyDetached(
            data: Data("Physical Secure Enclave OpenPGP".utf8),
            signature: signature.artifact,
            atUnixSeconds: at
        )
        XCTAssertEqual(verification.status, .valid)
        let attached = try await model.signAttached(
            signingKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            data: Data("Physical Secure Enclave OpenPGP".utf8),
            format: .armored
        )
        let attachedVerification = try await model.verifyAttached(input: attached.artifact, atUnixSeconds: at)
        XCTAssertEqual(attachedVerification.outcome.status, .valid)
        XCTAssertEqual(attachedVerification.plaintext, Data("Physical Secure Enclave OpenPGP".utf8))
        let cleartextInput = "Physical Secure Enclave cleartext\r\nSecond line\r\n"
        let cleartext = try await model.signCleartext(
            signingKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            text: cleartextInput
        )
        let cleartextVerification = try await model.verifyCleartext(input: cleartext.artifact, atUnixSeconds: at)
        XCTAssertEqual(cleartextVerification.outcome.status, .valid)
        XCTAssertEqual(cleartextVerification.text, cleartextInput)
        for (name, artifact) in [
            ("payload.bin", Data("Physical Secure Enclave OpenPGP".utf8)),
            ("public.pgp", binding.publicCertificate),
            ("detached.sig", signature.artifact),
            ("attached.asc", attached.artifact),
            ("cleartext.asc", cleartext.artifact),
        ] {
            let attachment = XCTAttachment(data: artifact, uniformTypeIdentifier: "public.data")
            attachment.name = name
            attachment.lifetime = .keepAlways
            add(attachment)
        }
        let encrypted = try await model.encryptText(
            recipients: [fingerprint],
            atUnixSeconds: at,
            config: .seipdV1(cipher: .aes256),
            text: "Physical Secure Enclave ECDH",
            format: .binary
        )
        let decrypted = try await model.decryptText(
            decryptionKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            input: encrypted
        )
        XCTAssertEqual(decrypted.report.status, .unsigned)
        XCTAssertEqual(decrypted.text, "Physical Secure Enclave ECDH")
        let combined = try await model.signAndEncryptText(
            request: SignEncryptTextRequestFfi(
                signingKey: fingerprint,
                password: "",
                recipients: [fingerprint],
                atUnixSeconds: at,
                config: .seipdV1(cipher: .aes256),
                text: "Physical Secure Enclave combined operation",
                format: .binary
            )
        )
        let combinedResult = try await model.decryptText(
            decryptionKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            input: combined.artifact
        )
        XCTAssertEqual(combinedResult.report.status, .valid)
        XCTAssertEqual(combinedResult.text, "Physical Secure Enclave combined operation")
        if let fixture = peerFixture {
            XCTAssertEqual(fixture.recipientCertificateFingerprint, fingerprint)
            XCTAssertEqual(
                fixture.encryptionComponentFingerprint,
                binding.encryptionComponentFingerprint
            )
            let peer = try await model.importPublic(fixture.peerPublicCertificate)
            XCTAssertEqual(peer.summary.fingerprint, fixture.signerFingerprint)
            let peerUnsigned = try await model.decrypt(
                decryptionKey: fingerprint,
                password: "",
                atUnixSeconds: at,
                input: fixture.unsignedMessage
            )
            XCTAssertEqual(peerUnsigned.report.status, .unsigned)
            XCTAssertEqual(peerUnsigned.plaintext, fixture.unsignedPlaintext)
            let peerCombined = try await model.decrypt(
                decryptionKey: fingerprint,
                password: "",
                atUnixSeconds: at,
                input: fixture.combinedMessage
            )
            let peerDiagnostics: [String: Any] = [
                "evaluationTime": at,
                "status": String(describing: peerCombined.report.status),
                "signatures": peerCombined.report.signatures.map { signature in
                    [
                        "status": String(describing: signature.status),
                        "cryptographicallyValid": String(describing: signature.cryptographicallyValid),
                        "createdAt": String(describing: signature.createdAt),
                        "hashAlgorithm": String(describing: signature.hashAlgorithm),
                        "keyValidity": String(describing: signature.keyValidity),
                        "certificateFingerprint": String(describing: signature.certificateFingerprint),
                    ]
                },
            ]
            let diagnosticAttachment = XCTAttachment(
                data: try JSONSerialization.data(withJSONObject: peerDiagnostics),
                uniformTypeIdentifier: "public.json"
            )
            diagnosticAttachment.name = "peer-verification-diagnostics.json"
            diagnosticAttachment.lifetime = .keepAlways
            add(diagnosticAttachment)
            XCTAssertEqual(peerCombined.report.status, .valid)
            XCTAssertEqual(peerCombined.plaintext, fixture.combinedPlaintext)
            XCTAssertEqual(peerCombined.report.signatures.count, 1)
            let peerSignature = try XCTUnwrap(peerCombined.report.signatures.first)
            XCTAssertEqual(peerSignature.status, .valid)
            XCTAssertEqual(peerSignature.cryptographicallyValid, true)
            XCTAssertEqual(peerSignature.certificateFingerprint, fixture.signerFingerprint)
            let peerResult: [String: Any] = [
                "version": 1,
                "recipientCertificateFingerprint": fingerprint,
                "signerFingerprint": fixture.signerFingerprint,
                "unsignedDecryption": "passed",
                "combinedDecryptionAndVerification": "passed",
            ]
            for (name, artifact) in [
                ("gpg-encrypted.pgp", fixture.unsignedMessage),
                ("gpg-signed-encrypted.pgp", fixture.combinedMessage),
                ("gpg-peer-result.json", try JSONSerialization.data(withJSONObject: peerResult)),
            ] {
                let attachment = XCTAttachment(data: artifact, uniformTypeIdentifier: "public.data")
                attachment.name = name
                attachment.lifetime = .keepAlways
                add(attachment)
            }
        }

        let records = try await offMain { try engine.storageSnapshot() }
        let snapshotDiagnostics = records.map { record in
            [
                "fingerprint": record.fingerprint,
                "hasProtectedSecret": record.protectedSecret != nil,
                "exportPolicy": String(describing: record.exportPolicy),
            ]
        }
        XCTAssertEqual(
            records.first { $0.fingerprint == fingerprint }?.protectedSecret != nil,
            peerFixture == nil,
            String(reflecting: snapshotDiagnostics)
        )
        let secondEngine = OpenPgpEngine()
        try await offMain { try secondEngine.restoreStorage(records: records) }
        let restoredMetadata = try await offMain { try secondEngine.listKeys() }
        let expectedStorage: KeyStorageFfi = peerFixture == nil ? .softwareSecret : .publicOnly
        XCTAssertEqual(
            restoredMetadata.first { $0.fingerprint == fingerprint }?.storage,
            expectedStorage,
            String(reflecting: (snapshotDiagnostics, restoredMetadata))
        )
        let restoredManager = SecureEnclaveSessionManager(
            engine: secondEngine,
            lifecycle: SecureEnclaveBridge(provider: SecureEnclaveProvider(engine: provider)),
            store: store,
            persist: {}
        )
        let restored = OpenPgpApplicationModel(engine: secondEngine, secureEnclaveSessions: restoredManager)
        await restored.load()
        XCTAssertNil(restored.errorMessage, String(reflecting: try? secondEngine.listKeys()))
        XCTAssertEqual(restored.secureEnclaveRegistrations.count, 1)
        let restoredSignature = try await restored.signDetached(
            signingKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            data: Data("Restored physical Secure Enclave OpenPGP".utf8),
            format: .binary
        )
        XCTAssertEqual(restoredSignature.metadata.signerFingerprint, binding.signingComponentFingerprint)
        let restoredDecryption = try await restored.decryptText(
            decryptionKey: fingerprint,
            password: "",
            atUnixSeconds: at,
            input: encrypted
        )
        XCTAssertEqual(restoredDecryption.text, "Physical Secure Enclave ECDH")

        let saved = try await store.snapshot()
        if preparesPeer {
            XCTAssertEqual(saved.bindings.map(\.certificateFingerprint), [fingerprint])
            XCTAssertNil(saved.pending)
            let preparation: [String: Any] = [
                "schemaVersion": 1,
                "certificateFingerprint": fingerprint,
                "retainedForGnuPGPeer": true,
                "privateKeyMaterialExported": false,
            ]
            let preparationData = try JSONSerialization.data(withJSONObject: preparation)
            let attachment = XCTAttachment(data: preparationData, uniformTypeIdentifier: "public.json")
            attachment.name = "gpg-peer-preparation.json"
            attachment.lifetime = .keepAlways
            add(attachment)
            try preparationData.write(to: preparationMarker, options: .atomic)
        } else {
            try await manager.delete(certificateFingerprint: fingerprint)
            XCTAssertFalse(model.keys.contains(where: { $0.fingerprint == fingerprint }))
            XCTAssertEqual(model.keys.count, peerFixture == nil ? 0 : 1)
            let afterDeletion = try await store.snapshot()
            XCTAssertTrue(afterDeletion.bindings.isEmpty)
            XCTAssertNil(afterDeletion.pending)
        }
    }

    private struct PeerFixture: Decodable {
        let recipientCertificateFingerprint: String
        let encryptionComponentFingerprint: String
        let signerFingerprint: String
        let peerPublicCertificate: Data
        let unsignedMessage: Data
        let unsignedPlaintext: Data
        let combinedMessage: Data
        let combinedPlaintext: Data
    }

    private enum PeerFixtureError: Error {
        case missing
        case oversized
        case missingBinding
        case inconsistentState
    }

    private func peerFixture() throws -> PeerFixture? {
        let process = ProcessInfo.processInfo
        guard let encoded = process.environment["ADDRESSEE_SE_GPG_PEER_FIXTURE"] else {
            if process.arguments.contains("--require-gpg-peer-fixture") {
                throw PeerFixtureError.missing
            }
            return nil
        }
        guard encoded.count <= 1_000_000 else { throw PeerFixtureError.oversized }
        let input = try XCTUnwrap(Data(base64Encoded: encoded))
        return try JSONDecoder().decode(PeerFixture.self, from: input)
    }

    private func offMain<Value: Sendable>(
        _ operation: @escaping @Sendable () throws -> Value
    ) async throws -> Value {
        try await Task.detached(priority: .userInitiated, operation: operation).value
    }

    func testTamperedPublicReferenceIsRejected() async throws {
        let reference = try await provider.generate(usage: .signing)
        addTeardownBlock { [provider] in
            try await provider?.delete(reference)
        }
        var invalidBytes = reference.publicKeyX963
        invalidBytes[0] = 0
        let malformed = SecureEnclaveKeyReference(
            id: reference.id,
            usage: reference.usage,
            publicKeyX963: invalidBytes
        )
        do {
            _ = try await provider.signSHA256Digest(Data(repeating: 0, count: 32), with: malformed)
            XCTFail("Expected malformed public-key encoding rejection")
        } catch let error as SecureEnclaveError {
            XCTAssertEqual(error, .invalidPublicKey)
        }

        let other = try await provider.generate(usage: .signing)
        addTeardownBlock { [provider] in
            try await provider?.delete(other)
        }
        let mismatched = SecureEnclaveKeyReference(
            id: reference.id,
            usage: reference.usage,
            publicKeyX963: other.publicKeyX963
        )
        do {
            _ = try await provider.signSHA256Digest(Data(repeating: 0, count: 32), with: mismatched)
            XCTFail("Expected public-key binding rejection")
        } catch let error as SecureEnclaveError {
            XCTAssertEqual(error, .publicKeyMismatch)
        }
    }
}
