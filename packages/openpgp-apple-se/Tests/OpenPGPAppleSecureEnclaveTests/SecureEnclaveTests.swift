import CryptoKit
import Foundation
import Security
import XCTest
@testable import OpenPGPAppleSecureEnclave

@MainActor
final class SecureEnclaveValidationTests: XCTestCase {
    func testPublicKeyEncodingValidation() {
        XCTAssertThrowsError(try P256Encoding.validatePublicKey(Data(repeating: 0, count: 64)))
        XCTAssertThrowsError(try P256Encoding.validatePublicKey(Data(repeating: 0, count: 65)))
        var invalid = Data(repeating: 1, count: 65)
        invalid[0] = 0x04
        XCTAssertThrowsError(try P256Encoding.validatePublicKey(invalid))
        let valid = P256.Signing.PrivateKey().publicKey.x963Representation
        XCTAssertNoThrow(try P256Encoding.validatePublicKey(valid))
    }

    func testReferenceFromAnotherNamespaceIsRejected() async {
        let provider = SecureEnclaveKeyProvider(namespace: "app.addressee.tests.current")
        let reference = SecureEnclaveKeyReference(
            id: "app.addressee.tests.other.signing.\(UUID().uuidString)",
            usage: .signing,
            publicKeyX963: Data()
        )
        do {
            _ = try await provider.publicKey(for: reference)
            XCTFail("Expected namespace rejection")
        } catch let error as SecureEnclaveError {
            XCTAssertEqual(error, .invalidReference)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testBiometricPoliciesDoNotAllowPasscodeFallback() {
        for (policy, biometricFlag) in [
            (SecureEnclaveAccessControl.biometryAny, SecAccessControlCreateFlags.biometryAny),
            (.biometryCurrentSet, .biometryCurrentSet),
        ] {
            let flags = SecureEnclaveKeyProvider.accessControlFlags(for: policy)
            XCTAssertEqual(flags, [.privateKeyUsage, biometricFlag])
            XCTAssertFalse(flags.contains(.userPresence))
            XCTAssertFalse(flags.contains(.devicePasscode))
        }
    }

    func testUserPresenceIsExplicitlyBiometryOrPasscode() {
        XCTAssertEqual(
            SecureEnclaveKeyProvider.accessControlFlags(for: .userPresence),
            [.privateKeyUsage, .userPresence]
        )
        XCTAssertEqual(
            SecureEnclaveKeyProvider.accessControlFlags(for: .deviceUnlocked),
            [.privateKeyUsage]
        )
    }

    func testReferenceWithExtraComponentsIsRejectedBeforeKeychainAccess() async {
        let provider = SecureEnclaveKeyProvider(namespace: "app.addressee.tests.current")
        let reference = SecureEnclaveKeyReference(
            id: "app.addressee.tests.current.signing.extra.\(UUID().uuidString)",
            usage: .signing,
            publicKeyX963: Data()
        )
        do {
            _ = try await provider.publicKey(for: reference)
            XCTFail("Expected strict reference rejection")
        } catch let error as SecureEnclaveError {
            XCTAssertEqual(error, .invalidReference)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testEmptyPublicKeyCannotBypassReferenceBinding() async {
        let provider = SecureEnclaveKeyProvider(namespace: "app.addressee.tests.current")
        let reference = SecureEnclaveKeyReference(
            id: "app.addressee.tests.current.signing.\(UUID().uuidString)",
            usage: .signing,
            publicKeyX963: Data()
        )
        do {
            _ = try await provider.publicKey(for: reference)
            XCTFail("Expected an empty public key to be rejected")
        } catch let error as SecureEnclaveError {
            XCTAssertEqual(error, .invalidPublicKey)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
        do {
            _ = try await provider.signSHA256Digest(Data(repeating: 0, count: 32), with: reference)
            XCTFail("Expected an empty public key to be rejected")
        } catch let error as SecureEnclaveError {
            XCTAssertEqual(error, .invalidPublicKey)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}

@MainActor
final class SecureEnclaveHardwareTests: XCTestCase {
    private var provider: SecureEnclaveKeyProvider!

    override func setUp() async throws {
        guard ProcessInfo.processInfo.environment["ADDRESSEE_SE_HARDWARE_TESTS"] == "1" else {
            throw XCTSkip("Physical Secure Enclave tests are opt-in")
        }
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave is unavailable on this host")
        }
        provider = SecureEnclaveKeyProvider(
            namespace: "app.addressee.tests.\(UUID().uuidString)"
        )
    }

    func testSHA256DigestSignatureUsesRawDigest() async throws {
        let reference = try await provider.generate(usage: .signing)
        addTeardownBlock { [provider] in
            try await provider?.delete(reference)
        }

        let message = Data("OpenPGP digest test".utf8)
        let digest = Data(SHA256.hash(data: message))
        let signature = try await provider.signSHA256Digest(digest, with: reference)
        let publicKey = try P256.Signing.PublicKey(x963Representation: reference.publicKeyX963)
        let parsedSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        XCTAssertTrue(publicKey.isValidSignature(parsedSignature, for: message))
        XCTAssertFalse(publicKey.isValidSignature(parsedSignature, for: Data("Different message".utf8)))

        do {
            _ = try await provider.signSHA256Digest(Data(repeating: 0, count: 31), with: reference)
            XCTFail("Expected digest length rejection")
        } catch let error as SecureEnclaveError {
            XCTAssertEqual(error, .invalidDigestLength)
        }
    }

    func testAgreementProducesMatchingRawSecrets() async throws {
        let first = try await provider.generate(usage: .keyAgreement)
        addTeardownBlock { [provider] in
            try await provider?.delete(first)
        }
        let second = try await provider.generate(usage: .keyAgreement)
        addTeardownBlock { [provider] in
            try await provider?.delete(second)
        }

        let firstSecret = try await provider.sharedSecret(
            with: second.publicKeyX963,
            reference: first
        )
        let secondSecret = try await provider.sharedSecret(
            with: first.publicKeyX963,
            reference: second
        )
        let firstBytes = firstSecret.withUnsafeBytes { Data($0) }
        let secondBytes = secondSecret.withUnsafeBytes { Data($0) }
        XCTAssertEqual(firstBytes.count, 32)
        XCTAssertEqual(firstBytes, secondBytes)
    }

    func testBiometricPrivateKeyOperations() async throws {
        let signing = try await provider.generate(
            usage: .signing,
            accessControl: .biometryAny
        )
        addTeardownBlock { [provider] in
            try await provider?.delete(signing)
        }
        let message = Data("Package biometric Secure Enclave authorization".utf8)
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

    func testBiometricCancellationIsAnError() async throws {
        guard ProcessInfo.processInfo.arguments.contains(
            "--secure-enclave-biometric-cancel-tests"
        ) else {
            throw XCTSkip("Biometric cancellation requires an explicit interactive test run")
        }
        let reference = try await provider.generate(
            usage: .signing,
            accessControl: .biometryAny
        )
        addTeardownBlock { [provider] in
            try await provider?.delete(reference)
        }
        do {
            _ = try await provider.signSHA256Digest(
                Data(repeating: 1, count: 32),
                with: reference
            )
            XCTFail("Cancel biometric authorization instead of approving it")
        } catch SecureEnclaveError.coreFoundation(_, let domain, let code) {
            XCTAssertEqual(domain, NSOSStatusErrorDomain)
            XCTAssertEqual(code, Int(errSecUserCanceled))
        }
    }

    func testTamperedPublicReferenceIsRejectedBeforePrivateOperations() async throws {
        let reference = try await provider.generate(usage: .signing)
        addTeardownBlock { [provider] in
            try await provider?.delete(reference)
        }
        var alteredPublicKey = reference.publicKeyX963
        alteredPublicKey[1] ^= 0x01
        let altered = SecureEnclaveKeyReference(
            id: reference.id,
            usage: .signing,
            publicKeyX963: alteredPublicKey
        )

        do {
            _ = try await provider.publicKey(for: altered)
            XCTFail("Expected public-key binding rejection")
        } catch let error as SecureEnclaveError {
            XCTAssertEqual(error, .publicKeyMismatch)
        }
        do {
            _ = try await provider.signSHA256Digest(
                Data(repeating: 0, count: 32),
                with: altered
            )
            XCTFail("Expected signing binding rejection")
        } catch let error as SecureEnclaveError {
            XCTAssertEqual(error, .publicKeyMismatch)
        }
    }
}
