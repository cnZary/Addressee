import Foundation
import OpenPGPAppleSecureEnclave
import Testing
@testable import OpenPGPKeyProvider

@Test func invalidFingerprintIsRejectedBeforeSecureEnclaveAccess() async {
    let provider = SecureEnclaveProvider()
    let reference = SecureEnclaveKeyReference(
        id: "not-a-registered-key",
        usage: .signing,
        publicKeyX963: Data([0x04])
    )
    do {
        _ = try await provider.register(reference, fingerprint: "not-a-fingerprint")
        Issue.record("Expected fingerprint rejection")
    } catch let error as PrivateKeyProviderError {
        #expect(error == .invalidReference)
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func unregisteredSecureEnclaveReferenceIsNotUsedImplicitly() async {
    let provider = SecureEnclaveProvider()
    let reference = ProviderKeyReference(
        id: "app.addressee.secure-enclave.signing.\(UUID().uuidString)",
        algorithm: .nistP256ECDSA,
        backend: .secureEnclave,
        exportPolicy: .hardwareNonExportable
    )
    do {
        _ = try await provider.publicKey(for: reference)
        Issue.record("Expected explicit-registration requirement")
    } catch let error as PrivateKeyProviderError {
        #expect(error == .invalidReference)
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}
