import Foundation
import Testing
@testable import OpenPGPKeyProvider

private actor RecordingProvider: PrivateKeyProvider {
    let backend = KeyBackend.software

    func publicKey(for reference: ProviderKeyReference) async throws -> Data {
        Data([0x04, 0x01])
    }

    func sign(_ request: SignatureRequest, with reference: ProviderKeyReference) async throws -> Data {
        Data(request.digest.reversed())
    }

    func sharedSecret(_ request: KeyAgreementRequest, with reference: ProviderKeyReference) async throws -> SecretBytes {
        SecretBytes(Data([1, 2, 3]))
    }

    func exportPrivateKey(for reference: ProviderKeyReference) async throws -> Data {
        Data([0xAA])
    }
}

private struct EmptyProvider: PrivateKeyProvider {
    let backend = KeyBackend.software
}

private func reference(
    backend: KeyBackend = .software,
    exportPolicy: PrivateKeyExportPolicy = .allowed
) -> ProviderKeyReference {
    ProviderKeyReference(
        id: "test-reference",
        algorithm: .nistP256ECDSA,
        backend: backend,
        exportPolicy: exportPolicy
    )
}

@Test func routerDispatchesToSelectedBackend() async throws {
    let router = PrivateKeyProviderRouter()
    try await router.register(RecordingProvider())
    let signature = try await router.sign(
        SignatureRequest(digest: Data([1, 2, 3]), hashAlgorithm: .sha256),
        with: reference()
    )
    #expect(signature == Data([3, 2, 1]))
    #expect(try await router.publicKey(for: reference()) == Data([0x04, 0x01]))
}

@Test func missingAndDuplicateProvidersAreRejected() async throws {
    let router = PrivateKeyProviderRouter()
    do {
        _ = try await router.publicKey(for: reference())
        Issue.record("Expected missing-provider failure")
    } catch let error as PrivateKeyProviderError {
        #expect(error == .providerUnavailable)
    }
    try await router.register(RecordingProvider())
    do {
        try await router.register(RecordingProvider())
        Issue.record("Expected duplicate-provider rejection")
    } catch let error as PrivateKeyProviderError {
        #expect(error == .providerAlreadyRegistered)
    }
}

@Test func publicOnlyRecordsCannotAccessPrivateOperations() async throws {
    let router = PrivateKeyProviderRouter()
    try await router.register(RecordingProvider())
    do {
        _ = try await router.publicKey(for: reference(backend: .publicOnly))
        Issue.record("Expected public-only rejection")
    } catch let error as PrivateKeyProviderError {
        #expect(error == .providerUnavailable)
    }
}

@Test func exportPolicyIsEnforcedBelowProviderCalls() async throws {
    let router = PrivateKeyProviderRouter()
    try await router.register(RecordingProvider())
    #expect(try await router.exportPrivateKey(for: reference()) == Data([0xAA]))

    do {
        _ = try await router.exportPrivateKey(for: reference(exportPolicy: .applicationDisabled))
        Issue.record("Expected application export rejection")
    } catch let error as PrivateKeyProviderError {
        #expect(error == .exportDisabled)
    }

    do {
        _ = try await router.exportPrivateKey(
            for: reference(backend: .secureEnclave, exportPolicy: .hardwareNonExportable)
        )
        Issue.record("Expected hardware export rejection")
    } catch let error as PrivateKeyProviderError {
        #expect(error == .hardwareNonExportable)
    }
}

@Test func unsupportedOperationsUseExplicitErrors() async throws {
    let router = PrivateKeyProviderRouter()
    try await router.register(EmptyProvider())
    let capabilities = try await router.capabilities(for: reference())
    #expect(!capabilities.canSign && !capabilities.canDecrypt && !capabilities.canAgree)
    do {
        _ = try await router.sign(
            SignatureRequest(digest: Data(repeating: 0, count: 32), hashAlgorithm: .sha256),
            with: reference()
        )
        Issue.record("Expected unsupported-operation failure")
    } catch let error as PrivateKeyProviderError {
        #expect(error == .unsupportedOperation)
    }
}

@Test func secretBytesExposeOnlyScopedReadAccess() {
    let secret = SecretBytes(Data([4, 5, 6]))
    let copied = secret.withUnsafeBytes { Data($0) }
    #expect(copied == Data([4, 5, 6]))
}
