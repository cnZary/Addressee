import Foundation

public protocol PrivateKeyProvider: Sendable {
    var backend: KeyBackend { get }

    func capabilities(for reference: ProviderKeyReference) async throws -> PrivateKeyCapabilities
    func availability(for reference: ProviderKeyReference) async throws -> ProviderAvailability
    func publicKey(for reference: ProviderKeyReference) async throws -> Data
    func sign(_ request: SignatureRequest, with reference: ProviderKeyReference) async throws -> Data
    func decrypt(_ request: DecryptionRequest, with reference: ProviderKeyReference) async throws -> SecretBytes
    func sharedSecret(_ request: KeyAgreementRequest, with reference: ProviderKeyReference) async throws -> SecretBytes
    func exportPrivateKey(for reference: ProviderKeyReference) async throws -> Data
}

extension PrivateKeyProvider {
    public func capabilities(for reference: ProviderKeyReference) async throws -> PrivateKeyCapabilities {
        PrivateKeyCapabilities()
    }

    public func availability(for reference: ProviderKeyReference) async throws -> ProviderAvailability {
        .unavailable
    }

    public func publicKey(for reference: ProviderKeyReference) async throws -> Data {
        throw PrivateKeyProviderError.unsupportedOperation
    }

    public func sign(_ request: SignatureRequest, with reference: ProviderKeyReference) async throws -> Data {
        throw PrivateKeyProviderError.unsupportedOperation
    }

    public func decrypt(_ request: DecryptionRequest, with reference: ProviderKeyReference) async throws -> SecretBytes {
        throw PrivateKeyProviderError.unsupportedOperation
    }

    public func sharedSecret(_ request: KeyAgreementRequest, with reference: ProviderKeyReference) async throws -> SecretBytes {
        throw PrivateKeyProviderError.unsupportedOperation
    }

    public func exportPrivateKey(for reference: ProviderKeyReference) async throws -> Data {
        switch reference.exportPolicy {
        case .hardwareNonExportable:
            throw PrivateKeyProviderError.hardwareNonExportable
        case .applicationDisabled, .notApplicable:
            throw PrivateKeyProviderError.exportDisabled
        case .allowed:
            throw PrivateKeyProviderError.unsupportedOperation
        }
    }
}

public actor PrivateKeyProviderRouter {
    private var providers: [KeyBackend: any PrivateKeyProvider] = [:]

    public init() {}

    public func register(_ provider: any PrivateKeyProvider) throws {
        guard provider.backend != .publicOnly, providers[provider.backend] == nil else {
            throw PrivateKeyProviderError.providerAlreadyRegistered
        }
        providers[provider.backend] = provider
    }

    public func capabilities(for reference: ProviderKeyReference) async throws -> PrivateKeyCapabilities {
        try await provider(for: reference).capabilities(for: reference)
    }

    public func availability(for reference: ProviderKeyReference) async throws -> ProviderAvailability {
        try await provider(for: reference).availability(for: reference)
    }

    public func publicKey(for reference: ProviderKeyReference) async throws -> Data {
        try await provider(for: reference).publicKey(for: reference)
    }

    public func sign(_ request: SignatureRequest, with reference: ProviderKeyReference) async throws -> Data {
        try await provider(for: reference).sign(request, with: reference)
    }

    public func decrypt(_ request: DecryptionRequest, with reference: ProviderKeyReference) async throws -> SecretBytes {
        try await provider(for: reference).decrypt(request, with: reference)
    }

    public func sharedSecret(_ request: KeyAgreementRequest, with reference: ProviderKeyReference) async throws -> SecretBytes {
        try await provider(for: reference).sharedSecret(request, with: reference)
    }

    public func exportPrivateKey(for reference: ProviderKeyReference) async throws -> Data {
        switch reference.exportPolicy {
        case .hardwareNonExportable:
            throw PrivateKeyProviderError.hardwareNonExportable
        case .applicationDisabled, .notApplicable:
            throw PrivateKeyProviderError.exportDisabled
        case .allowed:
            return try await provider(for: reference).exportPrivateKey(for: reference)
        }
    }

    private func provider(for reference: ProviderKeyReference) throws -> any PrivateKeyProvider {
        guard reference.backend != .publicOnly, let provider = providers[reference.backend] else {
            throw PrivateKeyProviderError.providerUnavailable
        }
        return provider
    }
}
