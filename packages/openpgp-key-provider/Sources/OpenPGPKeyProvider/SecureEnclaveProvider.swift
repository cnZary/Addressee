import Foundation
import OpenPGPAppleSecureEnclave

public actor SecureEnclaveProvider: PrivateKeyProvider {
    public let backend = KeyBackend.secureEnclave
    private let engine: SecureEnclaveKeyProvider
    private var registeredKeys: [String: RegisteredKey] = [:]

    private struct RegisteredKey {
        let reference: SecureEnclaveKeyReference
        let fingerprint: String?
    }

    public init(engine: SecureEnclaveKeyProvider = SecureEnclaveKeyProvider()) {
        self.engine = engine
    }

    public func generate(
        usage: SecureEnclaveKeyUsage,
        accessControl: SecureEnclaveAccessControl = .deviceUnlocked
    ) async throws -> ProviderKeyReference {
        let reference = try await engine.generate(usage: usage, accessControl: accessControl)
        registeredKeys[reference.id] = RegisteredKey(reference: reference, fingerprint: nil)
        return providerReference(for: reference, fingerprint: nil)
    }

    public func makeIdentifier(for usage: SecureEnclaveKeyUsage) async -> String {
        await engine.identifier(for: usage)
    }

    public func generate(
        usage: SecureEnclaveKeyUsage,
        accessControl: SecureEnclaveAccessControl = .deviceUnlocked,
        identifier: String
    ) async throws -> ProviderKeyReference {
        let reference = try await engine.generate(
            usage: usage,
            accessControl: accessControl,
            identifier: identifier
        )
        registeredKeys[reference.id] = RegisteredKey(reference: reference, fingerprint: nil)
        return providerReference(for: reference, fingerprint: nil)
    }

    public func delete(identifier: String, usage: SecureEnclaveKeyUsage) async throws {
        try await engine.delete(identifier: identifier, usage: usage)
        registeredKeys.removeValue(forKey: identifier)
    }

    public func register(
        _ reference: SecureEnclaveKeyReference,
        fingerprint: String? = nil
    ) async throws -> ProviderKeyReference {
        guard !reference.publicKeyX963.isEmpty else {
            throw PrivateKeyProviderError.invalidReference
        }
        let fingerprint = try Self.normalizedFingerprint(fingerprint)
        _ = try await engine.publicKey(for: reference)
        registeredKeys[reference.id] = RegisteredKey(reference: reference, fingerprint: fingerprint)
        return providerReference(for: reference, fingerprint: fingerprint)
    }

    public func capabilities(for reference: ProviderKeyReference) async throws -> PrivateKeyCapabilities {
        let resolved = try resolve(reference)
        switch resolved.usage {
        case .signing:
            return PrivateKeyCapabilities(canSign: true, isHardwareBacked: true)
        case .keyAgreement:
            return PrivateKeyCapabilities(canAgree: true, isHardwareBacked: true)
        }
    }

    public func availability(for reference: ProviderKeyReference) async throws -> ProviderAvailability {
        let resolved = try resolve(reference)
        guard await engine.isAvailable else { return .unavailable }
        do {
            _ = try await engine.publicKey(for: resolved)
            return .available
        } catch SecureEnclaveError.keyNotFound {
            return .unavailable
        }
    }

    public func publicKey(for reference: ProviderKeyReference) async throws -> Data {
        try await engine.publicKey(for: resolve(reference))
    }

    public func sign(
        _ request: SignatureRequest,
        with reference: ProviderKeyReference
    ) async throws -> Data {
        guard request.hashAlgorithm == .sha256,
              reference.algorithm == .nistP256ECDSA else {
            throw PrivateKeyProviderError.unsupportedAlgorithm
        }
        return try await engine.signSHA256Digest(
            request.digest,
            with: try resolve(reference)
        )
    }

    public func sharedSecret(
        _ request: KeyAgreementRequest,
        with reference: ProviderKeyReference
    ) async throws -> SecretBytes {
        guard request.algorithm == .nistP256ECDH else {
            throw PrivateKeyProviderError.unsupportedAlgorithm
        }
        let sharedSecret = try await engine.sharedSecret(
            with: request.peerPublicKey,
            reference: try resolve(reference)
        )
        return SecretBytes(sharedSecret.withUnsafeBytes { Data($0) })
    }

    public func delete(_ reference: ProviderKeyReference) async throws {
        let resolved = try resolve(reference)
        do {
            _ = try await engine.publicKey(for: resolved)
        } catch SecureEnclaveError.keyNotFound {
            try await engine.delete(resolved)
            registeredKeys.removeValue(forKey: reference.id)
            return
        }
        try await engine.delete(resolved)
        registeredKeys.removeValue(forKey: reference.id)
    }

    private func resolve(
        _ reference: ProviderKeyReference
    ) throws -> SecureEnclaveKeyReference {
        guard reference.backend == .secureEnclave,
              reference.exportPolicy == .hardwareNonExportable,
              let registered = registeredKeys[reference.id],
              registered.fingerprint == (try Self.normalizedFingerprint(reference.fingerprint)) else {
            throw PrivateKeyProviderError.invalidReference
        }
        switch (registered.reference.usage, reference.algorithm) {
        case (.signing, .nistP256ECDSA), (.keyAgreement, .nistP256ECDH):
            return registered.reference
        case (.signing, _), (.keyAgreement, _):
            throw PrivateKeyProviderError.unsupportedAlgorithm
        }
    }

    private func providerReference(
        for reference: SecureEnclaveKeyReference,
        fingerprint: String?
    ) -> ProviderKeyReference {
        ProviderKeyReference(
            id: reference.id,
            fingerprint: fingerprint,
            algorithm: reference.usage == .signing ? .nistP256ECDSA : .nistP256ECDH,
            backend: .secureEnclave,
            exportPolicy: .hardwareNonExportable
        )
    }

    private static func normalizedFingerprint(_ fingerprint: String?) throws -> String? {
        guard let fingerprint else { return nil }
        let bytes = Array(fingerprint.utf8)
        guard [40, 64].contains(bytes.count),
              bytes.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 70) || ($0 >= 97 && $0 <= 102)
              }) else {
            throw PrivateKeyProviderError.invalidReference
        }
        return fingerprint.uppercased()
    }
}
