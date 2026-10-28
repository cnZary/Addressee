import CryptoKit
import Foundation
import OpenPGPAppleSecureEnclave
import OpenPGPKeyProvider
import Security

protocol SecureEnclaveKeyProviding: Sendable {
    func makeIdentifier(for usage: SecureEnclaveKeyUsage) async -> String
    func generate(
        usage: SecureEnclaveKeyUsage,
        accessControl: SecureEnclaveAccessControl,
        identifier: String
    ) async throws -> ProviderKeyReference
    func register(
        _ reference: SecureEnclaveKeyReference,
        fingerprint: String?
    ) async throws -> ProviderKeyReference
    func publicKey(for reference: ProviderKeyReference) async throws -> Data
    func sign(_ request: SignatureRequest, with reference: ProviderKeyReference) async throws -> Data
    func sharedSecret(
        _ request: KeyAgreementRequest,
        with reference: ProviderKeyReference
    ) async throws -> SecretBytes
    func delete(_ reference: ProviderKeyReference) async throws
    func delete(identifier: String, usage: SecureEnclaveKeyUsage) async throws
}

extension SecureEnclaveProvider: SecureEnclaveKeyProviding {}

protocol SecureEnclaveLifecycle: SecureEnclaveOperations {
    func isAvailable() async -> Bool
    func nextIdentifier(for usage: SecureEnclaveKeyUsage) async throws -> String
    func generateReference(
        usage: SecureEnclaveUsageFfi,
        identifier: String
    ) async throws -> SecureEnclaveReferenceFfi
    func registerComponentFingerprints(binding: SecureEnclaveBindingFfi) async throws
    func deleteReference(
        _ reference: SecureEnclaveReferenceFfi,
        componentFingerprint: String?
    ) async throws
    func deleteUnboundIdentifier(_ identifier: String, usage: SecureEnclaveUsageFfi) async throws
}

enum SecureEnclaveLifecycleError: Error, Sendable {
    case cleanupFailed
    case conflictingRecord
}

final class SecureEnclaveBridge: SecureEnclaveOperations, SecureEnclaveLifecycle, @unchecked Sendable {
    private struct RegisteredReference {
        let reference: SecureEnclaveReferenceFfi
        let fingerprint: String?
    }

    private let provider: any SecureEnclaveKeyProviding
    private let availability: @Sendable () -> Bool
    private let lock = NSLock()
    private var registeredReferences: [String: RegisteredReference] = [:]

    init(
        provider: any SecureEnclaveKeyProviding = SecureEnclaveProvider(),
        availability: @escaping @Sendable () -> Bool = { SecureEnclave.isAvailable }
    ) {
        self.provider = provider
        self.availability = availability
    }

    func isAvailable() async -> Bool {
        availability()
    }

    func publicKey(reference: SecureEnclaveReferenceFfi) throws -> Data {
        let providerReference = try providerReference(for: reference, expectedUsage: nil)
        return try wait {
            let actual = try await self.provider.publicKey(for: providerReference)
            guard actual == reference.publicKeyX963 else {
                throw BridgeFailure.invalidResponse
            }
            return actual
        }
    }

    func signSha256(reference: SecureEnclaveReferenceFfi, digest: Data) throws -> Data {
        guard digest.count == 32 else {
            throw SecureEnclaveErrorFfi.InvalidResponse
        }
        let providerReference = try providerReference(for: reference, expectedUsage: .signing)
        return try wait {
            let actual = try await self.provider.publicKey(for: providerReference)
            guard actual == reference.publicKeyX963 else {
                throw BridgeFailure.invalidResponse
            }
            let derSignature = try await self.provider.sign(
                SignatureRequest(digest: digest, hashAlgorithm: .sha256),
                with: providerReference
            )
            let signature: P256.Signing.ECDSASignature
            do {
                signature = try P256.Signing.ECDSASignature(derRepresentation: derSignature)
            } catch {
                throw BridgeFailure.invalidResponse
            }
            let rawSignature = signature.rawRepresentation
            guard rawSignature.count == 64 else {
                throw BridgeFailure.invalidResponse
            }
            return rawSignature
        }
    }

    func ecdh(reference: SecureEnclaveReferenceFfi, peerPublicKey: Data) throws -> Data {
        let providerReference = try providerReference(for: reference, expectedUsage: .keyAgreement)
        return try wait {
            let actual = try await self.provider.publicKey(for: providerReference)
            guard actual == reference.publicKeyX963 else {
                throw BridgeFailure.invalidResponse
            }
            let secret = try await self.provider.sharedSecret(
                KeyAgreementRequest(algorithm: .nistP256ECDH, peerPublicKey: peerPublicKey),
                with: providerReference
            )
            return try secret.withUnsafeBytes { bytes in
                guard bytes.count == 32 else {
                    throw BridgeFailure.invalidResponse
                }
                return Data(bytes)
            }
        }
    }

    func nextIdentifier(for usage: SecureEnclaveKeyUsage) async throws -> String {
        await provider.makeIdentifier(for: usage)
    }

    func generateReference(
        usage: SecureEnclaveUsageFfi,
        identifier: String
    ) async throws -> SecureEnclaveReferenceFfi {
        let keyUsage = try Self.keyUsage(for: usage)
        let generated: ProviderKeyReference
        do {
            generated = try await provider.generate(
                usage: keyUsage,
                accessControl: .biometryAny,
                identifier: identifier
            )
            guard generated.id == identifier else { throw BridgeFailure.invalidResponse }
        } catch {
            throw Self.map(error)
        }
        do {
            let publicKey = try await provider.publicKey(for: generated)
            try Self.validatePublicKey(publicKey)
            let reference = SecureEnclaveReferenceFfi(
                id: generated.id,
                usage: usage,
                publicKeyX963: publicKey
            )
            let isNew = lock.withLock { () -> Bool in
                guard registeredReferences[reference.id] == nil else { return false }
                registeredReferences[reference.id] = RegisteredReference(
                    reference: reference,
                    fingerprint: nil
                )
                return true
            }
            guard isNew else {
                throw SecureEnclaveErrorFfi.InvalidReference
            }
            return reference
        } catch {
            do {
                try await provider.delete(generated)
            } catch {
                throw SecureEnclaveLifecycleError.cleanupFailed
            }
            throw Self.map(error)
        }
    }

    func registerComponentFingerprints(binding: SecureEnclaveBindingFfi) async throws {
        do {
            let certification: SecureEnclaveReferenceFfi?
            if let reference = binding.certification {
                certification = try await register(
                    reference: reference,
                    expectedUsage: .signing,
                    fingerprint: binding.certificateFingerprint
                )
            } else {
                certification = nil
            }
            let signing = try await register(
                reference: binding.signing,
                expectedUsage: .signing,
                fingerprint: binding.signingComponentFingerprint
            )
            let encryption = try await register(
                reference: binding.encryption,
                expectedUsage: .keyAgreement,
                fingerprint: binding.encryptionComponentFingerprint
            )
            lock.withLock {
                if let certification, let reference = binding.certification {
                    registeredReferences[reference.id] = RegisteredReference(
                        reference: certification,
                        fingerprint: binding.certificateFingerprint
                    )
                }
                registeredReferences[binding.signing.id] = RegisteredReference(
                    reference: signing,
                    fingerprint: binding.signingComponentFingerprint
                )
                registeredReferences[binding.encryption.id] = RegisteredReference(
                    reference: encryption,
                    fingerprint: binding.encryptionComponentFingerprint
                )
            }
        } catch {
            throw Self.map(error)
        }
    }

    func deleteReference(
        _ reference: SecureEnclaveReferenceFfi,
        componentFingerprint: String?
    ) async throws {
        do {
            try Self.validate(reference)
            do {
                let registered = try await provider.register(
                    SecureEnclaveKeyReference(
                        id: reference.id,
                        usage: try Self.keyUsage(for: reference.usage),
                        publicKeyX963: reference.publicKeyX963
                    ),
                    fingerprint: componentFingerprint
                )
                try await provider.delete(registered)
            } catch SecureEnclaveError.keyNotFound {
                // A missing key already satisfies idempotent deletion.
            }
            lock.withLock {
                if registeredReferences[reference.id]?.reference == reference {
                    registeredReferences.removeValue(forKey: reference.id)
                }
            }
        } catch SecureEnclaveError.keyNotFound {
            lock.withLock {
                _ = registeredReferences.removeValue(forKey: reference.id)
            }
        } catch {
            throw Self.map(error)
        }
    }

    func deleteUnboundIdentifier(_ identifier: String, usage: SecureEnclaveUsageFfi) async throws {
        do {
            try await provider.delete(identifier: identifier, usage: Self.keyUsage(for: usage))
        } catch {
            throw Self.map(error)
        }
        lock.withLock {
            _ = registeredReferences.removeValue(forKey: identifier)
        }
    }

    private func register(
        reference: SecureEnclaveReferenceFfi,
        expectedUsage: SecureEnclaveUsageFfi,
        fingerprint: String
    ) async throws -> SecureEnclaveReferenceFfi {
        try Self.validate(reference)
        guard reference.usage == expectedUsage else {
            throw SecureEnclaveErrorFfi.InvalidReference
        }
        let registered = try await provider.register(
            SecureEnclaveKeyReference(
                id: reference.id,
                usage: try Self.keyUsage(for: reference.usage),
                publicKeyX963: reference.publicKeyX963
            ),
            fingerprint: fingerprint
        )
        let actual = try await provider.publicKey(for: registered)
        guard actual == reference.publicKeyX963 else {
            throw BridgeFailure.invalidResponse
        }
        return reference
    }

    private func providerReference(
        for reference: SecureEnclaveReferenceFfi,
        expectedUsage: SecureEnclaveUsageFfi?
    ) throws -> ProviderKeyReference {
        try Self.validate(reference)
        if let expectedUsage, reference.usage != expectedUsage {
            throw SecureEnclaveErrorFfi.InvalidReference
        }
        let registered = lock.withLock { registeredReferences[reference.id] }
        guard let registered,
              registered.reference == reference else {
            throw SecureEnclaveErrorFfi.InvalidReference
        }
        return ProviderKeyReference(
            id: reference.id,
            fingerprint: registered.fingerprint,
            algorithm: reference.usage == .signing ? .nistP256ECDSA : .nistP256ECDH,
            backend: .secureEnclave,
            exportPolicy: .hardwareNonExportable
        )
    }

    private func wait<Value: Sendable>(
        _ operation: @escaping @Sendable () async throws -> Value
    ) throws -> Value {
        guard !Thread.isMainThread else {
            throw SecureEnclaveErrorFfi.Unavailable
        }
        do {
            return try CallbackWait.wait(for: operation)
        } catch {
            throw Self.map(error)
        }
    }

    private static func validate(_ reference: SecureEnclaveReferenceFfi) throws {
        guard !reference.id.isEmpty, reference.id.count <= 1_024 else {
            throw SecureEnclaveErrorFfi.InvalidReference
        }
        try validatePublicKey(reference.publicKeyX963)
    }

    private static func validatePublicKey(_ publicKey: Data) throws {
        guard publicKey.count == 65, publicKey.first == 0x04 else {
            throw SecureEnclaveErrorFfi.InvalidReference
        }
        do {
            _ = try P256.Signing.PublicKey(x963Representation: publicKey)
        } catch {
            throw SecureEnclaveErrorFfi.InvalidReference
        }
    }

    private static func keyUsage(
        for usage: SecureEnclaveUsageFfi
    ) throws -> SecureEnclaveKeyUsage {
        switch usage {
        case .signing:
            return .signing
        case .keyAgreement:
            return .keyAgreement
        }
    }

    private static func map(_ error: Error) -> SecureEnclaveErrorFfi {
        if error is CancellationError {
            return .Cancelled
        }
        if let error = error as? SecureEnclaveErrorFfi {
            return error
        }
        if error is BridgeFailure {
            return .InvalidResponse
        }
        if let error = error as? SecureEnclaveError {
            switch error {
            case .invalidReference, .invalidUsage:
                return .InvalidReference
            case .invalidPublicKey, .publicKeyMismatch, .invalidDigestLength:
                return .InvalidResponse
            case .securityFramework(_, let status) where status == errSecUserCanceled:
                return .Cancelled
            case .coreFoundation(_, let domain, let code)
                where domain == NSOSStatusErrorDomain && code == Int(errSecUserCanceled):
                return .Cancelled
            case .unavailable, .accessControlCreationFailed, .unsupportedAlgorithm,
                 .keyNotFound, .securityFramework, .coreFoundation:
                return .Unavailable
            }
        }
        if let error = error as? PrivateKeyProviderError {
            switch error {
            case .invalidReference, .unsupportedAlgorithm:
                return .InvalidReference
            case .unsupportedOperation, .providerUnavailable, .providerAlreadyRegistered,
                 .exportDisabled, .hardwareNonExportable, .authenticationRequired:
                return .Unavailable
            }
        }
        let nsError = error as NSError
        if nsError.domain == NSCocoaErrorDomain && nsError.code == NSUserCancelledError {
            return .Cancelled
        }
        return .Unavailable
    }
}

private enum BridgeFailure: Error {
    case invalidResponse
}
