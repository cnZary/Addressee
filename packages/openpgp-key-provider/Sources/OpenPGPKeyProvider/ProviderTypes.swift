import Foundation

public struct AlgorithmIdentifier: Codable, Hashable, Sendable {
    public let id: String

    public init(_ id: String) {
        self.id = id
    }

    public static let nistP256ECDSA = AlgorithmIdentifier("nist-p256-ecdsa")
    public static let nistP256ECDH = AlgorithmIdentifier("nist-p256-ecdh")
}

public enum KeyBackend: String, Codable, Sendable {
    case publicOnly
    case software
    case secureEnclave
    case openPgpCard
}

public enum PrivateKeyExportPolicy: String, Codable, Sendable {
    case allowed
    case applicationDisabled
    case hardwareNonExportable
    case notApplicable
}

public struct ProviderKeyReference: Codable, Hashable, Sendable {
    public let id: String
    public let fingerprint: String?
    public let algorithm: AlgorithmIdentifier
    public let backend: KeyBackend
    public let exportPolicy: PrivateKeyExportPolicy

    public init(
        id: String,
        fingerprint: String? = nil,
        algorithm: AlgorithmIdentifier,
        backend: KeyBackend,
        exportPolicy: PrivateKeyExportPolicy
    ) {
        self.id = id
        self.fingerprint = fingerprint
        self.algorithm = algorithm
        self.backend = backend
        self.exportPolicy = exportPolicy
    }
}

public enum OpenPGPHashAlgorithm: String, Codable, Sendable {
    case sha256
    case sha384
    case sha512
    case sha3_256
    case sha3_512
}

public struct SignatureRequest: Sendable {
    public let digest: Data
    public let hashAlgorithm: OpenPGPHashAlgorithm

    public init(digest: Data, hashAlgorithm: OpenPGPHashAlgorithm) {
        self.digest = digest
        self.hashAlgorithm = hashAlgorithm
    }
}

public struct DecryptionRequest: Sendable {
    public let algorithm: AlgorithmIdentifier
    public let ciphertext: Data

    public init(algorithm: AlgorithmIdentifier, ciphertext: Data) {
        self.algorithm = algorithm
        self.ciphertext = ciphertext
    }
}

public struct KeyAgreementRequest: Sendable {
    public let algorithm: AlgorithmIdentifier
    public let peerPublicKey: Data

    public init(algorithm: AlgorithmIdentifier, peerPublicKey: Data) {
        self.algorithm = algorithm
        self.peerPublicKey = peerPublicKey
    }
}

public struct PrivateKeyCapabilities: Equatable, Sendable {
    public var canSign: Bool
    public var canDecrypt: Bool
    public var canAgree: Bool
    public var canExportPrivate: Bool
    public var isHardwareBacked: Bool

    public init(
        canSign: Bool = false,
        canDecrypt: Bool = false,
        canAgree: Bool = false,
        canExportPrivate: Bool = false,
        isHardwareBacked: Bool = false
    ) {
        self.canSign = canSign
        self.canDecrypt = canDecrypt
        self.canAgree = canAgree
        self.canExportPrivate = canExportPrivate
        self.isHardwareBacked = isHardwareBacked
    }
}

public enum ProviderAvailability: Equatable, Sendable {
    case available
    case authenticationRequired
    case disconnected
    case unavailable
}

public enum PrivateKeyProviderError: Error, Equatable, Sendable {
    case unsupportedOperation
    case unsupportedAlgorithm
    case invalidReference
    case providerUnavailable
    case providerAlreadyRegistered
    case exportDisabled
    case hardwareNonExportable
    case authenticationRequired
}

public final class SecretBytes: @unchecked Sendable {
    private var bytes: Data

    public init(_ bytes: Data) {
        self.bytes = bytes
    }

    public func withUnsafeBytes<R>(
        _ body: (UnsafeRawBufferPointer) throws -> R
    ) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    deinit {
        _ = bytes.withUnsafeMutableBytes { buffer in
            buffer.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }
}
