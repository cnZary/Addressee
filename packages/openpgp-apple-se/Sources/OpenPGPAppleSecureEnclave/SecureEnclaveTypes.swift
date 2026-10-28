import CryptoKit
import Foundation

public enum SecureEnclaveKeyUsage: String, Codable, Sendable {
    case signing
    case keyAgreement
}

public enum SecureEnclaveAccessControl: String, Codable, Sendable {
    case deviceUnlocked
    case userPresence
    case biometryAny
    case biometryCurrentSet
}

public struct SecureEnclaveKeyReference: Codable, Equatable, Sendable {
    public let id: String
    public let usage: SecureEnclaveKeyUsage
    public let publicKeyX963: Data

    public init(id: String, usage: SecureEnclaveKeyUsage, publicKeyX963: Data) {
        self.id = id
        self.usage = usage
        self.publicKeyX963 = publicKeyX963
    }
}

public enum SecureEnclaveError: Error, Equatable, Sendable {
    case unavailable
    case accessControlCreationFailed
    case invalidReference
    case invalidPublicKey
    case publicKeyMismatch
    case invalidDigestLength
    case invalidUsage
    case unsupportedAlgorithm
    case keyNotFound
    case securityFramework(operation: String, status: OSStatus)
    case coreFoundation(operation: String, domain: String, code: Int)
}

public final class SecureEnclaveSharedSecret: @unchecked Sendable {
    private var bytes: Data

    init(bytes: Data) {
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

enum P256Encoding {
    static func validatePublicKey(_ data: Data) throws {
        guard data.count == 65, data.first == 0x04 else {
            throw SecureEnclaveError.invalidPublicKey
        }
        do {
            _ = try P256.Signing.PublicKey(x963Representation: data)
        } catch {
            throw SecureEnclaveError.invalidPublicKey
        }
    }
}
