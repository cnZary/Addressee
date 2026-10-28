import CryptoKit
import Foundation
import Security

public struct SoftwareKeyEnvelope: Codable, Equatable, Sendable {
    public let formatVersion: Int
    public let payload: Data

    public init(formatVersion: Int, payload: Data) {
        self.formatVersion = formatVersion
        self.payload = payload
    }
}

public enum SoftwareKeyEnvelopeError: Error, Equatable, Sendable {
    case invalidIdentifier
    case invalidExportPolicy
    case invalidEnvelope
    case keyNotFound
    case invalidWrappingKey
    case authenticationFailed
    case securityFramework(operation: String, status: OSStatus)
}

public actor SoftwareKeyEnvelopeStore {
    private let service: String

    public init(service: String = "app.addressee.software-key-wrapping") {
        self.service = service
    }

    public func seal(
        _ plaintext: Data,
        identifier: String,
        exportPolicy: PrivateKeyExportPolicy
    ) throws -> SoftwareKeyEnvelope {
        try validate(identifier: identifier, exportPolicy: exportPolicy)
        let key = try loadOrCreateWrappingKey(identifier: identifier)
        let box = try AES.GCM.seal(
            plaintext,
            using: key,
            nonce: AES.GCM.Nonce(),
            authenticating: additionalData(identifier: identifier, exportPolicy: exportPolicy)
        )
        guard let combined = box.combined else {
            throw SoftwareKeyEnvelopeError.invalidEnvelope
        }
        return SoftwareKeyEnvelope(formatVersion: 1, payload: combined)
    }

    package func unseal(
        _ envelope: SoftwareKeyEnvelope,
        identifier: String,
        exportPolicy: PrivateKeyExportPolicy
    ) throws -> Data {
        try validate(identifier: identifier, exportPolicy: exportPolicy)
        guard envelope.formatVersion == 1, envelope.payload.count >= 28 else {
            throw SoftwareKeyEnvelopeError.invalidEnvelope
        }
        let key = try loadWrappingKey(identifier: identifier)
        do {
            let box = try AES.GCM.SealedBox(combined: envelope.payload)
            return try AES.GCM.open(
                box,
                using: key,
                authenticating: additionalData(identifier: identifier, exportPolicy: exportPolicy)
            )
        } catch {
            throw SoftwareKeyEnvelopeError.authenticationFailed
        }
    }

    public func hasWrappingKey(identifier: String) throws -> Bool {
        try validate(identifier: identifier)
        do {
            _ = try loadWrappingKey(identifier: identifier)
            return true
        } catch SoftwareKeyEnvelopeError.keyNotFound {
            return false
        }
    }

    public func deleteWrappingKey(identifier: String) throws {
        try validate(identifier: identifier)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identifier,
            kSecAttrSynchronizable as String: false,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SoftwareKeyEnvelopeError.securityFramework(operation: "delete", status: status)
        }
    }

    private func loadOrCreateWrappingKey(identifier: String) throws -> SymmetricKey {
        do {
            return try loadWrappingKey(identifier: identifier)
        } catch SoftwareKeyEnvelopeError.keyNotFound {
            let key = SymmetricKey(size: .bits256)
            var keyData = key.withUnsafeBytes { Data($0) }
            defer {
                _ = keyData.withUnsafeMutableBytes { buffer in
                    buffer.initializeMemory(as: UInt8.self, repeating: 0)
                }
            }
            let attributes: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: identifier,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecAttrSynchronizable as String: false,
                kSecValueData as String: keyData,
            ]
            let status = SecItemAdd(attributes as CFDictionary, nil)
            if status == errSecDuplicateItem {
                return try loadWrappingKey(identifier: identifier)
            }
            guard status == errSecSuccess else {
                throw SoftwareKeyEnvelopeError.securityFramework(operation: "create", status: status)
            }
            return key
        }
    }

    private func loadWrappingKey(identifier: String) throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identifier,
            kSecAttrSynchronizable as String: false,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status != errSecItemNotFound else {
            throw SoftwareKeyEnvelopeError.keyNotFound
        }
        guard status == errSecSuccess else {
            throw SoftwareKeyEnvelopeError.securityFramework(operation: "load", status: status)
        }
        guard let data = result as? Data, data.count == 32 else {
            throw SoftwareKeyEnvelopeError.invalidWrappingKey
        }
        return SymmetricKey(data: data)
    }

    private func additionalData(
        identifier: String,
        exportPolicy: PrivateKeyExportPolicy
    ) -> Data {
        Data("addressee.software-key-envelope.v1\0\(identifier)\0\(exportPolicy.rawValue)".utf8)
    }

    private func validate(
        identifier: String,
        exportPolicy: PrivateKeyExportPolicy? = nil
    ) throws {
        guard [32, 40, 64].contains(identifier.count),
              identifier.allSatisfy({ $0.isASCII && $0.isHexDigit && !$0.isLowercase }) else {
            throw SoftwareKeyEnvelopeError.invalidIdentifier
        }
        if let exportPolicy,
           exportPolicy != .allowed && exportPolicy != .applicationDisabled {
            throw SoftwareKeyEnvelopeError.invalidExportPolicy
        }
    }
}
