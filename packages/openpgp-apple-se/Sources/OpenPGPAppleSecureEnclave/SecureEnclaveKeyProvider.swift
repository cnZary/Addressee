import CryptoKit
import Foundation
import Security

public actor SecureEnclaveKeyProvider {
    private let namespace: String

    public init(namespace: String = "app.addressee.secure-enclave") {
        self.namespace = namespace
    }

    public var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    public func identifier(for usage: SecureEnclaveKeyUsage) -> String {
        "\(namespace).\(usage.rawValue).\(UUID().uuidString)"
    }

    public func generate(
        usage: SecureEnclaveKeyUsage,
        accessControl: SecureEnclaveAccessControl = .deviceUnlocked
    ) throws -> SecureEnclaveKeyReference {
        try generate(
            usage: usage,
            accessControl: accessControl,
            identifier: identifier(for: usage)
        )
    }

    public func generate(
        usage: SecureEnclaveKeyUsage,
        accessControl: SecureEnclaveAccessControl = .deviceUnlocked,
        identifier: String
    ) throws -> SecureEnclaveKeyReference {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.unavailable
        }
        try validateIdentifier(identifier, usage: usage)
        let applicationTag = Data(identifier.utf8)
        let flags = Self.accessControlFlags(for: accessControl)
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            nil
        ) else {
            throw SecureEnclaveError.accessControlCreationFailed
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag,
                kSecAttrAccessControl as String: access,
                kSecAttrSynchronizable as String: false,
            ],
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw Self.cfError("generate", error)
        }
        do {
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                throw SecureEnclaveError.invalidPublicKey
            }
            let publicData = try externalRepresentation(publicKey)
            try P256Encoding.validatePublicKey(publicData)
            return SecureEnclaveKeyReference(
                id: identifier,
                usage: usage,
                publicKeyX963: publicData
            )
        } catch {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: applicationTag,
                kSecAttrSynchronizable as String: false,
            ]
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw SecureEnclaveError.securityFramework(operation: "cleanup-generation", status: status)
            }
            throw error
        }
    }

    public func publicKey(for reference: SecureEnclaveKeyReference) throws -> Data {
        try validate(reference)
        let privateKey = try loadPrivateKey(reference)
        try validateBinding(reference, with: privateKey)
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveError.invalidPublicKey
        }
        let data = try externalRepresentation(publicKey)
        try P256Encoding.validatePublicKey(data)
        return data
    }

    public func signSHA256Digest(
        _ digest: Data,
        with reference: SecureEnclaveKeyReference
    ) throws -> Data {
        try validate(reference, expectedUsage: .signing)
        guard digest.count == 32 else {
            throw SecureEnclaveError.invalidDigestLength
        }
        let privateKey = try loadPrivateKey(reference)
        try validateBinding(reference, with: privateKey)
        let algorithm = SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw SecureEnclaveError.unsupportedAlgorithm
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            digest as CFData,
            &error
        ) else {
            throw Self.cfError("sign", error)
        }
        return signature as Data
    }

    public func sharedSecret(
        with publicKeyX963: Data,
        reference: SecureEnclaveKeyReference
    ) throws -> SecureEnclaveSharedSecret {
        try validate(reference, expectedUsage: .keyAgreement)
        try P256Encoding.validatePublicKey(publicKeyX963)
        let privateKey = try loadPrivateKey(reference)
        try validateBinding(reference, with: privateKey)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(publicKeyX963 as CFData, attributes as CFDictionary, &error) else {
            throw Self.cfError("import-public-key", error)
        }
        let algorithm = SecKeyAlgorithm.ecdhKeyExchangeStandard
        guard SecKeyIsAlgorithmSupported(privateKey, .keyExchange, algorithm) else {
            throw SecureEnclaveError.unsupportedAlgorithm
        }
        guard let secret = SecKeyCopyKeyExchangeResult(
            privateKey,
            algorithm,
            publicKey,
            [:] as CFDictionary,
            &error
        ) else {
            throw Self.cfError("key-agreement", error)
        }
        return SecureEnclaveSharedSecret(bytes: secret as Data)
    }

    public func delete(identifier: String, usage: SecureEnclaveKeyUsage) throws {
        try validateIdentifier(identifier, usage: usage)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(identifier.utf8),
            kSecAttrSynchronizable as String: false,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureEnclaveError.securityFramework(operation: "delete-identifier", status: status)
        }
    }

    public func delete(_ reference: SecureEnclaveKeyReference) throws {
        try validate(reference)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(reference.id.utf8),
            kSecAttrSynchronizable as String: false,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureEnclaveError.securityFramework(operation: "delete", status: status)
        }
    }

    private func loadPrivateKey(_ reference: SecureEnclaveKeyReference) throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: Data(reference.id.utf8),
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrSynchronizable as String: false,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status != errSecItemNotFound else {
            throw SecureEnclaveError.keyNotFound
        }
        guard status == errSecSuccess, let result else {
            throw SecureEnclaveError.securityFramework(operation: "load", status: status)
        }
        guard CFGetTypeID(result) == SecKeyGetTypeID() else {
            throw SecureEnclaveError.invalidReference
        }
        return result as! SecKey
    }

    private func validate(
        _ reference: SecureEnclaveKeyReference,
        expectedUsage: SecureEnclaveKeyUsage? = nil
    ) throws {
        try validateIdentifier(reference.id, usage: reference.usage)
        try P256Encoding.validatePublicKey(reference.publicKeyX963)
        if let expectedUsage, reference.usage != expectedUsage {
            throw SecureEnclaveError.invalidUsage
        }
    }

    private func validateIdentifier(_ identifier: String, usage: SecureEnclaveKeyUsage) throws {
        let prefix = "\(namespace).\(usage.rawValue)."
        guard identifier.hasPrefix(prefix),
              UUID(uuidString: String(identifier.dropFirst(prefix.count))) != nil else {
            throw SecureEnclaveError.invalidReference
        }
    }

    private func validateBinding(
        _ reference: SecureEnclaveKeyReference,
        with privateKey: SecKey
    ) throws {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveError.invalidPublicKey
        }
        let actual = try externalRepresentation(publicKey)
        try P256Encoding.validatePublicKey(actual)
        guard actual == reference.publicKeyX963 else {
            throw SecureEnclaveError.publicKeyMismatch
        }
    }

    static func accessControlFlags(
        for accessControl: SecureEnclaveAccessControl
    ) -> SecAccessControlCreateFlags {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        switch accessControl {
        case .deviceUnlocked:
            break
        case .userPresence:
            flags.insert(.userPresence)
        case .biometryAny:
            flags.insert(.biometryAny)
        case .biometryCurrentSet:
            flags.insert(.biometryCurrentSet)
        }
        return flags
    }

    private func externalRepresentation(_ key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &error) else {
            throw Self.cfError("export-public-key", error)
        }
        return data as Data
    }

    private static func cfError(
        _ operation: String,
        _ unmanaged: Unmanaged<CFError>?
    ) -> SecureEnclaveError {
        guard let error = unmanaged?.takeRetainedValue() else {
            return .coreFoundation(operation: operation, domain: "unknown", code: -1)
        }
        return .coreFoundation(
            operation: operation,
            domain: CFErrorGetDomain(error) as String,
            code: CFErrorGetCode(error)
        )
    }
}
