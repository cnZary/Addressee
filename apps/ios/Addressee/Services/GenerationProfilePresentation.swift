import SwiftUI

extension GenerationProfileFfi: CaseIterable {
    public static let allCases: [GenerationProfileFfi] = [
        .modernV6,
        .curve448V6,
        .legacyCurve25519V4,
        .nistP256v4,
        .nistP384v4,
        .nistP521v4,
        .rsa2048V4,
        .rsa3072V4,
        .rsa4096V4,
    ]
}

extension GenerationProfileFfi: Identifiable {
    public var id: String { String(describing: self) }

    var title: LocalizedStringKey {
        switch self {
        case .modernV6: "profile.modern"
        case .curve448V6: "profile.curve448"
        case .legacyCurve25519V4: "profile.legacyCurve25519"
        case .nistP256v4: "profile.nistP256"
        case .nistP384v4: "profile.nistP384"
        case .nistP521v4: "profile.nistP521"
        case .rsa2048V4: "profile.rsa2048"
        case .rsa3072V4: "profile.rsa3072"
        case .rsa4096V4: "profile.rsa4096"
        }
    }

    var isLegacyCompatibilityProfile: Bool {
        switch self {
        case .modernV6, .curve448V6, .nistP256v4, .nistP384v4, .nistP521v4:
            false
        case .legacyCurve25519V4, .rsa2048V4, .rsa3072V4, .rsa4096V4:
            true
        }
    }

    var keyVersion: String {
        switch self {
        case .modernV6, .curve448V6: "v6"
        default: "v4"
        }
    }

    fileprivate var algorithmRoles: [(primary: String, signing: String, encryption: String)] {
        switch self {
        case .modernV6: [("ed25519", "ed25519", "x25519")]
        case .curve448V6: [("ed448", "ed448", "x448")]
        case .legacyCurve25519V4: [("legacy-ed25519", "legacy-ed25519", "legacy-curve25519-ecdh")]
        case .nistP256v4: [("nist-p256-ecdsa", "nist-p256-ecdsa", "nist-p256-ecdh")]
        case .nistP384v4: [("nist-p384-ecdsa", "nist-p384-ecdsa", "nist-p384-ecdh")]
        case .nistP521v4: [("nist-p521-ecdsa", "nist-p521-ecdsa", "nist-p521-ecdh")]
        case .rsa2048V4: [("rsa-2048", "rsa-2048", "rsa-2048")]
        case .rsa3072V4: [("rsa-3072", "rsa-3072", "rsa-3072")]
        case .rsa4096V4: [("rsa-4096", "rsa-4096", "rsa-4096")]
        }
    }

    func isEnabled(in registry: AlgorithmCapabilityRegistry?) -> Bool {
        guard let registry else { return false }
        for role in algorithmRoles {
            for (algorithm, operation) in [
                (role.primary, CapabilityOperation.generate),
                (role.primary, .useAsPrimaryKey),
                (role.signing, .generate),
                (role.signing, .useAsSigningSubkey),
                (role.encryption, .generate),
                (role.encryption, .useAsEncryptionSubkey),
            ] {
                guard let entry = registry.entry(
                    algorithm: algorithm,
                    backend: "software",
                    keyVersion: keyVersion
                ), entry.isOperationEnabled(operation) else {
                    return false
                }
            }
        }
        return true
    }
}

extension AlgorithmCapabilityRegistry {
    func entry(algorithm: String, backend: String, keyVersion: String) -> AlgorithmCapabilityEntry? {
        entries.first {
            $0.algorithm == algorithm && $0.backend == backend && $0.keyVersion == keyVersion
        }
    }
}
