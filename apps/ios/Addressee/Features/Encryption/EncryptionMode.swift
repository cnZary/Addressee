import SwiftUI

enum EncryptionMode: String, CaseIterable, Identifiable, Sendable {
    case encrypt
    case decrypt

    var id: String { rawValue }

    var operation: CryptographicOperation {
        switch self {
        case .encrypt: .encryption
        case .decrypt: .decryption
        }
    }

    var title: LocalizedStringKey {
        switch self {
        case .encrypt: "encryption.mode.encrypt"
        case .decrypt: "encryption.mode.decrypt"
        }
    }

    var actionTitle: LocalizedStringKey {
        switch self {
        case .encrypt: "encryption.action.encrypt"
        case .decrypt: "encryption.action.decrypt"
        }
    }

    var unavailableTitle: LocalizedStringKey {
        switch self {
        case .encrypt: "encryption.encrypt.unavailable.title"
        case .decrypt: "encryption.decrypt.unavailable.title"
        }
    }

    var unavailableMessage: LocalizedStringKey {
        switch self {
        case .encrypt: "encryption.encrypt.unavailable.message"
        case .decrypt: "encryption.decrypt.unavailable.message"
        }
    }

    var accessibilityIdentifier: String {
        "mode.encryption.\(rawValue)"
    }
}
