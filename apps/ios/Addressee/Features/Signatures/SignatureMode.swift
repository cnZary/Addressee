import SwiftUI

enum SignatureMode: String, CaseIterable, Identifiable, Sendable {
    case sign
    case verify

    var id: String { rawValue }

    var operation: CryptographicOperation {
        switch self {
        case .sign: .signing
        case .verify: .verification
        }
    }

    var title: LocalizedStringKey {
        switch self {
        case .sign: "signature.mode.sign"
        case .verify: "signature.mode.verify"
        }
    }

    var actionTitle: LocalizedStringKey {
        switch self {
        case .sign: "signature.action.sign"
        case .verify: "signature.action.verify"
        }
    }

    var unavailableTitle: LocalizedStringKey {
        switch self {
        case .sign: "signature.sign.unavailable.title"
        case .verify: "signature.verify.unavailable.title"
        }
    }

    var unavailableMessage: LocalizedStringKey {
        switch self {
        case .sign: "signature.sign.unavailable.message"
        case .verify: "signature.verify.unavailable.message"
        }
    }

    var accessibilityIdentifier: String {
        "mode.signature.\(rawValue)"
    }
}
