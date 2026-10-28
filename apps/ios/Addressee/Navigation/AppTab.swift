import SwiftUI

enum AppTab: String, CaseIterable, Identifiable, Sendable {
    case keys
    case sign
    case encrypt
    case more

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .keys: "tab.keys"
        case .sign: "tab.sign"
        case .encrypt: "tab.encrypt"
        case .more: "tab.more"
        }
    }

    var systemImage: String {
        switch self {
        case .keys: "key"
        case .sign: "signature"
        case .encrypt: "lock"
        case .more: "ellipsis.circle"
        }
    }

    var accessibilityIdentifier: String {
        "tab.\(rawValue)"
    }
}
