import Foundation

enum KeyProtection: String, Equatable, Sendable {
    case software
    case secureEnclaveP256
}

struct StoredKey: Identifiable, Equatable, Sendable {
    let id: UUID
    let displayName: String
    let protection: KeyProtection
}

struct KeyInventory: Equatable, Sendable {
    static let empty = KeyInventory()

    let keys: [StoredKey]

    init(keys: [StoredKey] = []) {
        self.keys = keys
    }

    var isEmpty: Bool {
        keys.isEmpty
    }

    var count: Int {
        keys.count
    }
}
