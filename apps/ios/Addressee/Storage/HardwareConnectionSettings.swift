import Foundation

// UserDefaults is thread-safe, and this type only reads and writes one Boolean setting.
struct HardwareConnectionSettings: @unchecked Sendable {
    static let multipleHardwareKeysStorageKey = "hardware.multipleHardwareKeys"

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var allowsMultipleHardwareKeys: Bool {
        get { defaults.bool(forKey: Self.multipleHardwareKeysStorageKey) }
        nonmutating set { defaults.set(newValue, forKey: Self.multipleHardwareKeysStorageKey) }
    }
}
