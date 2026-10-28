import Foundation

struct SecuritySettings: Equatable, Sendable {
    static let softwareExportStorageKey = "security.allowSoftwareKeyExport"

    var allowsSoftwareKeyExport = false

    func permitsPrivateKeyExport(for protection: KeyProtection) -> Bool {
        switch protection {
        case .software:
            allowsSoftwareKeyExport
        case .secureEnclaveP256:
            false
        }
    }
}
