import Foundation

enum CryptographicOperation: String, CaseIterable, Identifiable, Sendable {
    case keyManagement
    case signing
    case verification
    case encryption
    case decryption
    case hardwareKeyManagement

    var id: String { rawValue }
}
