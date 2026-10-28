import Foundation

struct ServiceAvailability: Equatable, Sendable {
    static let unavailable = ServiceAvailability()

    private let availableOperations: Set<CryptographicOperation>

    init(availableOperations: Set<CryptographicOperation> = []) {
        self.availableOperations = availableOperations
    }

    var isUnavailable: Bool {
        availableOperations.isEmpty
    }

    func isAvailable(_ operation: CryptographicOperation) -> Bool {
        availableOperations.contains(operation)
    }
}
