import Foundation

enum CapabilityOperation: String, Sendable {
    case generate
    case `import`
    case exportPublic
    case exportPrivate
    case sign
    case verify
    case encrypt
    case decrypt
    case useAsPrimaryKey
    case useAsSigningSubkey
    case useAsEncryptionSubkey
}

struct OperationEvidence: Decodable, Sendable {
    let operation: String
    let libraryClaim: String
    let implementation: String
    let unitTests: String
    let independentInteroperabilityTests: String
    let physicalHardwareTests: String
}

struct AlgorithmCapabilityEntry: Decodable, Sendable {
    let algorithm: String
    let backend: String
    let keyVersion: String
    let canGenerate: Bool
    let canImport: Bool
    let canExportPublic: Bool
    let canExportPrivate: Bool
    let canSign: Bool
    let canVerify: Bool
    let canEncrypt: Bool
    let canDecrypt: Bool
    let canUseAsPrimaryKey: Bool
    let canUseAsSigningSubkey: Bool
    let canUseAsEncryptionSubkey: Bool
    let isHardwareBacked: Bool
    let isHardwareNonExportable: Bool
    let isDeprecated: Bool
    let isGenerationDeprecated: Bool
    let isRecommendedForNewKeys: Bool
    let requiresRuntimeDiscovery: Bool
    let evidence: [OperationEvidence]

    func isOperationEnabled(_ operation: CapabilityOperation) -> Bool {
        guard can(operation),
              let evidence = evidence.first(where: { $0.operation == operation.rawValue }),
              evidence.libraryClaim == "claimed",
              evidence.implementation == "implemented",
              evidence.unitTests == "passed" else {
            return false
        }
        return !isHardwareBacked || evidence.physicalHardwareTests == "passed"
    }

    func isFullySupported(_ operation: CapabilityOperation) -> Bool {
        guard isOperationEnabled(operation),
              let evidence = evidence.first(where: { $0.operation == operation.rawValue }) else {
            return false
        }
        return evidence.independentInteroperabilityTests == "passed"
    }

    private func can(_ operation: CapabilityOperation) -> Bool {
        switch operation {
        case .generate: canGenerate
        case .import: canImport
        case .exportPublic: canExportPublic
        case .exportPrivate: canExportPrivate
        case .sign: canSign
        case .verify: canVerify
        case .encrypt: canEncrypt
        case .decrypt: canDecrypt
        case .useAsPrimaryKey: canUseAsPrimaryKey
        case .useAsSigningSubkey: canUseAsSigningSubkey
        case .useAsEncryptionSubkey: canUseAsEncryptionSubkey
        }
    }
}

struct AlgorithmCapabilityRegistry: Decodable, Sendable {
    let schemaVersion: Int
    let entries: [AlgorithmCapabilityEntry]

    func entries(enabledFor operation: CapabilityOperation) -> [AlgorithmCapabilityEntry] {
        entries.filter { $0.isOperationEnabled(operation) }
    }

    func entries(fullySupporting operation: CapabilityOperation) -> [AlgorithmCapabilityEntry] {
        entries.filter { $0.isFullySupported(operation) }
    }
}

enum AlgorithmCapabilityError: Error, Equatable {
    case unsupportedSchema(Int)
}

enum AlgorithmCapabilityService {
    static func loadRegistry() async throws -> AlgorithmCapabilityRegistry {
        try await Task.detached(priority: .userInitiated) {
            let json = try algorithmCapabilitiesJson()
            let registry = try JSONDecoder().decode(
                AlgorithmCapabilityRegistry.self,
                from: Data(json.utf8)
            )
            guard registry.schemaVersion == 1 else {
                throw AlgorithmCapabilityError.unsupportedSchema(registry.schemaVersion)
            }
            return registry
        }.value
    }
}
