import Foundation

struct CardIdentityRecord: Codable, Equatable, Sendable {
    let manufacturer: UInt16
    let serial: UInt32
    let version: UInt16

    init(_ identity: CardIdentityFfi) {
        manufacturer = identity.manufacturer
        serial = identity.serial
        version = identity.version
    }

    func ffi() -> CardIdentityFfi {
        CardIdentityFfi(manufacturer: manufacturer, serial: serial, version: version)
    }
}

struct CardBinding: Codable, Equatable, Sendable {
    let certificateFingerprint: String
    let identity: CardIdentityRecord
    let signingComponent: String?
    let decryptionComponent: String?

    init(registration: CardRegistrationFfi) throws {
        certificateFingerprint = registration.certificateFingerprint
        identity = CardIdentityRecord(registration.identity)
        var signingComponent: String?
        var decryptionComponent: String?
        for component in registration.components {
            switch component.slot {
            case .signing:
                guard signingComponent == nil else { throw CardBindingStoreError.invalidManifest }
                signingComponent = component.componentFingerprint
            case .decryption:
                guard decryptionComponent == nil else { throw CardBindingStoreError.invalidManifest }
                decryptionComponent = component.componentFingerprint
            case .authentication:
                throw CardBindingStoreError.invalidManifest
            }
        }
        self.signingComponent = signingComponent
        self.decryptionComponent = decryptionComponent
        try validate()
    }

    var registration: CardRegistrationFfi {
        var components: [CardComponentBindingFfi] = []
        if let signingComponent {
            components.append(CardComponentBindingFfi(
                slot: .signing,
                componentFingerprint: signingComponent
            ))
        }
        if let decryptionComponent {
            components.append(CardComponentBindingFfi(
                slot: .decryption,
                componentFingerprint: decryptionComponent
            ))
        }
        return CardRegistrationFfi(
            certificateFingerprint: certificateFingerprint,
            identity: identity.ffi(),
            components: components
        )
    }

    func validate() throws {
        guard isCardFingerprint(certificateFingerprint),
              signingComponent != nil || decryptionComponent != nil else {
            throw CardBindingStoreError.invalidManifest
        }
        for component in [signingComponent, decryptionComponent] {
            if let component {
                guard isCardFingerprint(component) else {
                    throw CardBindingStoreError.invalidManifest
                }
            }
        }
        if let signingComponent, let decryptionComponent {
            guard signingComponent != decryptionComponent else {
                throw CardBindingStoreError.invalidManifest
            }
        }
    }
}

enum CardBindingStoreError: Error, Equatable, Sendable {
    case invalidManifest
    case conflict
    case notFound
    case io
}

actor CardBindingStore {
    private struct Manifest: Codable {
        var formatVersion: Int
        var bindings: [CardBinding]
    }

    private static let maximumManifestBytes = 1024 * 1024
    private static let maximumBindings = 64

    private let directory: URL?
    private let fileManager: FileManager
    private var manifest: Manifest?
    private var manifestURL: URL? { directory?.appendingPathComponent("manifest.json") }

    init(directory: URL?, fileManager: FileManager = .default) {
        self.directory = directory
        self.fileManager = fileManager
    }

    static func inMemory() -> CardBindingStore {
        CardBindingStore(directory: nil)
    }

    static func live() -> CardBindingStore {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return CardBindingStore(
            directory: base.appendingPathComponent("Addressee/CardBindings", isDirectory: true)
        )
    }

    func bindings() throws -> [CardBinding] {
        try current().bindings
    }

    func insert(_ binding: CardBinding) throws {
        var manifest = try current()
        try binding.validate()
        guard !manifest.bindings.contains(where: {
            $0.certificateFingerprint == binding.certificateFingerprint
        }) else {
            throw CardBindingStoreError.conflict
        }
        manifest.bindings.append(binding)
        manifest.bindings.sort { $0.certificateFingerprint < $1.certificateFingerprint }
        try save(manifest)
    }

    func remove(certificateFingerprint: String) throws {
        guard isCardFingerprint(certificateFingerprint) else {
            throw CardBindingStoreError.invalidManifest
        }
        var manifest = try current()
        guard manifest.bindings.contains(where: {
            $0.certificateFingerprint == certificateFingerprint
        }) else {
            throw CardBindingStoreError.notFound
        }
        manifest.bindings.removeAll { $0.certificateFingerprint == certificateFingerprint }
        try save(manifest)
    }

    func replaceAll(_ bindings: [CardBinding]) throws {
        var manifest = Manifest(formatVersion: 1, bindings: bindings)
        manifest.bindings.sort { $0.certificateFingerprint < $1.certificateFingerprint }
        try save(manifest)
    }

    private func current() throws -> Manifest {
        if let manifest { return manifest }
        guard let manifestURL else {
            let empty = Manifest(formatVersion: 1, bindings: [])
            manifest = empty
            return empty
        }
        do {
            let handle = try FileHandle(forReadingFrom: manifestURL)
            defer { try? handle.close() }
            let data = try handle.read(upToCount: Self.maximumManifestBytes + 1) ?? Data()
            guard data.count <= Self.maximumManifestBytes else {
                throw CardBindingStoreError.invalidManifest
            }
            let decoded = try JSONDecoder().decode(Manifest.self, from: data)
            try validate(decoded)
            manifest = decoded
            return decoded
        } catch let error as CardBindingStoreError {
            throw error
        } catch {
            let error = error as NSError
            if error.domain == NSCocoaErrorDomain,
               error.code == NSFileNoSuchFileError || error.code == NSFileReadNoSuchFileError {
                let empty = Manifest(formatVersion: 1, bindings: [])
                manifest = empty
                return empty
            }
            throw CardBindingStoreError.invalidManifest
        }
    }

    private func save(_ next: Manifest) throws {
        do {
            try validate(next)
            guard let directory, let manifestURL else {
                manifest = next
                return
            }
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            #if os(iOS)
            try fileManager.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: directory.path
            )
            #endif
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(next)
            guard data.count <= Self.maximumManifestBytes else {
                throw CardBindingStoreError.invalidManifest
            }
            try data.write(to: manifestURL, options: .atomic)
            #if os(iOS)
            try fileManager.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: manifestURL.path
            )
            #endif
            manifest = next
        } catch let error as CardBindingStoreError {
            throw error
        } catch {
            throw CardBindingStoreError.io
        }
    }

    private func validate(_ manifest: Manifest) throws {
        guard manifest.formatVersion == 1,
              manifest.bindings.count <= Self.maximumBindings,
              Set(manifest.bindings.map(\.certificateFingerprint)).count == manifest.bindings.count else {
            throw CardBindingStoreError.invalidManifest
        }
        for binding in manifest.bindings {
            try binding.validate()
        }
    }
}

private func isCardFingerprint(_ value: String) -> Bool {
    value.count == 40 && value.utf8.allSatisfy {
        ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x46)
    }
}
