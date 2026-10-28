import CryptoKit
import Foundation
import OpenPGPAppleSecureEnclave

struct SecureEnclaveReferenceRecord: Codable, Equatable, Sendable {
    let id: String
    let usage: SecureEnclaveKeyUsage
    let publicKeyX963: Data

    init(_ reference: SecureEnclaveReferenceFfi) {
        id = reference.id
        switch reference.usage {
        case .signing: usage = .signing
        case .keyAgreement: usage = .keyAgreement
        }
        publicKeyX963 = reference.publicKeyX963
    }

    func ffi() -> SecureEnclaveReferenceFfi {
        SecureEnclaveReferenceFfi(
            id: id,
            usage: usage == .signing ? .signing : .keyAgreement,
            publicKeyX963: publicKeyX963
        )
    }
}

struct SecureEnclaveBindingRecord: Codable, Equatable, Sendable {
    let certificateFingerprint: String
    let publicCertificate: Data
    let signingComponentFingerprint: String
    let encryptionComponentFingerprint: String
    let signing: SecureEnclaveReferenceRecord
    let encryption: SecureEnclaveReferenceRecord
    let accessControl: SecureEnclaveAccessControl

    init(
        _ binding: SecureEnclaveBindingFfi,
        accessControl: SecureEnclaveAccessControl = .biometryAny
    ) {
        certificateFingerprint = binding.certificateFingerprint
        publicCertificate = binding.publicCertificate
        signingComponentFingerprint = binding.signingComponentFingerprint
        encryptionComponentFingerprint = binding.encryptionComponentFingerprint
        signing = SecureEnclaveReferenceRecord(binding.signing)
        encryption = SecureEnclaveReferenceRecord(binding.encryption)
        self.accessControl = accessControl
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        certificateFingerprint = try container.decode(String.self, forKey: .certificateFingerprint)
        publicCertificate = try container.decode(Data.self, forKey: .publicCertificate)
        signingComponentFingerprint = try container.decode(String.self, forKey: .signingComponentFingerprint)
        encryptionComponentFingerprint = try container.decode(String.self, forKey: .encryptionComponentFingerprint)
        signing = try container.decode(SecureEnclaveReferenceRecord.self, forKey: .signing)
        encryption = try container.decode(SecureEnclaveReferenceRecord.self, forKey: .encryption)
        accessControl = try container.decodeIfPresent(
            SecureEnclaveAccessControl.self,
            forKey: .accessControl
        ) ?? .deviceUnlocked
    }

    func ffi() -> SecureEnclaveBindingFfi {
        SecureEnclaveBindingFfi(
            certificateFingerprint: certificateFingerprint,
            publicCertificate: publicCertificate,
            signingComponentFingerprint: signingComponentFingerprint,
            encryptionComponentFingerprint: encryptionComponentFingerprint,
            signing: signing.ffi(),
            encryption: encryption.ffi()
        )
    }
}

struct SecureEnclaveGenerationJournal: Codable, Equatable, Sendable {
    let signingIdentifier: String
    let encryptionIdentifier: String
    var candidate: SecureEnclaveBindingRecord?
}

struct SecureEnclaveDeletionJournal: Codable, Equatable, Sendable {
    let binding: SecureEnclaveBindingRecord
    var deletedIdentifiers: Set<String>
}

enum PendingSecureEnclaveOperation: Codable, Equatable, Sendable {
    case generation(SecureEnclaveGenerationJournal)
    case deletion(SecureEnclaveDeletionJournal)
}

struct SecureEnclaveBindingSnapshot: Sendable {
    let bindings: [SecureEnclaveBindingFfi]
    let accessControls: [String: SecureEnclaveAccessControl]
    let pending: PendingSecureEnclaveOperation?
}

enum SecureEnclaveBindingStoreError: Error, Equatable, Sendable {
    case invalidManifest
    case conflict
    case notFound
    case io
}

actor SecureEnclaveBindingStore {
    private struct Manifest: Codable {
        var formatVersion: Int
        var bindings: [SecureEnclaveBindingRecord]
        var pending: PendingSecureEnclaveOperation?
    }

    private let directory: URL?
    private let fileManager: FileManager
    private var manifest: Manifest?
    private var manifestURL: URL? { directory?.appendingPathComponent("manifest.json") }

    init(directory: URL?, fileManager: FileManager = .default) {
        self.directory = directory
        self.fileManager = fileManager
    }

    static func inMemory() -> SecureEnclaveBindingStore {
        SecureEnclaveBindingStore(directory: nil)
    }

    static func live() -> SecureEnclaveBindingStore {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return SecureEnclaveBindingStore(
            directory: base.appendingPathComponent("Addressee/SecureEnclaveBindings", isDirectory: true)
        )
    }

    func snapshot() throws -> SecureEnclaveBindingSnapshot {
        let manifest = try current()
        return SecureEnclaveBindingSnapshot(
            bindings: manifest.bindings.map { $0.ffi() },
            accessControls: Dictionary(uniqueKeysWithValues: manifest.bindings.map {
                ($0.certificateFingerprint, $0.accessControl)
            }),
            pending: manifest.pending
        )
    }

    func beginGeneration(signingIdentifier: String, encryptionIdentifier: String) throws {
        var manifest = try current()
        guard manifest.pending == nil else { throw SecureEnclaveBindingStoreError.conflict }
        try validateIdentifier(signingIdentifier)
        try validateIdentifier(encryptionIdentifier)
        guard signingIdentifier != encryptionIdentifier else {
            throw SecureEnclaveBindingStoreError.invalidManifest
        }
        manifest.pending = .generation(SecureEnclaveGenerationJournal(
            signingIdentifier: signingIdentifier,
            encryptionIdentifier: encryptionIdentifier,
            candidate: nil
        ))
        try save(manifest)
    }

    func recordGenerationCandidate(_ binding: SecureEnclaveBindingFfi) throws {
        var manifest = try current()
        guard case .generation(var journal) = manifest.pending else {
            throw SecureEnclaveBindingStoreError.notFound
        }
        let candidate = SecureEnclaveBindingRecord(binding)
        try validate(candidate)
        guard journal.signingIdentifier == candidate.signing.id,
              journal.encryptionIdentifier == candidate.encryption.id,
              journal.candidate == nil || journal.candidate == candidate else {
            throw SecureEnclaveBindingStoreError.conflict
        }
        journal.candidate = candidate
        manifest.pending = .generation(journal)
        try save(manifest)
    }

    func commitGeneration(_ binding: SecureEnclaveBindingFfi) throws {
        var manifest = try current()
        guard case .generation(let journal) = manifest.pending,
              journal.candidate == SecureEnclaveBindingRecord(binding),
              !manifest.bindings.contains(where: {
                  $0.certificateFingerprint == binding.certificateFingerprint
              }) else {
            throw SecureEnclaveBindingStoreError.conflict
        }
        manifest.bindings.append(SecureEnclaveBindingRecord(binding))
        manifest.bindings.sort { $0.certificateFingerprint < $1.certificateFingerprint }
        manifest.pending = nil
        try save(manifest)
    }

    func cancelGeneration() throws {
        var manifest = try current()
        guard case .generation = manifest.pending else {
            throw SecureEnclaveBindingStoreError.notFound
        }
        manifest.pending = nil
        try save(manifest)
    }

    func beginDeletion(certificateFingerprint: String) throws {
        var manifest = try current()
        guard manifest.pending == nil,
              let binding = manifest.bindings.first(where: {
                  $0.certificateFingerprint == certificateFingerprint
              }) else {
            throw SecureEnclaveBindingStoreError.notFound
        }
        manifest.pending = .deletion(SecureEnclaveDeletionJournal(
            binding: binding,
            deletedIdentifiers: []
        ))
        try save(manifest)
    }

    func markDeleted(identifier: String) throws {
        var manifest = try current()
        guard case .deletion(var journal) = manifest.pending,
              journal.binding.signing.id == identifier || journal.binding.encryption.id == identifier else {
            throw SecureEnclaveBindingStoreError.conflict
        }
        journal.deletedIdentifiers.insert(identifier)
        manifest.pending = .deletion(journal)
        try save(manifest)
    }

    func finishDeletion(certificateFingerprint: String) throws {
        var manifest = try current()
        guard case .deletion(let journal) = manifest.pending,
              journal.binding.certificateFingerprint == certificateFingerprint,
              journal.deletedIdentifiers.isSuperset(of: [
                  journal.binding.signing.id,
                  journal.binding.encryption.id,
              ]) else {
            throw SecureEnclaveBindingStoreError.conflict
        }
        manifest.bindings.removeAll { $0.certificateFingerprint == certificateFingerprint }
        manifest.pending = nil
        try save(manifest)
    }

    private func current() throws -> Manifest {
        if let manifest { return manifest }
        guard let manifestURL else {
            let empty = Manifest(formatVersion: 1, bindings: [], pending: nil)
            manifest = empty
            return empty
        }
        let data: Data
        do {
            data = try Data(contentsOf: manifestURL)
        } catch {
            let error = error as NSError
            if error.domain == NSCocoaErrorDomain,
               error.code == NSFileNoSuchFileError || error.code == NSFileReadNoSuchFileError {
                let empty = Manifest(formatVersion: 1, bindings: [], pending: nil)
                manifest = empty
                return empty
            }
            throw SecureEnclaveBindingStoreError.io
        }
        do {
            let decoded = try JSONDecoder().decode(Manifest.self, from: data)
            try validate(decoded)
            manifest = decoded
            return decoded
        } catch let error as SecureEnclaveBindingStoreError {
            throw error
        } catch {
            throw SecureEnclaveBindingStoreError.invalidManifest
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
            try data.write(to: manifestURL, options: .atomic)
            #if os(iOS)
            try fileManager.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: manifestURL.path
            )
            #endif
            manifest = next
        } catch let error as SecureEnclaveBindingStoreError {
            throw error
        } catch {
            throw SecureEnclaveBindingStoreError.io
        }
    }

    private func validate(_ manifest: Manifest) throws {
        guard manifest.formatVersion == 1,
              Set(manifest.bindings.map(\.certificateFingerprint)).count == manifest.bindings.count else {
            throw SecureEnclaveBindingStoreError.invalidManifest
        }
        for binding in manifest.bindings { try validate(binding) }
        switch manifest.pending {
        case .none:
            break
        case .generation(let journal):
            try validateIdentifier(journal.signingIdentifier)
            try validateIdentifier(journal.encryptionIdentifier)
            guard journal.signingIdentifier != journal.encryptionIdentifier else {
                throw SecureEnclaveBindingStoreError.invalidManifest
            }
            if let candidate = journal.candidate {
                try validate(candidate)
                guard candidate.signing.id == journal.signingIdentifier,
                      candidate.encryption.id == journal.encryptionIdentifier else {
                    throw SecureEnclaveBindingStoreError.invalidManifest
                }
            }
        case .deletion(let journal):
            try validate(journal.binding)
            guard journal.deletedIdentifiers.isSubset(of: [
                journal.binding.signing.id,
                journal.binding.encryption.id,
            ]) else {
                throw SecureEnclaveBindingStoreError.invalidManifest
            }
        }
    }

    private func validate(_ binding: SecureEnclaveBindingRecord) throws {
        for fingerprint in [
            binding.certificateFingerprint,
            binding.signingComponentFingerprint,
            binding.encryptionComponentFingerprint,
        ] {
            guard fingerprint.count == 40,
                  fingerprint.allSatisfy({ $0.isASCII && $0.isHexDigit && !$0.isLowercase }) else {
                throw SecureEnclaveBindingStoreError.invalidManifest
            }
        }
        try validateIdentifier(binding.signing.id)
        try validateIdentifier(binding.encryption.id)
        guard binding.signing.id != binding.encryption.id,
              binding.signing.usage == .signing,
              binding.encryption.usage == .keyAgreement,
              !binding.publicCertificate.isEmpty,
              binding.publicCertificate.count <= 4 * 1024 * 1024 else {
            throw SecureEnclaveBindingStoreError.invalidManifest
        }
        for reference in [binding.signing, binding.encryption] {
            guard reference.publicKeyX963.count == 65,
                  reference.publicKeyX963.first == 0x04,
                  (try? P256.Signing.PublicKey(x963Representation: reference.publicKeyX963)) != nil else {
                throw SecureEnclaveBindingStoreError.invalidManifest
            }
        }
    }

    private func validateIdentifier(_ identifier: String) throws {
        guard !identifier.isEmpty, identifier.count <= 1_024,
              identifier.utf8.allSatisfy({ $0 >= 0x20 && $0 != 0x7F }) else {
            throw SecureEnclaveBindingStoreError.invalidManifest
        }
    }
}
