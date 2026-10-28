import Foundation

public struct StoredSoftwareKey: Equatable, Sendable {
    public var fingerprint: String
    public var exportPolicy: PrivateKeyExportPolicy
    public var publicCertificate: Data
    public var protectedSecret: Data?

    public init(
        fingerprint: String,
        exportPolicy: PrivateKeyExportPolicy,
        publicCertificate: Data,
        protectedSecret: Data? = nil
    ) {
        self.fingerprint = fingerprint
        self.exportPolicy = exportPolicy
        self.publicCertificate = publicCertificate
        self.protectedSecret = protectedSecret
    }

    var isSecret: Bool {
        protectedSecret != nil
    }
}

public enum SoftwareKeyFileStoreError: Error, Equatable, Sendable {
    case invalidRecord(String)
    case invalidStoreFile(String)
    case io(String)
}

/// Persists software key records as versioned files. Secret material is always
/// sealed by `SoftwareKeyEnvelopeStore`; only public certificates and metadata
/// appear in plaintext. Saving replaces the whole record set so deletions can
/// never leave a stale key behind.
public actor SoftwareKeyFileStore {
    private let directory: URL
    private let envelopeStore: SoftwareKeyEnvelopeStore
    private let fileManager: FileManager

    public init(
        directory: URL,
        envelopeStore: SoftwareKeyEnvelopeStore = SoftwareKeyEnvelopeStore(),
        fileManager: FileManager = .default
    ) {
        self.directory = directory
        self.envelopeStore = envelopeStore
        self.fileManager = fileManager
    }

    public func load() async throws -> [StoredSoftwareKey] {
        guard let names = try? fileManager.contentsOfDirectory(atPath: directory.path) else {
            return []
        }
        var records: [StoredSoftwareKey] = []
        for name in names where name.hasSuffix(".json") {
            let url = directory.appendingPathComponent(name, isDirectory: false)
            let data: Data
            do {
                data = try Data(contentsOf: url)
            } catch {
                throw SoftwareKeyFileStoreError.io("read \(name) failed")
            }
            let file: RecordFile
            do {
                file = try JSONDecoder().decode(RecordFile.self, from: data)
            } catch {
                throw SoftwareKeyFileStoreError.invalidStoreFile(name)
            }
            records.append(try await record(from: file, name: name))
        }
        return records.sorted { $0.fingerprint < $1.fingerprint }
    }

    public func save(_ keys: [StoredSoftwareKey]) async throws {
        var seen = Set<String>()
        for key in keys {
            guard seen.insert(key.fingerprint).inserted else {
                throw SoftwareKeyFileStoreError.invalidRecord("duplicate fingerprint")
            }
            try validate(key)
        }
        do {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            throw SoftwareKeyFileStoreError.io("create store directory failed")
        }
        #if os(iOS)
        do {
            try fileManager.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: directory.path
            )
        } catch {
            throw SoftwareKeyFileStoreError.io("protect store directory failed")
        }
        #endif

        for key in keys {
            let file = try await recordFile(from: key)
            let data: Data
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys]
                data = try encoder.encode(file)
            } catch {
                throw SoftwareKeyFileStoreError.invalidRecord("encode \(key.fingerprint) failed")
            }
            let url = fileURL(for: key.fingerprint)
            do {
                try data.write(to: url, options: .atomic)
            } catch {
                throw SoftwareKeyFileStoreError.io("write \(key.fingerprint) failed")
            }
            #if os(iOS)
            do {
                try fileManager.setAttributes(
                    [.protectionKey: FileProtectionType.complete],
                    ofItemAtPath: url.path
                )
            } catch {
                throw SoftwareKeyFileStoreError.io("protect \(key.fingerprint) failed")
            }
            #endif
        }

        let keep = Set(keys.map(\.fingerprint))
        let names = (try? fileManager.contentsOfDirectory(atPath: directory.path)) ?? []
        for name in names where name.hasSuffix(".json") {
            let fingerprint = String(name.dropLast(".json".count))
            guard !keep.contains(fingerprint) else { continue }
            try? fileManager.removeItem(at: directory.appendingPathComponent(name))
            try await envelopeStore.deleteWrappingKey(identifier: fingerprint)
        }
    }

    public func delete(fingerprint: String) async throws {
        try validateFingerprint(fingerprint)
        let url = fileURL(for: fingerprint)
        if fileManager.fileExists(atPath: url.path) {
            do {
                try fileManager.removeItem(at: url)
            } catch {
                throw SoftwareKeyFileStoreError.io("delete \(fingerprint) failed")
            }
        }
        try await envelopeStore.deleteWrappingKey(identifier: fingerprint)
    }

    private func fileURL(for fingerprint: String) -> URL {
        directory.appendingPathComponent("\(fingerprint).json", isDirectory: false)
    }

    private func validate(_ key: StoredSoftwareKey) throws {
        try validateFingerprint(key.fingerprint)
        if key.isSecret {
            guard key.exportPolicy == .allowed || key.exportPolicy == .applicationDisabled else {
                throw SoftwareKeyFileStoreError.invalidRecord("secret export policy")
            }
            guard let secret = key.protectedSecret, !secret.isEmpty else {
                throw SoftwareKeyFileStoreError.invalidRecord("missing protected secret")
            }
        } else if key.exportPolicy != .notApplicable {
            throw SoftwareKeyFileStoreError.invalidRecord("public-only export policy")
        }
        guard !key.publicCertificate.isEmpty else {
            throw SoftwareKeyFileStoreError.invalidRecord("missing public certificate")
        }
    }

    private func validateFingerprint(_ fingerprint: String) throws {
        guard [32, 40, 64].contains(fingerprint.count),
              fingerprint.allSatisfy({ $0.isASCII && $0.isHexDigit && !$0.isLowercase })
        else {
            throw SoftwareKeyFileStoreError.invalidRecord("fingerprint format")
        }
    }

    private func recordFile(from key: StoredSoftwareKey) async throws -> RecordFile {
        var envelope: SoftwareKeyEnvelope?
        if let secret = key.protectedSecret {
            envelope = try await envelopeStore.seal(
                secret,
                identifier: key.fingerprint,
                exportPolicy: key.exportPolicy
            )
        }
        return RecordFile(
            formatVersion: 1,
            fingerprint: key.fingerprint,
            exportPolicy: key.exportPolicy,
            publicCertificate: key.publicCertificate,
            protectedSecret: envelope
        )
    }

    private func record(from file: RecordFile, name: String) async throws -> StoredSoftwareKey {
        guard file.formatVersion == 1,
              name == "\(file.fingerprint).json"
        else {
            throw SoftwareKeyFileStoreError.invalidStoreFile(name)
        }
        let protectedSecret: Data?
        if let envelope = file.protectedSecret {
            protectedSecret = try await envelopeStore.unseal(
                envelope,
                identifier: file.fingerprint,
                exportPolicy: file.exportPolicy
            )
        } else {
            protectedSecret = nil
        }
        let key = StoredSoftwareKey(
            fingerprint: file.fingerprint,
            exportPolicy: file.exportPolicy,
            publicCertificate: file.publicCertificate,
            protectedSecret: protectedSecret
        )
        do {
            try validate(key)
        } catch {
            throw SoftwareKeyFileStoreError.invalidStoreFile(name)
        }
        return key
    }
}

private struct RecordFile: Codable {
    var formatVersion: Int
    var fingerprint: String
    var exportPolicy: PrivateKeyExportPolicy
    var publicCertificate: Data
    var protectedSecret: SoftwareKeyEnvelope?
}
