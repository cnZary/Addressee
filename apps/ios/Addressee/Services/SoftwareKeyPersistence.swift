import Foundation
import OpenPGPKeyProvider

/// Maps engine storage snapshots to the sealed file store. Secret material is
/// never written unprotected and private export policy is preserved verbatim.
struct SoftwareKeyPersistence: Sendable {
    let store: SoftwareKeyFileStore

    static func live() -> SoftwareKeyPersistence {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return SoftwareKeyPersistence(
            store: SoftwareKeyFileStore(
                directory: base.appendingPathComponent("Addressee/KeyRecords", isDirectory: true)
            )
        )
    }

    func load() async throws -> [StorageRecordFfi] {
        try await store.load().map { key in
            StorageRecordFfi(
                fingerprint: key.fingerprint,
                protectedSecret: key.protectedSecret,
                publicCertificate: key.publicCertificate,
                exportPolicy: exportPolicy(for: key.exportPolicy)
            )
        }
    }

    func save(_ records: [StorageRecordFfi]) async throws {
        try await store.save(records.map { record in
            StoredSoftwareKey(
                fingerprint: record.fingerprint,
                exportPolicy: exportPolicy(for: record.exportPolicy),
                publicCertificate: record.publicCertificate,
                protectedSecret: record.protectedSecret
            )
        })
    }

    private func exportPolicy(for policy: PrivateKeyExportPolicy) -> ExportPolicyFfi? {
        switch policy {
        case .allowed: .allowed
        case .applicationDisabled: .disabled
        case .hardwareNonExportable, .notApplicable: nil
        }
    }

    private func exportPolicy(for policy: ExportPolicyFfi?) -> PrivateKeyExportPolicy {
        switch policy {
        case .allowed: .allowed
        case .disabled: .applicationDisabled
        case .notApplicable, nil: .notApplicable
        }
    }
}
