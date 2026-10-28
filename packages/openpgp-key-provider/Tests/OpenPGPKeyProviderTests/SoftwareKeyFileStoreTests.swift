import Foundation
import XCTest
@testable import OpenPGPKeyProvider

final class SoftwareKeyFileStoreTests: XCTestCase {
    private var directory: URL!
    private var envelopeStore: SoftwareKeyEnvelopeStore!
    private var store: SoftwareKeyFileStore!

    private let secretFingerprint = String(repeating: "A", count: 40)
    private let publicFingerprint = String(repeating: "B", count: 40)

    override func setUp() async throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SoftwareKeyFileStoreTests-\(UUID().uuidString)", isDirectory: true)
        envelopeStore = SoftwareKeyEnvelopeStore(service: "app.addressee.tests.\(UUID().uuidString)")
        store = SoftwareKeyFileStore(directory: directory, envelopeStore: envelopeStore)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: directory)
        if ProcessInfo.processInfo.environment["ADDRESSEE_KEYCHAIN_TESTS"] == "1" {
            try? await envelopeStore.deleteWrappingKey(identifier: secretFingerprint)
            try? await envelopeStore.deleteWrappingKey(identifier: publicFingerprint)
        }
    }

    func testValidationRejectsInvalidRecordsBeforeWriting() async throws {
        let validSecret = StoredSoftwareKey(
            fingerprint: secretFingerprint,
            exportPolicy: .allowed,
            publicCertificate: Data("public".utf8),
            protectedSecret: Data("secret".utf8)
        )
        let invalid: [StoredSoftwareKey] = [
            StoredSoftwareKey(
                fingerprint: "not-hex",
                exportPolicy: .allowed,
                publicCertificate: Data("public".utf8),
                protectedSecret: Data("secret".utf8)
            ),
            StoredSoftwareKey(
                fingerprint: secretFingerprint,
                exportPolicy: .hardwareNonExportable,
                publicCertificate: Data("public".utf8),
                protectedSecret: Data("secret".utf8)
            ),
            StoredSoftwareKey(
                fingerprint: secretFingerprint,
                exportPolicy: .allowed,
                publicCertificate: Data("public".utf8)
            ),
            StoredSoftwareKey(
                fingerprint: publicFingerprint,
                exportPolicy: .allowed,
                publicCertificate: Data("public".utf8)
            ),
        ]
        for record in invalid {
            do {
                try await store.save([record])
                XCTFail("Expected invalid record rejection for \(record.exportPolicy)")
            } catch is SoftwareKeyFileStoreError {}
        }
        do {
            try await store.save([validSecret, validSecret])
            XCTFail("Expected duplicate fingerprint rejection")
        } catch is SoftwareKeyFileStoreError {}
        let loaded = try await store.load()
        XCTAssertTrue(loaded.isEmpty)
    }

    func testRoundTripReplacementAndDeletion() async throws {
        try requireKeychainTests()
        let secret = StoredSoftwareKey(
            fingerprint: secretFingerprint,
            exportPolicy: .applicationDisabled,
            publicCertificate: Data("public certificate".utf8),
            protectedSecret: Data("protected secret".utf8)
        )
        let publicOnly = StoredSoftwareKey(
            fingerprint: publicFingerprint,
            exportPolicy: .notApplicable,
            publicCertificate: Data("public only".utf8)
        )
        try await store.save([secret, publicOnly])
        let loaded = try await store.load()
        XCTAssertEqual(loaded, [publicOnly, secret].sorted { $0.fingerprint < $1.fingerprint })

        let fileURL = directory.appendingPathComponent("\(secretFingerprint).json")
        var object = try JSONSerialization.jsonObject(with: Data(contentsOf: fileURL)) as! [String: Any]
        var envelope = object["protectedSecret"] as! [String: Any]
        var payload = envelope["payload"] as! String
        payload.replaceSubrange(payload.startIndex..<payload.index(after: payload.startIndex), with: "A")
        envelope["payload"] = payload
        object["protectedSecret"] = envelope
        let tampered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        try tampered.write(to: fileURL)
        do {
            _ = try await store.load()
            XCTFail("Expected tamper rejection")
        } catch {}

        try await store.save([publicOnly])
        let replaced = try await store.load()
        XCTAssertEqual(replaced, [publicOnly])
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))

        try await store.delete(fingerprint: publicFingerprint)
        let remaining = try await store.load()
        XCTAssertTrue(remaining.isEmpty)
    }

    func testDeleteRejectsPathTraversalBeforeTouchingFiles() async throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let sibling = directory.deletingLastPathComponent()
            .appendingPathComponent("outside-\(UUID().uuidString).json")
        try Data("do not delete".utf8).write(to: sibling)
        defer { try? FileManager.default.removeItem(at: sibling) }

        do {
            try await store.delete(fingerprint: "../\(sibling.deletingPathExtension().lastPathComponent)")
            XCTFail("Expected invalid fingerprint rejection")
        } catch SoftwareKeyFileStoreError.invalidRecord {}
        XCTAssertEqual(try Data(contentsOf: sibling), Data("do not delete".utf8))
    }

    func testLoadRejectsFilenameAndFingerprintMismatch() async throws {
        let publicOnly = StoredSoftwareKey(
            fingerprint: publicFingerprint,
            exportPolicy: .notApplicable,
            publicCertificate: Data("public only".utf8)
        )
        try await store.save([publicOnly])
        try FileManager.default.moveItem(
            at: directory.appendingPathComponent("\(publicFingerprint).json"),
            to: directory.appendingPathComponent("\(secretFingerprint).json")
        )

        do {
            _ = try await store.load()
            XCTFail("Expected record filename mismatch rejection")
        } catch SoftwareKeyFileStoreError.invalidStoreFile(let name) {
            XCTAssertEqual(name, "\(secretFingerprint).json")
        }
    }

    private func requireKeychainTests() throws {
        guard ProcessInfo.processInfo.environment["ADDRESSEE_KEYCHAIN_TESTS"] == "1" else {
            throw XCTSkip("Keychain integration tests are opt-in")
        }
    }
}
