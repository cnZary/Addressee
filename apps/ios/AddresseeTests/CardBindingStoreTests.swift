import XCTest
@testable import Addressee

final class CardBindingStoreTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CardBindingStoreTests-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testDiskRoundTripPreservesPublicAssociationsOnly() async throws {
        let store = CardBindingStore(directory: directory)
        let first = try binding(certificate: "A", signing: "1", decryption: "2")
        let second = try binding(certificate: "B", signing: "3", decryption: "4")
        try await store.insert(second)
        try await store.insert(first)

        let restored = CardBindingStore(directory: directory)
        let bindings = try await restored.bindings()
        XCTAssertEqual(bindings, [first, second])
        XCTAssertEqual(bindings.map(\.registration), [first.registration, second.registration])
        try assertPublicManifest(expectedCount: 2)

        try await restored.remove(certificateFingerprint: first.certificateFingerprint)
        let afterRemoval = CardBindingStore(directory: directory)
        try await assertEqual(try await afterRemoval.bindings(), [second])
    }

    func testLegacyTransportFieldsMigrateWithoutConstrainingTheAssociation() async throws {
        let expected = try binding(certificate: "A", signing: "1", decryption: "2")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let manifest: [String: Any] = [
            "formatVersion": 1,
            "bindings": [[
                "certificateFingerprint": expected.certificateFingerprint,
                "identity": [
                    "manufacturer": expected.identity.manufacturer,
                    "serial": expected.identity.serial,
                    "version": expected.identity.version,
                ],
                "signingComponent": expected.signingComponent as Any,
                "decryptionComponent": expected.decryptionComponent as Any,
                "method": "usb",
                "readerName": "Legacy Explicit Reader",
            ]],
        ]
        try JSONSerialization.data(withJSONObject: manifest)
            .write(to: directory.appendingPathComponent("manifest.json"))

        let store = CardBindingStore(directory: directory)
        let restored = try await store.bindings()
        XCTAssertEqual(restored, [expected])
        try await store.replaceAll(restored)
        try assertPublicManifest(expectedCount: 1)
    }

    func testDuplicateAndInvalidAssociationsAreRejected() async throws {
        let store = CardBindingStore.inMemory()
        let original = try binding(certificate: "A", signing: "1", decryption: "2")
        try await store.insert(original)
        do {
            try await store.insert(original)
            XCTFail("A duplicate certificate association must be rejected")
        } catch {
            XCTAssertEqual(error as? CardBindingStoreError, .conflict)
        }
        do {
            try await store.insert(try binding(certificate: "A", signing: "3", decryption: "4"))
            XCTFail("A conflicting association must not replace the original")
        } catch {
            XCTAssertEqual(error as? CardBindingStoreError, .conflict)
        }
        try await assertEqual(try await store.bindings(), [original])

        var authentication = original.registration
        authentication.components[0].slot = .authentication
        XCTAssertThrowsError(try CardBinding(registration: authentication))
        var repeated = original.registration
        repeated.components[1].componentFingerprint = repeated.components[0].componentFingerprint
        XCTAssertThrowsError(try CardBinding(registration: repeated))
        var duplicateSlot = original.registration
        duplicateSlot.components[1].slot = .signing
        XCTAssertThrowsError(try CardBinding(registration: duplicateSlot))
    }

    func testMalformedManifestDoesNotBecomeAnEmptyStore() async throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let manifest: [String: Any] = [
            "formatVersion": 1,
            "bindings": [[
                "certificateFingerprint": "not-a-fingerprint",
                "identity": ["manufacturer": 65_536, "serial": 1, "version": 0x0304],
                "signingComponent": String(repeating: "1", count: 40),
                "method": "nfc",
            ]],
        ]
        let data = try JSONSerialization.data(withJSONObject: manifest)
        try data.write(to: directory.appendingPathComponent("manifest.json"))

        let store = CardBindingStore(directory: directory)
        do {
            _ = try await store.bindings()
            XCTFail("Malformed persisted state must be surfaced")
        } catch {
            XCTAssertEqual(error as? CardBindingStoreError, .invalidManifest)
        }
        let untouched = try Data(contentsOf: directory.appendingPathComponent("manifest.json"))
        XCTAssertEqual(untouched, data)
    }

    func testBindingLimitDoesNotDiscardExistingState() async throws {
        let store = CardBindingStore.inMemory()
        let original = try binding(certificate: "A", signing: "1", decryption: "2")
        try await store.insert(original)
        let excessive = try (0...64).map { index in
            try binding(
                certificate: String(format: "%X", index + 1),
                signing: "1",
                decryption: "2"
            )
        }
        do {
            try await store.replaceAll(excessive)
            XCTFail("An excessive association manifest must be rejected")
        } catch {
            XCTAssertEqual(error as? CardBindingStoreError, .invalidManifest)
        }
        try await assertEqual(try await store.bindings(), [original])
    }

    private func assertPublicManifest(expectedCount: Int) throws {
        let data = try Data(contentsOf: directory.appendingPathComponent("manifest.json"))
        let manifest = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        XCTAssertEqual(manifest["formatVersion"] as? Int, 1)
        let records = try XCTUnwrap(manifest["bindings"] as? [[String: Any]])
        XCTAssertEqual(records.count, expectedCount)
        let publicFields: Set<String> = [
            "certificateFingerprint", "identity", "signingComponent", "decryptionComponent",
        ]
        for record in records {
            XCTAssertEqual(Set(record.keys), publicFields)
            XCTAssertNil(record["pin"])
            XCTAssertNil(record["password"])
            let identity = try XCTUnwrap(record["identity"] as? [String: Any])
            XCTAssertEqual(Set(identity.keys), ["manufacturer", "serial", "version"])
        }
    }

    private func assertEqual<T: Equatable>(
        _ actual: @autoclosure () async throws -> T,
        _ expected: @autoclosure () async throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async rethrows {
        let actual = try await actual()
        let expected = try await expected()
        XCTAssertEqual(actual, expected, file: file, line: line)
    }

    private func binding(
        certificate: String,
        signing: String,
        decryption: String
    ) throws -> CardBinding {
        let fingerprint = String(String(repeating: certificate, count: 40).prefix(40))
        do {
            return try CardBinding(registration: CardRegistrationFfi(
                certificateFingerprint: fingerprint,
                identity: CardIdentityFfi(
                    manufacturer: 0xF1D0,
                    serial: 0x10203040,
                    version: 0x0304
                ),
                components: [
                    CardComponentBindingFfi(
                        slot: .signing,
                        componentFingerprint: String(repeating: signing, count: 40)
                    ),
                    CardComponentBindingFfi(
                        slot: .decryption,
                        componentFingerprint: String(repeating: decryption, count: 40)
                    ),
                ]
            ))
        } catch {
            XCTFail("Invalid synthetic association: certificate seed \(certificate)")
            throw error
        }
    }
}
