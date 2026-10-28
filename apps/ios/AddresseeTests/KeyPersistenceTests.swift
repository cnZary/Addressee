import OpenPGPKeyProvider
import XCTest
@testable import Addressee

@MainActor
final class KeyPersistenceTests: XCTestCase {
    private var directory: URL!
    private var envelopeStore: SoftwareKeyEnvelopeStore!
    private var persistence: SoftwareKeyPersistence!
    private var secretFingerprints = Set<String>()

    override func setUp() async throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("KeyPersistenceTests-\(UUID().uuidString)", isDirectory: true)
        envelopeStore = SoftwareKeyEnvelopeStore(service: "app.addressee.tests.\(UUID().uuidString)")
        persistence = SoftwareKeyPersistence(
            store: SoftwareKeyFileStore(directory: directory, envelopeStore: envelopeStore)
        )
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: directory)
        for fingerprint in secretFingerprints {
            try? await envelopeStore.deleteWrappingKey(identifier: fingerprint)
        }
    }

    func testGenerateRestoreSignAndDeleteAcrossModelInstances() async throws {
        let first = OpenPgpApplicationModel(persistence: persistence)
        await first.load()
        let generated = try await first.generate(
            profile: .modernV6,
            userID: "Persistence <persistence@example.invalid>",
            password: "persistence-test-only",
            exportPolicy: .disabled
        )
        let fingerprint = generated.summary.fingerprint
        secretFingerprints.insert(fingerprint)

        let second = OpenPgpApplicationModel(persistence: persistence)
        await second.load()
        XCTAssertNil(second.errorMessage)
        XCTAssertEqual(second.keys.map(\.fingerprint), [fingerprint])
        let summary = try XCTUnwrap(second.keys.first)
        XCTAssertEqual(summary.privateExportPolicy, .disabled)
        XCTAssertEqual(summary.storage, .softwareSecret)

        let at = UInt64(Date().timeIntervalSince1970) + 60
        let signature = try await second.signDetached(
            signingKey: fingerprint,
            password: "persistence-test-only",
            atUnixSeconds: at,
            data: Data("persisted".utf8),
            format: .armored
        )
        let verified = try await second.verifyDetached(
            data: Data("persisted".utf8),
            signature: signature.artifact,
            atUnixSeconds: at
        )
        XCTAssertEqual(verified.status, .valid)

        do {
            _ = try await second.exportPrivate(fingerprint: fingerprint, format: .armored)
            XCTFail("Private export must remain disabled after restore")
        } catch {}

        try await second.removeKey(fingerprint: fingerprint)
        XCTAssertTrue(second.keys.isEmpty)

        let third = OpenPgpApplicationModel(persistence: persistence)
        await third.load()
        XCTAssertTrue(third.keys.isEmpty)
    }

    func testPublicCertificatePersistsWithoutSecretMaterial() async throws {
        let generator = OpenPgpApplicationModel()
        await generator.load()
        let generated = try await generator.generate(
            profile: .modernV6,
            userID: "Public Persistence <public@example.invalid>",
            password: "public-test-only",
            exportPolicy: .disabled
        )

        let first = OpenPgpApplicationModel(persistence: persistence)
        await first.load()
        _ = try await first.importPublic(generated.publicCertificate)

        let second = OpenPgpApplicationModel(persistence: persistence)
        await second.load()
        XCTAssertNil(second.errorMessage)
        XCTAssertEqual(second.keys.map(\.fingerprint), [generated.summary.fingerprint])
        XCTAssertEqual(second.keys.first?.storage, .publicOnly)
        XCTAssertTrue(second.signingKeys.isEmpty)

        try await second.removeKey(fingerprint: generated.summary.fingerprint)
        let third = OpenPgpApplicationModel(persistence: persistence)
        await third.load()
        XCTAssertTrue(third.keys.isEmpty)
    }
}
