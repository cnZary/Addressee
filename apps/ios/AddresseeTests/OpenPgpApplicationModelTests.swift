import XCTest
@testable import Addressee

@MainActor
final class OpenPgpApplicationModelTests: XCTestCase {
    func testModernGenerationPublicExportAndReimport() async throws {
        let model = OpenPgpApplicationModel()
        await model.load()
        XCTAssertEqual(model.availableGenerationProfiles.count, 9)

        let generated = try await model.generate(
            profile: .modernV6,
            userID: "Model Test <model@example.invalid>",
            password: "model-test-only",
            exportPolicy: .disabled
        )
        XCTAssertEqual(generated.summary.fingerprint.count, 64)
        XCTAssertEqual(generated.summary.subkeys.count, 2)
        XCTAssertEqual(model.keys.count, 1)
        XCTAssertEqual(model.keys[0].displayName, "Model Test <model@example.invalid>")

        let publicKey = try await model.exportPublic(
            fingerprint: generated.summary.fingerprint,
            format: .armored
        )
        let importingModel = OpenPgpApplicationModel()
        await importingModel.load()
        let imported = try await importingModel.importPublic(publicKey)
        XCTAssertEqual(imported.summary.fingerprint, generated.summary.fingerprint)
        XCTAssertEqual(importingModel.keys.count, 1)
        XCTAssertFalse(imported.summary.isSecret)

        do {
            _ = try await model.exportPrivate(
                fingerprint: generated.summary.fingerprint,
                format: .armored
            )
            XCTFail("Expected export-disabled rejection")
        } catch let error as AddresseeError {
            XCTAssertEqual(error, .ExportDisabled)
        }
    }

    func testEmptyPasswordIsRejectedWithoutCreatingAKey() async throws {
        let model = OpenPgpApplicationModel()
        await model.load()

        do {
            _ = try await model.generate(
                profile: .modernV6,
                userID: "Model Test",
                password: "",
                exportPolicy: .disabled
            )
            XCTFail("Expected empty-password rejection")
        } catch let error as AddresseeError {
            XCTAssertEqual(error, .EmptyPassword)
        }
        XCTAssertTrue(model.keys.isEmpty)
    }

    func testRemoteKeyUnavailableUsesLocalizedMessage() {
        let message = ErrorPresenter.message(for: AddresseeError.RemoteKeyUnavailable)
        XCTAssertEqual(
            message,
            NSLocalizedString("error.remoteKeyUnavailable", comment: "")
        )
        XCTAssertNotEqual(message, "error.remoteKeyUnavailable")
    }

    func testCardRegistrationChangesKeySelectionWithoutChangingStorage() async throws {
        let softwareModel = OpenPgpApplicationModel()
        await softwareModel.load()
        let generated = try await softwareModel.generate(
            profile: .nistP256v4,
            userID: "Card Selection <card-selection@example.invalid>",
            password: "card-selection-test-only",
            exportPolicy: .disabled
        )
        let publicCertificate = try await softwareModel.exportPublic(
            fingerprint: generated.summary.fingerprint,
            format: .binary
        )
        let sessions = MockCardSessions()
        let defaultsSuite = "OpenPgpApplicationModelTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: defaultsSuite))
        defer { defaults.removePersistentDomain(forName: defaultsSuite) }
        let connectionSettings = HardwareConnectionSettings(defaults: defaults)
        let cardModel = OpenPgpApplicationModel(
            cardSessions: sessions,
            hardwareConnectionSettings: connectionSettings
        )
        await cardModel.load()
        _ = try await cardModel.importPublic(publicCertificate)
        let fingerprint = generated.summary.fingerprint
        XCTAssertTrue(cardModel.signingKeys.isEmpty)
        XCTAssertTrue(cardModel.decryptionKeys.isEmpty)
        XCTAssertEqual(cardModel.keys.first?.storage, .publicOnly)

        let signing: KeyMetadataSummary = try XCTUnwrap(
            generated.summary.subkeys.first(where: { $0.keyFlags.sign })
        )
        let decryption: KeyMetadataSummary = try XCTUnwrap(
            generated.summary.subkeys.first(where: {
                $0.keyFlags.encryptCommunications || $0.keyFlags.encryptStorage
            })
        )
        let registration = CardRegistrationFfi(
            certificateFingerprint: fingerprint,
            identity: CardIdentityFfi(manufacturer: 0xFFFF, serial: 0x01020304, version: 0x0304),
            components: [
                CardComponentBindingFfi(slot: .signing, componentFingerprint: signing.fingerprint),
                CardComponentBindingFfi(slot: .decryption, componentFingerprint: decryption.fingerprint),
            ]
        )
        sessions.activate(registration)

        XCTAssertTrue(cardModel.signingKeys.contains { $0.fingerprint == fingerprint })
        XCTAssertTrue(cardModel.decryptionKeys.contains { $0.fingerprint == fingerprint })
        XCTAssertFalse(cardModel.isSoftwarePasswordRequired(fingerprint: fingerprint))
        XCTAssertTrue(cardModel.canSubmitPrivateKeyOperation(fingerprint: fingerprint, password: ""))
        let automaticUSB = CardConnectionSelection(method: .usb)
        XCTAssertTrue(cardModel.canSubmitPrivateKeyOperation(
            fingerprint: fingerprint,
            password: "",
            connection: automaticUSB
        ))
        connectionSettings.allowsMultipleHardwareKeys = true
        XCTAssertFalse(cardModel.canSubmitPrivateKeyOperation(
            fingerprint: fingerprint,
            password: "",
            connection: automaticUSB
        ))
        XCTAssertTrue(cardModel.canSubmitPrivateKeyOperation(
            fingerprint: fingerprint,
            password: "",
            connection: CardConnectionSelection(method: .usb, readerName: "Explicit USB Reader")
        ))
        XCTAssertEqual(cardModel.keys.first?.storage, .publicOnly)
        XCTAssertFalse(softwareModel.canSubmitPrivateKeyOperation(fingerprint: fingerprint, password: ""))
        XCTAssertTrue(softwareModel.canSubmitPrivateKeyOperation(
            fingerprint: fingerprint,
            password: "card-selection-test-only"
        ))

        try await sessions.disconnect(certificateFingerprint: fingerprint)
        XCTAssertTrue(cardModel.signingKeys.isEmpty)
        XCTAssertTrue(cardModel.decryptionKeys.isEmpty)
        XCTAssertFalse(cardModel.canSubmitPrivateKeyOperation(fingerprint: fingerprint, password: ""))
    }

    func testStandaloneCardInspectionDoesNotRequireOrChangeAssociations() async throws {
        let sessions = MockCardSessions()
        let model = OpenPgpApplicationModel(cardSessions: sessions)
        await model.load()
        let registration = CardRegistrationFfi(
            certificateFingerprint: String(repeating: "A", count: 40),
            identity: CardIdentityFfi(
                manufacturer: 0xF1D0,
                serial: 0x10203040,
                version: 0x0304
            ),
            components: []
        )
        sessions.activate(registration)

        let information = try await model.inspectHardware(
            identity: registration.identity,
            connection: CardConnectionSelection()
        )
        XCTAssertEqual(information.identity, registration.identity)
        XCTAssertEqual(information.slots.count, 3)
        XCTAssertEqual(information.slots[0].touchPolicy, "Off")
        XCTAssertEqual(sessions.lastManagementExpectedIdentity, registration.identity)
        XCTAssertTrue(model.keys.isEmpty)
        XCTAssertEqual(model.cardRegistrations, [registration])
    }
}

@MainActor
private final class MockCardSessions: CardSessionManaging {
    private(set) var registrations: [CardRegistrationFfi] = []
    private(set) var lastManagementExpectedIdentity: CardIdentityFfi?
    var onChange: (([CardRegistrationFfi]) -> Void)?

    func activate(_ registration: CardRegistrationFfi) {
        registrations = [registration]
        onChange?(registrations)
    }

    func restore() async throws {}

    func readerNames() async throws -> [String] { [] }

    func preferredConnection(for fingerprint: String) -> CardConnectionSelection {
        CardConnectionSelection()
    }

    func connect(
        certificateFingerprint: String,
        signingComponent: String?,
        decryptionComponent: String?,
        method: CardConnectionMethod,
        readerName: String?
    ) async throws -> CardRegistrationFfi {
        throw AddresseeError.UnsupportedOperation
    }

    func disconnect(certificateFingerprint: String) async throws {
        registrations.removeAll { $0.certificateFingerprint == certificateFingerprint }
        onChange?(registrations)
    }

    func withCardSession<T: Sendable>(
        certificateFingerprint: String,
        operation: PrivateKeyOperation,
        connection: CardConnectionSelection,
        body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await body()
    }

    func withUnboundCardManagementSession<T: Sendable>(
        expectedIdentity: CardIdentityFfi?,
        connection: CardConnectionSelection,
        operation: @escaping @Sendable (OpenPgpCardManagementSession) async throws -> T
    ) async throws -> T {
        lastManagementExpectedIdentity = expectedIdentity
        let identity = expectedIdentity ?? registrations.first?.identity ?? CardIdentityFfi(
            manufacturer: 0xF1D0,
            serial: 0x10203040,
            version: 0x0304
        )
        let bridge = CardTransportBridge(
            transport: ScriptedManagementTransport(),
            capabilities: .shortOnly
        )
        let session = try await Task.detached(priority: .userInitiated) {
            try OpenPgpCardManagementSession.connect(identity: identity, transport: bridge)
        }.value
        return try await Task.detached(priority: .userInitiated) {
            try await operation(session)
        }.value
    }
}
