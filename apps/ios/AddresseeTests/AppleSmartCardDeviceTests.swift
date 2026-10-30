import AppleSmartCardTransport
import Foundation
import XCTest
@testable import Addressee

#if canImport(CryptoTokenKit)
@preconcurrency import CryptoTokenKit
#endif

private actor CardTransportObservation {
    private(set) var opened = 0
    private(set) var closed = 0
    private(set) var successfulCloses = 0
    private(set) var failures = 0

    func recordOpen() {
        opened += 1
    }

    func recordClose(success: Bool) {
        closed += 1
        if success { successfulCloses += 1 }
    }

    func recordFailure() {
        failures += 1
    }

    func snapshot() -> (opened: Int, closed: Int, successfulCloses: Int, failures: Int) {
        (opened, closed, successfulCloses, failures)
    }
}

private struct ObservedCardTransportOpening: CardTransportOpening {
    let observation: CardTransportObservation
    private let base = CardTransportFactory()

    func readerNames() async throws -> [String] {
        try await base.readerNames()
    }

    func connect(
        method: CardConnectionMethod,
        readerName: String?,
        alertMessage: String
    ) async throws -> ConnectedCardTransport {
        do {
            let connection = try await base.connect(
                method: method,
                readerName: readerName,
                alertMessage: alertMessage
            )
            await observation.recordOpen()
            return ConnectedCardTransport(
                transport: connection.transport,
                capabilities: connection.capabilities,
                onClose: { successMessage in
                    do {
                        try await connection.close(successMessage: successMessage)
                        await observation.recordClose(success: successMessage != nil)
                    } catch {
                        await observation.recordFailure()
                        throw error
                    }
                }
            )
        } catch {
            await observation.recordFailure()
            throw error
        }
    }
}

@MainActor
final class AppleSmartCardDeviceTests: XCTestCase {
    func testReadOnlyTransportAvailability() async throws {
        guard ProcessInfo.processInfo.environment["ADDRESSEE_CARD_API_TESTS"] == "1" else {
            throw XCTSkip("Physical Apple smart card API probes require explicit opt-in")
        }
        #if targetEnvironment(simulator)
        throw XCTSkip("This probe requires a physical iOS device")
        #else
        var report: [String: Any] = [
            "schemaVersion": 1,
            "nfcReaderAvailable": CardTransportFactory.nfcIsAvailable(),
            "observationOnly": true,
            "nfcSessionStarted": false,
            "apduTransmitted": false,
        ]
        #if canImport(CryptoTokenKit)
        report["cryptoTokenKitManagerAvailable"] = TKSmartCardSlotManager.default != nil
        do {
            let readerNames = try await CardTransportFactory().readerNames()
            report["readerNames"] = readerNames
            report["readerCount"] = readerNames.count
        } catch {
            let errorType = String(reflecting: type(of: error))
            let error = error as NSError
            report["readerError"] = [
                "type": errorType,
                "domain": error.domain,
                "code": error.code,
            ]
        }
        #else
        report["cryptoTokenKitManagerAvailable"] = false
        report["readerError"] = ["type": "frameworkUnavailable"]
        #endif
        let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
        let attachment = XCTAttachment(data: data, uniformTypeIdentifier: "public.json")
        attachment.name = "apple-card-api-probe.json"
        attachment.lifetime = .keepAlways
        add(attachment)
        #endif
    }

    func testUSBAssociationAndCleanClose() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["ADDRESSEE_CARD_USB_TESTS"] == "1" else {
            throw XCTSkip("Physical USB card association requires an explicit fixture and opt-in")
        }
        #if targetEnvironment(simulator)
        throw XCTSkip("This test requires a physical iOS device and an OpenPGP card")
        #else
        let fixture = try Self.cardFixture(environment: environment, key: "ADDRESSEE_CARD_USB_FIXTURE")
        guard let readerName = environment["ADDRESSEE_CARD_READER_NAME"],
              !readerName.isEmpty, readerName.count <= 1_024 else {
            throw CardDeviceTestError.invalidTestConfiguration
        }
        let readers = try await CardTransportFactory().readerNames()
        guard readers == [readerName] else {
            XCTFail("The unique USB reader does not match the explicitly selected test reader")
            return
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CardUsbDeviceTests-\(UUID().uuidString)", isDirectory: true)
        let store = CardBindingStore(directory: directory)
        let interaction = CardInteractionCoordinator()
        let engine = OpenPgpEngine()
        let observation = CardTransportObservation()
        let manager = CardSessionManager(
            engine: engine,
            interaction: interaction,
            transports: ObservedCardTransportOpening(observation: observation),
            store: store
        )
        let model = OpenPgpApplicationModel(
            engine: engine,
            cardInteraction: interaction,
            cardSessions: manager
        )
        await model.load()
        XCTAssertNil(model.errorMessage)
        let imported = try await model.importPublic(fixture.publicCertificate)
        let fingerprint = imported.summary.fingerprint
        XCTAssertEqual(imported.summary.storage, .publicOnly)
        addTeardownBlock { @MainActor in
            interaction.cancelActiveInteraction()
            if model.hasCardBinding(fingerprint: fingerprint) {
                try? await model.disconnectCard(fingerprint: fingerprint)
            }
            try? FileManager.default.removeItem(at: directory)
        }

        let registration = try await model.connectCard(
            certificateFingerprint: fingerprint,
            signingComponent: fixture.signingComponent,
            decryptionComponent: fixture.decryptionComponent,
            method: .usb,
            readerName: readerName
        )
        XCTAssertEqual(registration.identity, fixture.identity.ffi())
        XCTAssertEqual(model.cardRegistrations, [registration])
        if let signing = fixture.signingComponent {
            XCTAssertTrue(registration.components.contains {
                $0.slot == .signing && $0.componentFingerprint == signing
            })
        }
        if let decryption = fixture.decryptionComponent {
            XCTAssertTrue(registration.components.contains {
                $0.slot == .decryption && $0.componentFingerprint == decryption
            })
        }
        let observed = await observation.snapshot()
        XCTAssertEqual(observed.opened, 1)
        XCTAssertEqual(observed.closed, 1)
        XCTAssertEqual(observed.successfulCloses, 1)
        XCTAssertEqual(observed.failures, 0)
        let report: [String: Any] = [
            "schemaVersion": 1,
            "transport": "usb",
            "readerName": readerName,
            "certificateFingerprint": fingerprint,
            "cardIdentity": registration.identity.displayIdentifier,
            "association": "passed",
            "transportOpenCount": observed.opened,
            "transportCloseCompletionCount": observed.closed,
            "successfulTransportCloseCompletionCount": observed.successfulCloses,
            "transportFailureCount": observed.failures,
            "pinSupplied": false,
            "privateKeyOperationRequested": false,
            "cardConfigurationWritten": false,
            "privateKeyExportRequested": false,
        ]
        let attachment = XCTAttachment(
            data: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]),
            uniformTypeIdentifier: "public.json"
        )
        attachment.name = "usb-association-result.json"
        attachment.lifetime = .keepAlways
        add(attachment)
        #endif
    }

    private enum USBPrivateKeyWorkflow {
        case signing
        case attachedSigning
        case decryption

        var operationName: String {
            switch self {
            case .signing: "signing"
            case .attachedSigning: "attached-signing"
            case .decryption: "decryption"
            }
        }

        var privateKeyOperation: PrivateKeyOperation {
            switch self {
            case .signing, .attachedSigning: .signing
            case .decryption: .decryption
            }
        }

        func componentFingerprint(in fixture: CardDeviceFixture) throws -> String {
            switch self {
            case .signing, .attachedSigning:
                try XCTUnwrap(fixture.signingComponent)
            case .decryption:
                try XCTUnwrap(fixture.decryptionComponent)
            }
        }
    }

    func testUSBPrivateKeySigning() async throws {
        try await runUSBPrivateKeyTest(workflow: .signing)
    }

    func testUSBPrivateKeyAttachedSigning() async throws {
        try await runUSBPrivateKeyTest(workflow: .attachedSigning)
    }

    func testUSBPrivateKeyDecryption() async throws {
        try await runUSBPrivateKeyTest(workflow: .decryption)
    }

    private func runUSBPrivateKeyTest(workflow: USBPrivateKeyWorkflow) async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["ADDRESSEE_CARD_USB_PRIVATE_KEY_TESTS"] == "1" else {
            throw XCTSkip("Physical USB private-key tests require an explicit fixture, PIN, and opt-in")
        }
        #if targetEnvironment(simulator)
        throw XCTSkip("This test requires a physical iOS device and an OpenPGP card")
        #else
        let fixture = try Self.cardFixture(environment: environment, key: "ADDRESSEE_CARD_USB_FIXTURE")
        guard let readerName = environment["ADDRESSEE_CARD_READER_NAME"],
              !readerName.isEmpty, readerName.count <= 1_024,
              let pin = environment["ADDRESSEE_CARD_TEST_PIN"],
              !pin.isEmpty, pin.utf8.count <= 128 else {
            throw CardDeviceTestError.invalidTestConfiguration
        }
        let operation = workflow.privateKeyOperation
        let operationName = workflow.operationName
        let componentFingerprint = try workflow.componentFingerprint(in: fixture)
        let readers = try await CardTransportFactory().readerNames()
        guard readers == [readerName] else {
            XCTFail("The unique USB reader does not match the explicitly selected test reader")
            return
        }
        let connection = CardConnectionSelection(method: .usb, readerName: readerName)
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CardUsbPrivateKeyTests-\(UUID().uuidString)", isDirectory: true)
        let store = CardBindingStore(directory: directory)
        let interaction = CardInteractionCoordinator()
        let engine = OpenPgpEngine()
        let observation = CardTransportObservation()
        let transports = ObservedCardTransportOpening(observation: observation)
        let manager = CardSessionManager(
            engine: engine,
            interaction: interaction,
            transports: transports,
            store: store
        )
        let model = OpenPgpApplicationModel(
            engine: engine,
            cardInteraction: interaction,
            cardSessions: manager
        )
        await model.load()
        XCTAssertNil(model.errorMessage)
        let imported = try await model.importPublic(fixture.publicCertificate)
        let fingerprint = imported.summary.fingerprint
        XCTAssertEqual(imported.summary.storage, .publicOnly)
        addTeardownBlock { @MainActor in
            interaction.cancelActiveInteraction()
            if model.hasCardBinding(fingerprint: fingerprint) {
                try? await model.disconnectCard(fingerprint: fingerprint)
            }
            try? FileManager.default.removeItem(at: directory)
        }

        let registration = try await model.connectCard(
            certificateFingerprint: fingerprint,
            signingComponent: fixture.signingComponent,
            decryptionComponent: fixture.decryptionComponent,
            method: .usb,
            readerName: readerName
        )
        XCTAssertEqual(registration.identity, fixture.identity.ffi())
        XCTAssertEqual(model.cardRegistrations, [registration])
        XCTAssertTrue(registration.components.contains {
            $0.componentFingerprint == componentFingerprint
        })
        XCTAssertEqual(model.privateKeyAccess(fingerprint: fingerprint, operation: operation), .smartCard)
        var observed = await observation.snapshot()
        XCTAssertEqual(observed.opened, 1)
        XCTAssertEqual(observed.closed, 1)
        XCTAssertEqual(observed.successfulCloses, 1)
        XCTAssertEqual(observed.failures, 0)

        let publicInformation = try await model.inspectCard(
            fingerprint: fingerprint,
            connection: connection
        )
        XCTAssertEqual(publicInformation.identity, registration.identity)
        observed = await observation.snapshot()
        XCTAssertEqual(observed.opened, 2)
        XCTAssertEqual(observed.closed, 2)
        XCTAssertEqual(observed.successfulCloses, 2)
        XCTAssertEqual(observed.failures, 0)

        let records = try await Task.detached(priority: .userInitiated) {
            try engine.storageSnapshot()
        }.value
        let restoredEngine = OpenPgpEngine()
        try await Task.detached(priority: .userInitiated) {
            try restoredEngine.restoreStorage(records: records)
        }.value
        let restoredInteraction = CardInteractionCoordinator()
        let restoredManager = CardSessionManager(
            engine: restoredEngine,
            interaction: restoredInteraction,
            transports: transports,
            store: store
        )
        let restored = OpenPgpApplicationModel(
            engine: restoredEngine,
            cardInteraction: restoredInteraction,
            cardSessions: restoredManager
        )
        await restored.load()
        XCTAssertNil(restored.errorMessage)
        XCTAssertEqual(restored.cardRegistrations, [registration])
        observed = await observation.snapshot()
        XCTAssertEqual(observed.opened, 2, "Restoring an association must not open a hardware session")
        addTeardownBlock { @MainActor in
            restoredInteraction.cancelActiveInteraction()
            if restored.hasCardBinding(fingerprint: fingerprint) {
                try? await restored.disconnectCard(fingerprint: fingerprint)
            }
        }

        let at = UInt64(Date().timeIntervalSince1970) + 60
        var messageSource = "local"
        switch workflow {
        case .signing:
            let payload = Data("Physical USB short signing session".utf8)
            let signature = try await Self.respondToCardInteractions(
                interaction: restoredInteraction,
                pin: pin
            ) {
                try await restored.signDetached(
                    signingKey: fingerprint,
                    password: "",
                    atUnixSeconds: at,
                    data: payload,
                    format: .binary,
                    connection: connection
                )
            }
            XCTAssertEqual(signature.metadata.signerFingerprint, componentFingerprint)
            let verification = try await restored.verifyDetached(
                data: payload,
                signature: signature.artifact,
                atUnixSeconds: at
            )
            XCTAssertEqual(verification.status, .valid)
            XCTAssertEqual(verification.signatures.first?.signerFingerprint, componentFingerprint)
            let payloadAttachment = XCTAttachment(data: payload, uniformTypeIdentifier: "public.data")
            payloadAttachment.name = "usb-signing-payload.bin"
            payloadAttachment.lifetime = .keepAlways
            add(payloadAttachment)
            let signatureAttachment = XCTAttachment(data: signature.artifact, uniformTypeIdentifier: "public.data")
            signatureAttachment.name = "usb-signing-signature.sig"
            signatureAttachment.lifetime = .keepAlways
            add(signatureAttachment)
        case .attachedSigning:
            let payload = Data("Physical USB attached signing\0\r\nSecond line".utf8)
            let signature = try await Self.respondToCardInteractions(
                interaction: restoredInteraction,
                pin: pin
            ) {
                try await restored.signAttached(
                    signingKey: fingerprint,
                    password: "",
                    atUnixSeconds: at,
                    data: payload,
                    format: .binary,
                    connection: connection
                )
            }
            XCTAssertEqual(signature.metadata.signerFingerprint, componentFingerprint)
            let verification = try await restored.verifyAttached(
                input: signature.artifact,
                atUnixSeconds: at
            )
            XCTAssertEqual(verification.outcome.status, .valid)
            XCTAssertEqual(verification.outcome.signatures.first?.signerFingerprint, componentFingerprint)
            XCTAssertEqual(verification.plaintext, payload)

            var tampered = signature.artifact
            let lastIndex = tampered.index(before: tampered.endIndex)
            tampered[lastIndex] ^= 0x01
            let tamperedRejected: Bool
            do {
                let rejected = try await restored.verifyAttached(input: tampered, atUnixSeconds: at)
                tamperedRejected = rejected.outcome.status == .invalid && rejected.plaintext != payload
            } catch {
                tamperedRejected = true
            }
            XCTAssertTrue(tamperedRejected)

            for (name, data) in [
                ("usb-attached-signing-payload.bin", payload),
                ("usb-attached-signing-message.pgp", signature.artifact),
                ("usb-attached-signing-tampered.pgp", tampered),
            ] {
                let attachment = XCTAttachment(data: data, uniformTypeIdentifier: "public.data")
                attachment.name = name
                attachment.lifetime = .keepAlways
                add(attachment)
            }
        case .decryption:
            let plaintext: Data
            let encrypted: Data
            let peerMessage = environment["ADDRESSEE_CARD_USB_PEER_MESSAGE"]
            let peerPlaintext = environment["ADDRESSEE_CARD_USB_PEER_PLAINTEXT"]
            if peerMessage != nil || peerPlaintext != nil {
                guard let peerMessage, let peerPlaintext,
                      let peerMessageData = Data(base64Encoded: peerMessage),
                      let peerPlaintextData = Data(base64Encoded: peerPlaintext),
                      !peerMessageData.isEmpty, peerMessageData.count <= 16 * 1024 * 1024,
                      !peerPlaintextData.isEmpty, peerPlaintextData.count <= 16 * 1024 * 1024 else {
                    throw CardDeviceTestError.invalidTestConfiguration
                }
                encrypted = peerMessageData
                plaintext = peerPlaintextData
                messageSource = "gpg"
            } else {
                plaintext = Data("Physical USB short decryption session".utf8)
                encrypted = try await restored.encrypt(
                    recipients: [fingerprint],
                    atUnixSeconds: at,
                    config: .seipdV1(cipher: .aes256),
                    data: plaintext,
                    format: .binary
                )
            }
            let decrypted = try await Self.respondToCardInteractions(
                interaction: restoredInteraction,
                pin: pin
            ) {
                try await restored.decrypt(
                    decryptionKey: fingerprint,
                    password: "",
                    atUnixSeconds: at,
                    input: encrypted,
                    connection: connection
                )
            }
            XCTAssertEqual(decrypted.report.status, .unsigned)
            XCTAssertEqual(decrypted.plaintext, plaintext)
        }
        XCTAssertEqual(restored.cardRegistrations, [registration])
        observed = await observation.snapshot()
        XCTAssertEqual(observed.opened, 3)
        XCTAssertEqual(observed.closed, 3)
        XCTAssertEqual(observed.successfulCloses, 3)
        XCTAssertEqual(observed.failures, 0)
        let report: [String: Any] = [
            "schemaVersion": 1,
            "transport": "usb",
            "operation": operationName,
            "messageSource": messageSource,
            "readerName": readerName,
            "certificateFingerprint": fingerprint,
            "componentFingerprint": componentFingerprint,
            "cardIdentity": registration.identity.displayIdentifier,
            "associationRestored": true,
            "publicInspection": "passed",
            "privateKeyOperation": "passed",
            "transportOpenCount": observed.opened,
            "transportCloseCompletionCount": observed.closed,
            "successfulTransportCloseCompletionCount": observed.successfulCloses,
            "transportFailureCount": observed.failures,
            "pinSupplied": true,
            "privateKeyOperationRequested": true,
            "cardConfigurationWritten": false,
            "privateKeyMaterialExported": false,
        ]
        let attachment = XCTAttachment(
            data: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]),
            uniformTypeIdentifier: "public.json"
        )
        attachment.name = "usb-\(operationName)-result.json"
        attachment.lifetime = .keepAlways
        add(attachment)
        #endif
    }

    func testNFCAssociationAndShortPrivateKeySessions() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["ADDRESSEE_CARD_NFC_TESTS"] == "1" else {
            throw XCTSkip("Physical NFC card tests require an explicit fixture and opt-in")
        }
        #if targetEnvironment(simulator)
        throw XCTSkip("This test requires a physical iOS device and an OpenPGP card")
        #else
        let fixture = try Self.cardFixture(environment: environment, key: "ADDRESSEE_CARD_NFC_FIXTURE")
        guard let pin = environment["ADDRESSEE_CARD_TEST_PIN"], !pin.isEmpty else {
            throw CardNfcTestError.invalidTestConfiguration
        }
        XCTAssertTrue(CardTransportFactory.nfcIsAvailable())
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CardNfcDeviceTests-\(UUID().uuidString)", isDirectory: true)
        let store = CardBindingStore(directory: directory)
        let interaction = CardInteractionCoordinator()
        let engine = OpenPgpEngine()
        let observation = CardTransportObservation()
        let transports = ObservedCardTransportOpening(observation: observation)
        let manager = CardSessionManager(
            engine: engine,
            interaction: interaction,
            transports: transports,
            store: store
        )
        let model = OpenPgpApplicationModel(
            engine: engine,
            cardInteraction: interaction,
            cardSessions: manager
        )
        await model.load()
        XCTAssertNil(model.errorMessage)
        let imported = try await model.importPublic(fixture.publicCertificate)
        let fingerprint = imported.summary.fingerprint
        XCTAssertEqual(imported.summary.storage, .publicOnly)
        addTeardownBlock { @MainActor in
            interaction.cancelActiveInteraction()
            if model.hasCardBinding(fingerprint: fingerprint) {
                try? await model.disconnectCard(fingerprint: fingerprint)
            }
            try? FileManager.default.removeItem(at: directory)
        }

        let registration = try await model.connectCard(
            certificateFingerprint: fingerprint,
            signingComponent: fixture.signingComponent,
            decryptionComponent: fixture.decryptionComponent,
            method: .nfc,
            readerName: nil
        )
        XCTAssertEqual(registration.identity, fixture.identity.ffi())
        XCTAssertEqual(model.cardRegistrations, [registration])
        if let signing = fixture.signingComponent {
            XCTAssertTrue(registration.components.contains {
                $0.slot == .signing && $0.componentFingerprint == signing
            })
            XCTAssertEqual(model.privateKeyAccess(fingerprint: fingerprint, operation: .signing), .smartCard)
        }
        if let decryption = fixture.decryptionComponent {
            XCTAssertTrue(registration.components.contains {
                $0.slot == .decryption && $0.componentFingerprint == decryption
            })
            XCTAssertEqual(model.privateKeyAccess(fingerprint: fingerprint, operation: .decryption), .smartCard)
        }
        var observed = await observation.snapshot()
        XCTAssertEqual(observed.opened, 1)
        XCTAssertEqual(observed.closed, 1)
        XCTAssertEqual(observed.successfulCloses, 1)
        XCTAssertEqual(observed.failures, 0)

        let publicInformation = try await model.inspectCard(fingerprint: fingerprint)
        XCTAssertEqual(publicInformation.identity, registration.identity)
        XCTAssertEqual(model.cardRegistrations, [registration])
        observed = await observation.snapshot()
        XCTAssertEqual(observed.opened, 2)
        XCTAssertEqual(observed.closed, 2)
        XCTAssertEqual(observed.successfulCloses, 2)
        XCTAssertEqual(observed.failures, 0)
        let records = try await Task.detached(priority: .userInitiated) {
            try engine.storageSnapshot()
        }.value
        let restoredEngine = OpenPgpEngine()
        try await Task.detached(priority: .userInitiated) {
            try restoredEngine.restoreStorage(records: records)
        }.value
        let restoredInteraction = CardInteractionCoordinator()
        let restoredManager = CardSessionManager(
            engine: restoredEngine,
            interaction: restoredInteraction,
            transports: transports,
            store: store
        )
        let restored = OpenPgpApplicationModel(
            engine: restoredEngine,
            cardInteraction: restoredInteraction,
            cardSessions: restoredManager
        )
        await restored.load()
        XCTAssertNil(restored.errorMessage)
        XCTAssertEqual(restored.cardRegistrations, [registration])
        observed = await observation.snapshot()
        XCTAssertEqual(observed.opened, 2, "Restoring an association must not open a hardware session")
        addTeardownBlock { @MainActor in
            restoredInteraction.cancelActiveInteraction()
            if restored.hasCardBinding(fingerprint: fingerprint) {
                try? await restored.disconnectCard(fingerprint: fingerprint)
            }
        }

        let at = UInt64(Date().timeIntervalSince1970) + 60
        var signingResult = "notRun"
        if fixture.signingComponent != nil {
            let signature = try await Self.respondToCardInteractions(
                interaction: restoredInteraction,
                pin: pin
            ) {
                try await restored.signDetached(
                    signingKey: fingerprint,
                    password: "",
                    atUnixSeconds: at,
                    data: Data("Physical NFC short signing session".utf8),
                    format: .binary
                )
            }
            XCTAssertEqual(signature.metadata.signerFingerprint, fixture.signingComponent)
            let verification = try await restored.verifyDetached(
                data: Data("Physical NFC short signing session".utf8),
                signature: signature.artifact,
                atUnixSeconds: at
            )
            XCTAssertEqual(verification.status, .valid)
            signingResult = "passed"
        }
        var decryptionResult = "notRun"
        if fixture.decryptionComponent != nil {
            let encrypted = try await restored.encryptText(
                recipients: [fingerprint],
                atUnixSeconds: at,
                config: .seipdV1(cipher: .aes256),
                text: "Physical NFC short decryption session",
                format: .binary
            )
            let decrypted = try await Self.respondToCardInteractions(
                interaction: restoredInteraction,
                pin: pin
            ) {
                try await restored.decryptText(
                    decryptionKey: fingerprint,
                    password: "",
                    atUnixSeconds: at,
                    input: encrypted
                )
            }
            XCTAssertEqual(decrypted.report.status, .unsigned)
            XCTAssertEqual(decrypted.text, "Physical NFC short decryption session")
            decryptionResult = "passed"
        }
        XCTAssertEqual(restored.cardRegistrations, [registration])
        let operationCount = (fixture.signingComponent == nil ? 0 : 1)
            + (fixture.decryptionComponent == nil ? 0 : 1)
        let expectedSessions = 2 + operationCount
        let expectedSuccessfulCloses = expectedSessions
        observed = await observation.snapshot()
        XCTAssertEqual(observed.opened, expectedSessions)
        XCTAssertEqual(observed.closed, expectedSessions)
        XCTAssertEqual(observed.successfulCloses, expectedSuccessfulCloses)
        XCTAssertEqual(observed.failures, 0)
        let report: [String: Any] = [
            "schemaVersion": 1,
            "certificateFingerprint": fingerprint,
            "cardIdentity": registration.identity.displayIdentifier,
            "associationRestored": true,
            "publicInspection": "passed",
            "signing": signingResult,
            "decryption": decryptionResult,
            "privateKeySessionPhases": 1,
            "transportOpenCount": observed.opened,
            "transportCloseCompletionCount": observed.closed,
            "successfulTransportCloseCompletionCount": observed.successfulCloses,
            "transportFailureCount": observed.failures,
            "cardConfigurationWritten": false,
            "privateKeyMaterialExported": false,
        ]
        let attachment = XCTAttachment(
            data: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]),
            uniformTypeIdentifier: "public.json"
        )
        attachment.name = "nfc-association-result.json"
        attachment.lifetime = .keepAlways
        add(attachment)
        #endif
    }

    private struct CardDeviceFixture: Decodable {
        let schemaVersion: Int
        let publicCertificate: Data
        let identity: CardIdentityRecord
        let signingComponent: String?
        let decryptionComponent: String?
    }

    private enum CardDeviceTestError: Error {
        case invalidTestConfiguration
    }

    private enum CardNfcTestError: Error {
        case invalidTestConfiguration
    }

    private static func cardFixture(
        environment: [String: String],
        key: String
    ) throws -> CardDeviceFixture {
        guard let encoded = environment[key],
              encoded.count <= 6_000_000,
              let data = Data(base64Encoded: encoded) else {
            throw CardDeviceTestError.invalidTestConfiguration
        }
        let fixture = try JSONDecoder().decode(CardDeviceFixture.self, from: data)
        guard fixture.schemaVersion == 1,
              !fixture.publicCertificate.isEmpty,
              fixture.publicCertificate.count <= 4 * 1024 * 1024,
              fixture.signingComponent != nil || fixture.decryptionComponent != nil else {
            throw CardDeviceTestError.invalidTestConfiguration
        }
        return fixture
    }

    private static func respondToCardInteractions<T: Sendable>(
        interaction: CardInteractionCoordinator,
        pin: String,
        operation: @escaping @MainActor @Sendable () async throws -> T
    ) async throws -> T {
        let responses = Task { @MainActor in
            while !Task.isCancelled {
                if interaction.pinRequest != nil {
                    interaction.pin = pin
                    interaction.submitPin()
                }
                if interaction.touchRequest != nil {
                    interaction.confirmTouch()
                }
                try? await Task.sleep(nanoseconds: 20_000_000)
            }
        }
        let operation = Task { @MainActor in
            try await operation()
        }
        defer {
            responses.cancel()
            interaction.cancelActiveInteraction()
        }
        return try await operation.value
    }
}
