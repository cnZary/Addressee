import AppleSmartCardTransport
import XCTest
@testable import Addressee

@MainActor
final class CardSessionManagerTests: XCTestCase {
    private var directory: URL!
    private var defaultsSuite = ""
    private var preferences: CardConnectionPreferenceStore!
    private var responders: [Task<Void, Never>] = []
    private var interactions: [CardInteractionCoordinator] = []

    override func setUp() async throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CardSessionManagerTests-\(UUID().uuidString)", isDirectory: true)
        defaultsSuite = "CardSessionManagerTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: defaultsSuite))
        defaults.removePersistentDomain(forName: defaultsSuite)
        preferences = CardConnectionPreferenceStore(defaults: defaults)
        responders = []
        interactions = []
    }

    override func tearDown() async throws {
        responders.forEach { $0.cancel() }
        interactions.forEach { $0.cancelActiveInteraction() }
        UserDefaults(suiteName: defaultsSuite)?.removePersistentDomain(forName: defaultsSuite)
        try? FileManager.default.removeItem(at: directory)
    }

    func testNFCCollectsPINBeforeOneSessionAndNextOperationCanUseUSB() async throws {
        let registration = makeRegistration()
        let spy = CardSessionSpy(registration: registration)
        let manager = makeManager(spy: spy, publicOnly: [registration.certificateFingerprint])

        let linked = try await manager.connect(
            certificateFingerprint: registration.certificateFingerprint,
            signingComponent: registration.components[0].componentFingerprint,
            decryptionComponent: registration.components[1].componentFingerprint,
            method: .nfc,
            readerName: nil
        )
        XCTAssertEqual(linked, registration)
        XCTAssertEqual(manager.registrations, [registration])
        var events = await spy.events
        assertOperationEvents(events, ["open", "reserve", "close"])
        XCTAssertEqual(events.last, .close(String(localized: "hardware.nfc.linked")))

        await spy.clearEvents()
        let first = try await manager.withCardSession(
            certificateFingerprint: registration.certificateFingerprint,
            operation: .signing,
            connection: CardConnectionSelection()
        ) {
            await spy.operate("first")
        }
        XCTAssertEqual(first, "first")
        await assertEqual(await spy.operationGuidance["first"], [
            String(localized: "hardware.nfc.privateOperationInProgress"),
        ])
        let usb = CardConnectionSelection(method: .usb, readerName: "Explicit USB Reader")
        let second = try await manager.withCardSession(
            certificateFingerprint: registration.certificateFingerprint,
            operation: .signing,
            connection: usb
        ) {
            await spy.operate("second")
        }
        XCTAssertEqual(second, "second")

        events = await spy.events
        assertOperationEvents(events, [
            "pin", "reserve", "open", "attach", "operate", "detach", "close",
            "reserve", "open", "attach", "operate", "detach", "close",
        ])
        let requests = await spy.requests
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests[0].method, .nfc)
        XCTAssertEqual(requests[1].method, .usb)
        XCTAssertEqual(requests[1].readerName, "Explicit USB Reader")
        guard case .preparedNFC(let id, let slot) = requests[0].interactionMode,
              case .interactive = requests[1].interactionMode else {
            return XCTFail("The single NFC session must use its prepared PIN")
        }
        XCTAssertNotEqual(id, UUID())
        XCTAssertEqual(slot, .signing)
        for request in requests {
            XCTAssertEqual(request.expectedIdentity, registration.identity)
            XCTAssertEqual(request.signingComponent, registration.components[0].componentFingerprint)
            XCTAssertEqual(request.decryptionComponent, registration.components[1].componentFingerprint)
        }
        await assertFalse(await spy.isAttached)
        XCTAssertEqual(events.last, .close(String(localized: "hardware.nfc.operationComplete")))
        await assertEqual(await spy.alertMessages, Array(
            repeating: String(localized: "hardware.nfc.privateOperationInProgress"),
            count: 2
        ))
        XCTAssertEqual(manager.preferredConnection(for: registration.certificateFingerprint), usb)
    }

    func testUSBAssociationRestoresWithoutReconnectingAndUsesSelectedReaderPreference() async throws {
        let registration = makeRegistration()
        let store = CardBindingStore(directory: directory)
        let firstSpy = CardSessionSpy(registration: registration)
        let first = makeManager(
            spy: firstSpy,
            store: store,
            publicOnly: [registration.certificateFingerprint]
        )
        _ = try await first.connect(
            certificateFingerprint: registration.certificateFingerprint,
            signingComponent: registration.components[0].componentFingerprint,
            decryptionComponent: registration.components[1].componentFingerprint,
            method: .usb,
            readerName: "Explicit USB Reader"
        )

        let secondSpy = CardSessionSpy(registration: registration)
        let second = makeManager(
            spy: secondSpy,
            store: store,
            publicOnly: [registration.certificateFingerprint]
        )
        try await second.restore()
        XCTAssertEqual(second.registrations, [registration])
        await assertEqual(await secondSpy.events.map(\.name), ["reserve"])

        _ = try await second.withCardSession(
            certificateFingerprint: registration.certificateFingerprint,
            operation: .signing,
            connection: second.preferredConnection(for: registration.certificateFingerprint)
        ) {
            await secondSpy.operate("usb")
        }
        let request = try await unwrap(await secondSpy.requests.first)
        XCTAssertEqual(request.method, .usb)
        XCTAssertEqual(request.readerName, "Explicit USB Reader")
        XCTAssertEqual(request.expectedIdentity, registration.identity)
    }

    func testIndependentCertificatesKeepTheirOwnCardsAndConnections() async throws {
        let first = makeRegistration()
        var second = makeRegistration(certificate: "B", signing: "3", decryption: "4")
        second.identity.serial ^= 1
        let firstSpy = CardSessionSpy(registration: first)
        let secondSpy = CardSessionSpy(registration: second)
        let store = CardBindingStore(directory: directory)
        let manager = makeManager(
            spies: [
                first.certificateFingerprint: firstSpy,
                second.certificateFingerprint: secondSpy,
            ],
            store: store,
            publicOnly: [first.certificateFingerprint, second.certificateFingerprint]
        )
        try await link(manager, registration: first, method: .usb)
        try await link(manager, registration: second, method: .nfc)
        XCTAssertEqual(manager.registrations, [first, second])
        await firstSpy.clearEvents()
        await secondSpy.clearEvents()

        let firstUSB = CardConnectionSelection(method: .usb, readerName: "Explicit USB Reader")
        _ = try await manager.withCardSession(
            certificateFingerprint: first.certificateFingerprint,
            operation: .signing,
            connection: firstUSB
        ) {
            await firstSpy.operate("first card")
        }
        _ = try await manager.withCardSession(
            certificateFingerprint: second.certificateFingerprint,
            operation: .decryption,
            connection: CardConnectionSelection()
        ) {
            await secondSpy.operate("second card")
        }
        let firstRequest = try await unwrap(await firstSpy.requests.last)
        let secondRequest = try await unwrap(await secondSpy.requests.last)
        XCTAssertEqual(firstRequest.expectedIdentity, first.identity)
        XCTAssertEqual(firstRequest.signingComponent, first.components[0].componentFingerprint)
        XCTAssertEqual(firstRequest.readerName, "Explicit USB Reader")
        XCTAssertEqual(secondRequest.expectedIdentity, second.identity)
        XCTAssertEqual(secondRequest.decryptionComponent, second.components[1].componentFingerprint)
        XCTAssertEqual(secondRequest.method, .nfc)
        await assertEqual(await firstSpy.events.map(\.name), ["reserve", "open", "attach", "operate", "detach", "close"])
        await assertFalse(await secondSpy.isAttached)

        let restoredSpy = CardSessionSpy(registration: first)
        let restoredSecondSpy = CardSessionSpy(registration: second)
        let restored = makeManager(
            spies: [
                first.certificateFingerprint: restoredSpy,
                second.certificateFingerprint: restoredSecondSpy,
            ],
            store: store,
            publicOnly: [first.certificateFingerprint, second.certificateFingerprint]
        )
        try await restored.restore()
        XCTAssertEqual(restored.registrations, [first, second])
        try await restored.disconnect(certificateFingerprint: first.certificateFingerprint)
        XCTAssertEqual(restored.registrations, [second])
        try await assertEqual(try await store.bindings().map(\.certificateFingerprint), [second.certificateFingerprint])
        await assertEqual(await restoredSpy.events.map(\.name), ["reserve", "release"])
        await assertEqual(await restoredSecondSpy.events.map(\.name), ["reserve"])
    }

    func testCleanupFailureDoesNotReplaceTheOriginalOperationFailure() async throws {
        let registration = makeRegistration()
        let spy = CardSessionSpy(registration: registration)
        let manager = makeManager(spy: spy, publicOnly: [registration.certificateFingerprint])
        try await link(manager, registration: registration, method: .usb)
        await spy.setCloseError(TestFailure.cleanup)
        await spy.clearEvents()

        do {
            _ = try await manager.withCardSession(
                certificateFingerprint: registration.certificateFingerprint,
                operation: .signing,
                connection: manager.preferredConnection(for: registration.certificateFingerprint)
            ) {
                await spy.operate("failed operation")
                throw TestFailure.operation
            }
            XCTFail("The operation must fail")
        } catch {
            XCTAssertEqual(error as? TestFailure, .operation)
        }
        XCTAssertEqual(manager.registrations, [registration])
        await assertFalse(await spy.isAttached)
    }

    func testOperationFailureKeepsTheAssociationAndNeverReportsSuccess() async throws {
        let registration = makeRegistration()
        let spy = CardSessionSpy(registration: registration)
        let manager = makeManager(spy: spy, publicOnly: [registration.certificateFingerprint])
        try await link(manager, registration: registration, method: .nfc)
        await spy.clearEvents()

        do {
            _ = try await manager.withCardSession(
                certificateFingerprint: registration.certificateFingerprint,
                operation: .signing,
                connection: CardConnectionSelection()
            ) {
                await spy.operate("failure")
                throw TestFailure.operation
            }
            XCTFail("The operation failure must be propagated")
        } catch {
            XCTAssertEqual(error as? TestFailure, .operation)
        }
        XCTAssertEqual(manager.registrations, [registration])
        var events = await spy.events
        assertOperationEvents(events, [
            "pin", "reserve", "open", "attach", "operate", "detach", "close",
        ])
        XCTAssertEqual(events.last, .close(nil))
        await assertFalse(await spy.isAttached)

        let result = try await manager.withCardSession(
            certificateFingerprint: registration.certificateFingerprint,
            operation: .signing,
            connection: CardConnectionSelection()
        ) {
            await spy.operate("explicit retry")
        }
        XCTAssertEqual(result, "explicit retry")
        await assertEqual(await spy.requests.count, 2)
        events = await spy.events
        XCTAssertEqual(events.last, .close(String(localized: "hardware.nfc.operationComplete")))
    }

    func testChangedCardIdentityStopsBeforeAttachmentAndDoesNotUnlink() async throws {
        let registration = makeRegistration()
        let spy = CardSessionSpy(registration: registration)
        let manager = makeManager(spy: spy, publicOnly: [registration.certificateFingerprint])
        try await link(manager, registration: registration, method: .nfc)
        var changed = registration
        changed.identity.serial ^= 1
        await spy.setNextRegistration(changed)
        await spy.clearEvents()

        do {
            _ = try await manager.withCardSession(
                certificateFingerprint: registration.certificateFingerprint,
                operation: .signing,
                connection: CardConnectionSelection()
            ) {
                await spy.operate("must not run")
            }
            XCTFail("A different physical card must not be accepted")
        } catch {
            XCTAssertEqual(error as? AddresseeError, .CardRegistrationConflict)
        }
        let events = await spy.events
        assertOperationEvents(events, ["pin", "reserve", "open", "close"])
        XCTAssertEqual(events.last, .close(nil))
        XCTAssertEqual(manager.registrations, [registration])
        await assertFalse(await spy.isAttached)
    }

    func testChangedCardOnTheOnlyNFCSessionStopsBeforeAttachment() async throws {
        let registration = makeRegistration()
        var changed = registration
        changed.identity.serial ^= 1
        let spy = CardSessionSpy(registration: registration)
        let manager = makeManager(spy: spy, publicOnly: [registration.certificateFingerprint])
        try await link(manager, registration: registration, method: .nfc)
        await spy.setNextRegistration(changed)
        await spy.clearEvents()

        do {
            _ = try await manager.withCardSession(
                certificateFingerprint: registration.certificateFingerprint,
                operation: .signing,
                connection: CardConnectionSelection()
            ) {
                await spy.operate("must not run")
            }
            XCTFail("A replacement card must not reach the private-key operation")
        } catch {
            XCTAssertEqual(error as? AddresseeError, .CardRegistrationConflict)
        }
        assertOperationEvents(await spy.events, [
            "pin", "reserve", "open", "close",
        ])
        await assertFalse(await spy.isAttached)
    }

    func testAttachFailureDoesNotRunThePrivateOperation() async throws {
        let registration = makeRegistration()
        let spy = CardSessionSpy(registration: registration)
        await spy.setAttachError(AddresseeError.RemoteKeyUnavailable)
        let manager = makeManager(spy: spy, publicOnly: [registration.certificateFingerprint])
        try await link(manager, registration: registration, method: .nfc)
        await spy.clearEvents()

        do {
            _ = try await manager.withCardSession(
                certificateFingerprint: registration.certificateFingerprint,
                operation: .signing,
                connection: CardConnectionSelection()
            ) {
                await spy.operate("must not run")
            }
            XCTFail("Attachment failure must be propagated")
        } catch {
            XCTAssertEqual(error as? AddresseeError, .RemoteKeyUnavailable)
        }
        assertOperationEvents(await spy.events, [
            "pin", "reserve", "open", "close",
        ])
        await assertFalse(await spy.isAttached)
        XCTAssertEqual(manager.registrations, [registration])
    }

    func testNFCPINPrecedesOpeningAndUsesConservativeTouchGuidance() async throws {
        let registration = makeRegistration()
        let spy = CardSessionSpy(registration: registration)
        let interaction = CardInteractionCoordinator()
        interactions.append(interaction)
        let manager = makeManager(
            spy: spy,
            interaction: interaction,
            publicOnly: [registration.certificateFingerprint]
        )
        try await link(manager, registration: registration, method: .nfc)
        await spy.clearEvents()
        let operation = Task {
            try await manager.withCardSession(
                certificateFingerprint: registration.certificateFingerprint,
                operation: .decryption,
                connection: CardConnectionSelection()
            ) { "decrypted" }
        }
        for _ in 0..<1_000 where interaction.pinRequest == nil {
            await Task.yield()
        }
        let request = try XCTUnwrap(interaction.pinRequest)
        XCTAssertEqual(request.purpose, .user)
        XCTAssertEqual(request.identity, registration.identity)
        XCTAssertEqual(request.minimumLength, 6)
        XCTAssertEqual(request.maximumLength, 64)
        XCTAssertNil(request.remainingRetries)
        XCTAssertTrue(request.opensNFCSession)
        await assertEqual(await spy.requests.count, 0)
        interaction.pin = "synthetic-test-pin"
        interaction.submitPin()
        let result = try await operation.value
        XCTAssertEqual(result, "decrypted")
        await assertEqual(await spy.requests.count, 1)
        let open = try await unwrap(await spy.requests.first)
        XCTAssertEqual(open.alertMessage, String(localized: "hardware.nfc.touchPossibleAlert"))
        guard case .preparedNFC(_, let slot) = open.interactionMode else {
            return XCTFail("The prepared PIN must belong to this operation")
        }
        XCTAssertEqual(slot, .decryption)
    }

    func testCancellingPINBeforeNFCNeverOpensASession() async throws {
        let registration = makeRegistration()
        let spy = CardSessionSpy(registration: registration)
        let interaction = CardInteractionCoordinator()
        interactions.append(interaction)
        let manager = makeManager(
            spy: spy,
            interaction: interaction,
            publicOnly: [registration.certificateFingerprint]
        )
        try await link(manager, registration: registration, method: .nfc)
        await spy.clearEvents()
        let operation = Task {
            try await manager.withCardSession(
                certificateFingerprint: registration.certificateFingerprint,
                operation: .signing,
                connection: CardConnectionSelection()
            ) { "must not run" }
        }
        for _ in 0..<1_000 where interaction.pinRequest == nil {
            await Task.yield()
        }
        XCTAssertNotNil(interaction.pinRequest)
        interaction.cancelActiveInteraction()
        do {
            _ = try await operation.value
            XCTFail("PIN cancellation must stop the operation")
        } catch {
            XCTAssertEqual(error as? CardInteractionErrorFfi, .Cancelled)
        }
        assertOperationEvents(await spy.events, ["reserve"])
        await assertEqual(await spy.requests.count, 0)
        XCTAssertEqual(manager.registrations, [registration])
    }

    func testRestorePrunesMissingPublicCertificatesWithoutOpeningHardware() async throws {
        let retained = makeRegistration()
        let missing = makeRegistration(certificate: "B", signing: "3", decryption: "4")
        let store = CardBindingStore(directory: directory)
        try await store.insert(try CardBinding(registration: retained))
        try await store.insert(try CardBinding(registration: missing))
        let spy = CardSessionSpy(registration: retained)
        let manager = makeManager(
            spy: spy,
            store: store,
            publicOnly: [retained.certificateFingerprint]
        )

        try await manager.restore()
        XCTAssertEqual(manager.registrations, [retained])
        assertOperationEvents(await spy.events, ["reserve"])
        try await assertEqual(try await store.bindings().count, 1)
        await assertEqual(await spy.requests.count, 0)
    }

    func testRestoreSurfacesReservationFailureInsteadOfEnablingOperations() async throws {
        let registration = makeRegistration()
        let store = CardBindingStore.inMemory()
        try await store.insert(try CardBinding(registration: registration))
        let spy = CardSessionSpy(registration: registration)
        let manager = CardSessionManager(
            engine: OpenPgpEngine(),
            interaction: CardInteractionCoordinator(),
            store: store,
            reserveCard: { _ in throw AddresseeError.AmbiguousPrivateKeyStorage },
            detachCard: { _ in },
            publicOnlyFingerprints: { [registration.certificateFingerprint] }
        )

        do {
            try await manager.restore()
            XCTFail("A storage conflict must not be silently ignored")
        } catch {
            XCTAssertEqual(error as? AddresseeError, .AmbiguousPrivateKeyStorage)
        }
        XCTAssertTrue(manager.registrations.isEmpty)
        do {
            _ = try await manager.withCardSession(
                certificateFingerprint: registration.certificateFingerprint,
                operation: .signing,
                connection: CardConnectionSelection()
            ) { "must not run" }
            XCTFail("The failed restoration must not enable private operations")
        } catch {
            XCTAssertEqual(error as? AddresseeError, .AmbiguousPrivateKeyStorage)
        }
        await assertEqual(await spy.requests.count, 0)
    }

    func testExplicitUnlinkReleasesTheReservationAndPersistentAssociation() async throws {
        let registration = makeRegistration()
        let store = CardBindingStore(directory: directory)
        let spy = CardSessionSpy(registration: registration)
        let manager = makeManager(
            spy: spy,
            store: store,
            publicOnly: [registration.certificateFingerprint]
        )
        try await link(manager, registration: registration, method: .usb)
        await spy.clearEvents()

        try await manager.disconnect(certificateFingerprint: registration.certificateFingerprint)
        XCTAssertTrue(manager.registrations.isEmpty)
        assertOperationEvents(await spy.events, ["release"])
        try await assertEqual(try await store.bindings(), [])

        try await manager.restore()
        XCTAssertTrue(manager.registrations.isEmpty)
        await assertEqual(await spy.requests.count, 0)
    }

    func testManagementReadsPublicInformationWithoutAttachingPrivateKeys() async throws {
        let registration = makeRegistration()
        let spy = CardSessionSpy(registration: registration)
        let manager = makeManager(spy: spy, publicOnly: [registration.certificateFingerprint])
        try await link(manager, registration: registration, method: .nfc)
        await spy.clearEvents()

        let information = try await manager.withCardManagementSession(
            certificateFingerprint: registration.certificateFingerprint,
            connection: CardConnectionSelection()
        ) { session in
            await spy.operate("inspect")
            return try session.inspect()
        }
        XCTAssertEqual(information.identity, registration.identity)
        XCTAssertEqual(information.slots.count, 3)
        XCTAssertEqual(information.userPinRetries, 3)
        assertOperationEvents(await spy.events, [
            "reserve", "open", "management", "operate", "close",
        ])
        await assertEqual(await spy.events.last, .close(String(localized: "hardware.nfc.managementComplete")))
        await assertFalse(await spy.isAttached)
        let request = try await unwrap(await spy.requests.first)
        XCTAssertEqual(request.method, .nfc)
        XCTAssertEqual(request.expectedIdentity, registration.identity)
        XCTAssertEqual(request.alertMessage, String(localized: "hardware.nfc.managementAlert"))
        await assertEqual(await spy.operationGuidance["inspect"], [
            String(localized: "hardware.nfc.managementInProgress"),
        ])
        XCTAssertEqual(manager.registrations, [registration])
    }

    func testManagementFailureClosesWithoutSuccessAndPreservesTheAssociation() async throws {
        let registration = makeRegistration()
        let spy = CardSessionSpy(registration: registration)
        let manager = makeManager(spy: spy, publicOnly: [registration.certificateFingerprint])
        try await link(manager, registration: registration, method: .usb)
        await spy.clearEvents()

        do {
            _ = try await manager.withCardManagementSession(
                certificateFingerprint: registration.certificateFingerprint,
                connection: manager.preferredConnection(for: registration.certificateFingerprint)
            ) { _ in
                await spy.operate("management failure")
                throw TestFailure.operation
            }
            XCTFail("The management failure must be propagated")
        } catch {
            XCTAssertEqual(error as? TestFailure, .operation)
        }
        assertOperationEvents(await spy.events, [
            "reserve", "open", "management", "operate", "close",
        ])
        await assertEqual(await spy.events.last, .close(nil))
        await assertFalse(await spy.isAttached)
        XCTAssertEqual(manager.registrations, [registration])
    }

    func testChangedCardIsRejectedBeforeCreatingTheManagementSession() async throws {
        let registration = makeRegistration()
        let spy = CardSessionSpy(registration: registration)
        let manager = makeManager(spy: spy, publicOnly: [registration.certificateFingerprint])
        try await link(manager, registration: registration, method: .nfc)
        var changed = registration
        changed.identity.serial ^= 1
        await spy.setNextRegistration(changed)
        await spy.clearEvents()

        do {
            _ = try await manager.withCardManagementSession(
                certificateFingerprint: registration.certificateFingerprint,
                connection: CardConnectionSelection()
            ) { _ in "must not run" }
            XCTFail("A different physical card must not reach management")
        } catch {
            XCTAssertEqual(error as? AddresseeError, .CardRegistrationConflict)
        }
        assertOperationEvents(await spy.events, ["reserve", "open", "close"])
        await assertEqual(await spy.events.last, .close(nil))
        XCTAssertEqual(manager.registrations, [registration])
    }

    private func assertOperationEvents(
        _ events: [CardSessionEvent],
        _ expected: [String],
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let names = events.map(\.name)
        XCTAssertEqual(
            names.filter { $0 != "pin" },
            expected.filter { $0 != "pin" },
            file: file,
            line: line
        )
        if expected.contains("pin") {
            guard let pin = names.firstIndex(of: "pin"),
                  let open = names.firstIndex(of: "open") else {
                return XCTFail("PIN entry must precede NFC session opening", file: file, line: line)
            }
            XCTAssertLessThan(pin, open, file: file, line: line)
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

    private func assertFalse(
        _ value: @autoclosure () async throws -> Bool,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async rethrows {
        let value = try await value()
        XCTAssertFalse(value, file: file, line: line)
    }

    private func unwrap<T>(
        _ value: @autoclosure () async throws -> T?,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws -> T {
        let value = try await value()
        return try XCTUnwrap(value, file: file, line: line)
    }

    private func makeManager(
        spy: CardSessionSpy,
        store: CardBindingStore = .inMemory(),
        interaction: CardInteractionCoordinator? = nil,
        publicOnly: Set<String>
    ) -> CardSessionManager {
        makeManager(
            spies: [spy.registration.certificateFingerprint: spy],
            store: store,
            interaction: interaction,
            publicOnly: publicOnly
        )
    }

    private func makeManager(
        spies: [String: CardSessionSpy],
        store: CardBindingStore = .inMemory(),
        interaction: CardInteractionCoordinator? = nil,
        publicOnly: Set<String>
    ) -> CardSessionManager {
        let shouldRespondAutomatically = interaction == nil
        let interaction = interaction ?? CardInteractionCoordinator()
        interactions.append(interaction)
        if shouldRespondAutomatically {
            responders.append(Task { @MainActor in
                while !Task.isCancelled {
                    if let request = interaction.pinRequest {
                        for spy in spies.values where await spy.handles(request.identity) {
                            await spy.notePinPrompt()
                        }
                        interaction.pin = "synthetic-test-pin"
                        interaction.submitPin()
                    }
                    await Task.yield()
                }
            })
        }
        return CardSessionManager(
            engine: OpenPgpEngine(),
            interaction: interaction,
            store: store,
            preferences: preferences,
            openSession: { request in
                guard let spy = spies[request.certificateFingerprint] else {
                    throw AddresseeError.CardRegistrationConflict
                }
                return try await spy.open(request)
            },
            reserveCard: { registration in
                await spies[registration.certificateFingerprint]?.reserve(registration)
            },
            releaseCard: { fingerprint in
                await spies[fingerprint]?.release(fingerprint)
            },
            detachCard: { fingerprint in
                guard let spy = spies[fingerprint] else {
                    throw AddresseeError.CardSessionUnavailable
                }
                try await spy.detach(fingerprint)
            },
            publicOnlyFingerprints: { publicOnly }
        )
    }

    private func link(
        _ manager: CardSessionManager,
        registration: CardRegistrationFfi,
        method: CardConnectionMethod
    ) async throws {
        _ = try await manager.connect(
            certificateFingerprint: registration.certificateFingerprint,
            signingComponent: registration.components[0].componentFingerprint,
            decryptionComponent: registration.components[1].componentFingerprint,
            method: method,
            readerName: method == .usb ? "Explicit USB Reader" : nil
        )
    }

    private func makeRegistration(
        certificate: String = "A",
        signing: String = "1",
        decryption: String = "2"
    ) -> CardRegistrationFfi {
        CardRegistrationFfi(
            certificateFingerprint: String(repeating: certificate, count: 40),
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
        )
    }
}

private enum TestFailure: Error {
    case operation
    case cleanup
}

private enum CardSessionEvent: Equatable {
    case open
    case reserve
    case attach
    case management
    case authorization
    case pin
    case operate(String)
    case detach
    case close(String?)
    case release

    var name: String {
        switch self {
        case .open: "open"
        case .reserve: "reserve"
        case .attach: "attach"
        case .management: "management"
        case .authorization: "authorization"
        case .pin: "pin"
        case .operate: "operate"
        case .detach: "detach"
        case .close: "close"
        case .release: "release"
        }
    }
}

private actor CardSessionSpy {
    nonisolated let registration: CardRegistrationFfi
    private let alertRecorder = ReaderGuidanceRecorder()
    private var registrationSequence: [CardRegistrationFfi] = []
    private var attachError: Error?
    private var closeError: Error?
    private var attached = false
    private var pinRetries: UInt8 = 3
    private(set) var requests: [CardSessionOpenRequest] = []
    private(set) var events: [CardSessionEvent] = []
    private(set) var operationGuidance: [String: [String]] = [:]

    var alertMessages: [String] { alertRecorder.messages }
    var isAttached: Bool { attached }

    init(registration: CardRegistrationFfi) {
        self.registration = registration
    }

    func handles(_ identity: CardIdentityFfi) -> Bool {
        registration.identity == identity
    }

    func setNextRegistration(_ registration: CardRegistrationFfi) {
        registrationSequence = [registration]
    }

    func setRegistrationSequence(_ registrations: [CardRegistrationFfi]) {
        registrationSequence = registrations
    }

    func setAttachError(_ error: Error?) {
        attachError = error
    }

    func setCloseError(_ error: Error?) {
        closeError = error
    }

    func setPinRetries(_ retries: UInt8) {
        pinRetries = retries
    }

    func clearEvents() {
        events.removeAll()
        requests.removeAll()
        operationGuidance.removeAll()
        alertRecorder.removeAll()
    }

    func reserve(_ registration: CardRegistrationFfi) {
        events.append(.reserve)
    }

    func release(_ fingerprint: String) {
        events.append(.release)
    }

    func detach(_ fingerprint: String) throws {
        guard attached else { throw AddresseeError.CardSessionUnavailable }
        events.append(.detach)
        attached = false
    }

    @discardableResult
    func operate(_ value: String) -> String {
        operationGuidance[value] = alertRecorder.messages
        events.append(.operate(value))
        return value
    }

    func noteManagement() {
        events.append(.management)
    }

    func notePinPrompt() {
        events.append(.pin)
    }

    func authorization(slot: CardSlot) -> CardOperationAuthorizationFfi {
        events.append(.authorization)
        return CardOperationAuthorizationFfi(
            slot: slot,
            pinPurpose: slot == .signing ? .signing : .user,
            minimumPinLength: 6,
            maximumPinLength: 64,
            remainingPinRetries: pinRetries,
            touchRequirement: .required
        )
    }

    func open(_ request: CardSessionOpenRequest) throws -> OpenedCardSession {
        requests.append(request)
        events.append(.open)
        let registration = if registrationSequence.isEmpty {
            registration
        } else {
            registrationSequence.removeFirst()
        }
        let transport = ScriptedManagementTransport()
        let bridge = CardTransportBridge(transport: transport, capabilities: .shortOnly)
        let connection = ConnectedCardTransport(
            transport: transport,
            capabilities: .shortOnly,
            onAlertMessage: { message in
                self.alertRecorder.record(message)
            },
            onClose: { message in
                try await self.close(message)
            }
        )
        return OpenedCardSession(
            registration: registration,
            connection: connection,
            attach: {
                try await self.attach(registration)
            },
            management: {
                await self.noteManagement()
                return try await Task.detached(priority: .userInitiated) {
                    try OpenPgpCardManagementSession.connect(
                        identity: registration.identity,
                        transport: bridge
                    )
                }.value
            },
            authorization: { slot in
                await self.authorization(slot: slot)
            }
        )
    }

    private func close(_ message: String?) throws {
        events.append(.close(message))
        if let closeError { throw closeError }
    }

    private func attach(_ registration: CardRegistrationFfi) throws -> CardRegistrationFfi {
        if let attachError { throw attachError }
        attached = true
        events.append(.attach)
        return registration
    }
}

struct ScriptedManagementTransport: APDUTransport {
    let capabilities = APDUTransportCapabilities.shortOnly
    private let applicationData = ScriptedManagementTransport.applicationData()

    func transmit(_ command: Data) async throws -> Data {
        if command == Data([0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
            || command == Data([0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00]) {
            return Data([0x90, 0x00])
        }
        guard command == Data([0x00, 0xCA, 0x00, 0x6E, 0x00]) else {
            throw APDUError.transportClosed
        }
        var response = applicationData
        response.append(contentsOf: [0x90, 0x00])
        return response
    }

    func close() async throws {}

    private static func applicationData() -> Data {
        let aid: [UInt8] = [
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04,
            0xF1, 0xD0, 0x10, 0x20, 0x30, 0x40, 0x00, 0x00,
        ]
        let oid: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        let fingerprints = Array(repeating: UInt8(0x11), count: 20)
            + Array(repeating: UInt8(0x22), count: 20)
            + Array(repeating: UInt8(0x00), count: 20)
        let fields: [([UInt8], [UInt8])] = [
            ([0x4F], aid),
            ([0x5F, 0x52], [0x00, 0x73, 0x00, 0x00, 0x80, 0x05, 0x90, 0x00]),
            ([0xC0], [0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            ([0xC1], [0x13] + oid),
            ([0xC2], [0x12] + oid),
            ([0xC3], [0x13] + oid),
            ([0xC4], [0x00, 0x40, 0x40, 0x40, 0x03, 0x00, 0x03]),
            ([0xC5], fingerprints),
            ([0xCD], [0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00]),
            ([0xD6], [0x00, 0x20]),
            ([0xD7], [0x00, 0x20]),
            ([0xD8], [0x00, 0x20]),
            ([0xDE], [0x01, 0x01, 0x02, 0x01, 0x03, 0x00]),
        ]
        let contents = fields.flatMap { tag, value in tlv(tag, value) }
        return Data(tlv([0x6E], contents))
    }

    private static func tlv(_ tag: [UInt8], _ value: [UInt8]) -> [UInt8] {
        var result = tag
        if value.count < 128 {
            result.append(UInt8(value.count))
        } else if value.count < 256 {
            result.append(contentsOf: [0x81, UInt8(value.count)])
        } else {
            preconditionFailure("The synthetic management data must fit a short TLV")
        }
        result.append(contentsOf: value)
        return result
    }
}
