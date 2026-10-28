import XCTest
@testable import Addressee

@MainActor
final class CardInteractionTests: XCTestCase {
    private let identity = CardIdentityFfi(manufacturer: 0xFFFF, serial: 0x01020304, version: 0x0304)

    func testPinCallbackUsesTheCoordinatorAndClearsTheSecret() async throws {
        let coordinator = CardInteractionCoordinator()
        defer { coordinator.cancelActiveInteraction() }
        let identity = identity
        let request = Task.detached {
            try coordinator.requestPin(purpose: .signing, identity: identity)
        }

        let pinRequested = await waitUntil { coordinator.pinRequest != nil }
        XCTAssertTrue(pinRequested)
        XCTAssertEqual(coordinator.pinRequest?.purpose, .signing)
        coordinator.pin = "synthetic-test-pin"
        coordinator.submitPin()

        let suppliedPin = try await request.value
        XCTAssertEqual(suppliedPin, "synthetic-test-pin")
        XCTAssertTrue(coordinator.pin.isEmpty)
        XCTAssertNil(coordinator.pinRequest)
    }

    func testCancellationReleasesTheFFICallbackAndClearsTheSecret() async {
        let coordinator = CardInteractionCoordinator()
        defer { coordinator.cancelActiveInteraction() }
        let request = Task.detached {
            try coordinator.requestPin(purpose: .user, identity: CardIdentityFfi(manufacturer: 0xFFFF, serial: 0x01020304, version: 0x0304))
        }

        let pinRequested = await waitUntil { coordinator.pinRequest != nil }
        XCTAssertTrue(pinRequested)
        coordinator.pin = "synthetic-cancelled-pin"
        coordinator.cancelActiveInteraction()

        do {
            _ = try await request.value
            XCTFail("Expected PIN cancellation")
        } catch {
            XCTAssertEqual(error as? CardInteractionErrorFfi, .Cancelled)
        }
        XCTAssertTrue(coordinator.pin.isEmpty)
        XCTAssertNil(coordinator.pinRequest)
    }

    func testTouchPromptIsAnAcknowledgementNotAHardwareResult() async throws {
        let coordinator = CardInteractionCoordinator()
        defer { coordinator.cancelActiveInteraction() }
        let request = Task.detached {
            try coordinator.requestTouch(slot: .decryption)
        }

        let touchRequested = await waitUntil { coordinator.touchRequest != nil }
        XCTAssertTrue(touchRequested)
        XCTAssertEqual(coordinator.touchRequest?.slot, .decryption)
        coordinator.confirmTouch()
        try await request.value
        XCTAssertNil(coordinator.touchRequest)
    }

    func testPreparedNFCPinSurvivesSheetDismissalAndIsConsumedOnce() async throws {
        let coordinator = CardInteractionCoordinator()
        defer { coordinator.cancelActiveInteraction() }
        let operationID = UUID()
        let preparation = Task {
            try await coordinator.preparePin(
                operationID: operationID,
                slot: .signing,
                identity: identity
            )
        }
        let pinRequested = await waitUntil { coordinator.pinRequest != nil }
        XCTAssertTrue(pinRequested)
        let requestID = try XCTUnwrap(coordinator.pinRequest?.id)
        XCTAssertEqual(coordinator.pinRequest?.minimumLength, 6)
        XCTAssertEqual(coordinator.pinRequest?.maximumLength, 64)
        XCTAssertNil(coordinator.pinRequest?.remainingRetries)
        coordinator.pin = "synthetic-nfc-pin"
        coordinator.submitPin()
        coordinator.cancelInteraction(id: requestID)
        try await preparation.value

        let callbacks = coordinator.callbacks(for: .preparedNFC(id: operationID, slot: .signing))
        let identity = identity
        let pin = try await Task.detached {
            try callbacks.requestPin(purpose: .signing, identity: identity)
        }.value
        XCTAssertEqual(pin, "synthetic-nfc-pin")
        try callbacks.requestTouch(slot: .signing)
        XCTAssertNil(coordinator.touchRequest)
        XCTAssertTrue(coordinator.pin.isEmpty)
        do {
            _ = try await Task.detached {
                try callbacks.requestPin(purpose: .signing, identity: identity)
            }.value
            XCTFail("A prepared PIN must not be reused")
        } catch {
            XCTAssertEqual(error as? CardInteractionErrorFfi, .Unavailable)
        }
        XCTAssertNil(coordinator.pinRequest)
    }

    func testPreparedPinRejectsWrongIdentityAndPurposeWithoutOpeningAnotherPrompt() async throws {
        let coordinator = CardInteractionCoordinator()
        defer { coordinator.cancelActiveInteraction() }
        let operationID = UUID()
        let preparation = Task {
            try await coordinator.preparePin(
                operationID: operationID,
                slot: .decryption,
                identity: identity
            )
        }
        let pinRequested = await waitUntil { coordinator.pinRequest != nil }
        XCTAssertTrue(pinRequested)
        coordinator.pin = "synthetic-nfc-pin"
        coordinator.submitPin()
        try await preparation.value
        let callbacks = coordinator.callbacks(for: .preparedNFC(id: operationID, slot: .decryption))
        var changedIdentity = identity
        changedIdentity.serial ^= 1
        do {
            _ = try await Task.detached {
                try callbacks.requestPin(purpose: .user, identity: changedIdentity)
            }.value
            XCTFail("A PIN must not be consumed for a different card")
        } catch {
            XCTAssertEqual(error as? CardInteractionErrorFfi, .Unavailable)
        }
        XCTAssertNil(coordinator.pinRequest)
        XCTAssertThrowsError(try callbacks.requestTouch(slot: .signing)) { error in
            XCTAssertEqual(error as? CardInteractionErrorFfi, .Unavailable)
        }
        XCTAssertThrowsError(try callbacks.requestPin(purpose: .signing, identity: identity)) { error in
            XCTAssertEqual(error as? CardInteractionErrorFfi, .Unavailable)
        }
    }

    private func waitUntil(_ predicate: @escaping () -> Bool) async -> Bool {
        for _ in 0..<1_000 {
            if predicate() {
                return true
            }
            await Task.yield()
        }
        return false
    }
}
