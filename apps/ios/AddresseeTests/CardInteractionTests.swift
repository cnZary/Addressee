import SwiftUI
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
        XCTAssertFalse(coordinator.isPresentationActive)
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

    func testPreparedNFCPinAcceptsAnyAssociatedCardOnlyOnce() async throws {
        let coordinator = CardInteractionCoordinator()
        defer { coordinator.cancelActiveInteraction() }
        let operationID = UUID()
        var secondIdentity = identity
        secondIdentity.serial ^= 1
        let preparation = Task {
            try await coordinator.preparePin(
                operationID: operationID,
                slot: .signing,
                identities: [identity, secondIdentity]
            )
        }
        let pinRequested = await waitUntil { coordinator.pinRequest != nil }
        XCTAssertTrue(pinRequested)
        XCTAssertNil(coordinator.pinRequest?.identity)
        coordinator.pin = "synthetic-nfc-pin"
        coordinator.submitPin()
        try await preparation.value

        let callbacks = coordinator.callbacks(for: .preparedNFC(id: operationID, slot: .signing))
        let pin = try await Task.detached {
            try callbacks.requestPin(purpose: .signing, identity: secondIdentity)
        }.value
        XCTAssertEqual(pin, "synthetic-nfc-pin")
        XCTAssertThrowsError(try callbacks.requestPin(purpose: .signing, identity: identity)) { error in
            XCTAssertEqual(error as? CardInteractionErrorFfi, .Unavailable)
        }
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

    func testPinToTouchTransitionKeepsTheRootSheetAlive() async throws {
        let coordinator = CardInteractionCoordinator()
        let window = UIWindow(frame: UIScreen.main.bounds)
        let host = UIHostingController(rootView: RootTabView(cardInteraction: coordinator))
        window.rootViewController = host
        window.makeKeyAndVisible()
        defer {
            coordinator.cancelActiveInteraction()
            window.isHidden = true
            window.rootViewController = nil
        }
        let identity = identity
        let operation = Task.detached {
            _ = try coordinator.requestPin(purpose: .signing, identity: identity)
            try await Task.sleep(nanoseconds: 50_000_000)
            try coordinator.requestTouch(slot: .signing)
        }

        let pinPresented = await waitUntil {
            coordinator.pinRequest != nil && host.presentedViewController != nil
        }
        XCTAssertTrue(pinPresented)
        try await Task.sleep(nanoseconds: 250_000_000)
        XCTAssertNotNil(coordinator.pinRequest)
        XCTAssertNotNil(host.presentedViewController)
        coordinator.pin = "synthetic-test-pin"
        coordinator.submitPin()
        XCTAssertTrue(coordinator.isPresentationActive)

        let touchPresented = await waitUntil {
            coordinator.touchRequest != nil && host.presentedViewController != nil
        }
        XCTAssertTrue(
            touchPresented,
            "pinPending=\(coordinator.pinRequest != nil) touchPending=\(coordinator.touchRequest != nil) presentationActive=\(coordinator.isPresentationActive) sheetPresented=\(host.presentedViewController != nil)"
        )
        try await Task.sleep(nanoseconds: 250_000_000)
        XCTAssertNotNil(coordinator.touchRequest)
        XCTAssertNotNil(host.presentedViewController)
        coordinator.confirmTouch()
        try await operation.value
        XCTAssertNil(coordinator.pinRequest)
        XCTAssertNil(coordinator.touchRequest)
        XCTAssertTrue(coordinator.isPresentationActive)
        coordinator.cancelActiveInteraction()
        let sheetDismissed = await waitUntil { host.presentedViewController == nil }
        XCTAssertTrue(sheetDismissed)
        XCTAssertFalse(coordinator.isPresentationActive)
    }

    func testDismissingThePinSheetCancelsTheCallback() async throws {
        let coordinator = CardInteractionCoordinator()
        let window = UIWindow(frame: UIScreen.main.bounds)
        let host = UIHostingController(rootView: RootTabView(cardInteraction: coordinator))
        window.rootViewController = host
        window.makeKeyAndVisible()
        defer {
            coordinator.cancelActiveInteraction()
            window.isHidden = true
            window.rootViewController = nil
        }
        let identity = identity
        let operation = Task.detached {
            try coordinator.requestPin(purpose: .signing, identity: identity)
        }

        let pinPresented = await waitUntil {
            coordinator.pinRequest != nil && host.presentedViewController != nil
        }
        XCTAssertTrue(pinPresented)
        host.presentedViewController?.dismiss(animated: false)
        do {
            _ = try await operation.value
            XCTFail("Dismissing the PIN sheet must cancel the callback")
        } catch {
            XCTAssertEqual(error as? CardInteractionErrorFfi, .Cancelled)
        }
        XCTAssertNil(coordinator.pinRequest)
        XCTAssertTrue(coordinator.pin.isEmpty)
    }

    private func waitUntil(_ predicate: @escaping () -> Bool) async -> Bool {
        for _ in 0..<500 {
            if predicate() {
                return true
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return predicate()
    }
}
