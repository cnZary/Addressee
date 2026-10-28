import Foundation
import Combine

struct CardPinRequest: Identifiable, Sendable {
    let id: UUID
    let purpose: CardPinPurpose
    let identity: CardIdentityFfi
    let minimumLength: Int
    let maximumLength: Int
    let remainingRetries: Int?
    let opensNFCSession: Bool
}

struct CardTouchRequest: Identifiable, Sendable {
    let id: UUID
    let slot: CardSlot
}

enum CardInteractionMode: Sendable {
    case interactive
    case preparedNFC(id: UUID, slot: CardSlot)
}

final class CardInteractionCallbacks: CardPinProvider, CardTouchPrompt {
    let pin: @Sendable (CardPinPurpose, CardIdentityFfi) throws -> String
    let touch: @Sendable (CardSlot) throws -> Void

    init(
        pin: @escaping @Sendable (CardPinPurpose, CardIdentityFfi) throws -> String,
        touch: @escaping @Sendable (CardSlot) throws -> Void
    ) {
        self.pin = pin
        self.touch = touch
    }

    func requestPin(purpose: CardPinPurpose, identity: CardIdentityFfi) throws -> String {
        try pin(purpose, identity)
    }

    func requestTouch(slot: CardSlot) throws {
        try touch(slot)
    }
}

@MainActor
final class CardInteractionCoordinator: ObservableObject {
    @Published private(set) var pinRequest: CardPinRequest?
    @Published private(set) var touchRequest: CardTouchRequest?
    @Published var pin = ""

    private enum PendingInteraction {
        case pin(UUID, CheckedContinuation<String, Error>)
        case touch(UUID, CheckedContinuation<Void, Error>)
    }

    private struct PreparedPin {
        let operationID: UUID
        let purpose: CardPinPurpose
        let identity: CardIdentityFfi
        let value: String
    }

    private var pending: PendingInteraction?
    private var preparedPin: PreparedPin?

    nonisolated func requestPin(
        purpose: CardPinPurpose,
        identity: CardIdentityFfi
    ) throws -> String {
        do {
            return try CallbackWait.wait { [self] in
                try await obtainPin(purpose: purpose, identity: identity)
            }
        } catch let error as CardInteractionErrorFfi {
            throw error
        } catch {
            throw CardInteractionErrorFfi.Unavailable
        }
    }

    nonisolated func requestTouch(slot: CardSlot) throws {
        do {
            try CallbackWait.wait { [self] in
                try await acknowledgeTouch(slot: slot)
            }
        } catch let error as CardInteractionErrorFfi {
            throw error
        } catch {
            throw CardInteractionErrorFfi.Unavailable
        }
    }

    func callbacks(for mode: CardInteractionMode) -> CardInteractionCallbacks {
        switch mode {
        case .interactive:
            CardInteractionCallbacks(pin: requestPin, touch: requestTouch)
        case .preparedNFC(let id, let slot):
            CardInteractionCallbacks(
                pin: { [self] purpose, identity in
                    guard purpose == slot.pinPurpose else {
                        throw CardInteractionErrorFfi.Unavailable
                    }
                    return try consumePreparedPin(operationID: id, purpose: purpose, identity: identity)
                },
                touch: { requestedSlot in
                    guard requestedSlot == slot else {
                        throw CardInteractionErrorFfi.Unavailable
                    }
                }
            )
        }
    }

    func preparePin(
        operationID: UUID,
        slot: CardSlot,
        identity: CardIdentityFfi
    ) async throws {
        preparedPin = nil
        let purpose = slot.pinPurpose
        let pin = try await obtainPin(
            purpose: purpose,
            identity: identity,
            id: operationID,
            opensNFCSession: true
        )
        guard (6...64).contains(pin.utf8.count) else {
            throw AddresseeError.InvalidInput
        }
        preparedPin = PreparedPin(
            operationID: operationID,
            purpose: purpose,
            identity: identity,
            value: pin
        )
    }

    func submitPin() {
        guard let request = pinRequest,
              case .pin(let id, let continuation) = pending,
              request.id == id,
              !pin.isEmpty else { return }
        let pin = pin
        clearInteraction()
        continuation.resume(returning: pin)
    }

    func confirmTouch() {
        guard let request = touchRequest,
              case .touch(let id, let continuation) = pending,
              request.id == id else { return }
        clearInteraction()
        continuation.resume()
    }

    func cancelActiveInteraction() {
        cancelInteraction(id: nil)
    }

    func cancelInteraction(id: UUID?) {
        guard let pending else {
            if id == nil { clearInteraction() }
            return
        }
        switch pending {
        case .pin(let pendingID, let continuation):
            guard id == nil || id == pendingID else { return }
            clearInteraction()
            continuation.resume(throwing: CardInteractionErrorFfi.Cancelled)
        case .touch(let pendingID, let continuation):
            guard id == nil || id == pendingID else { return }
            clearInteraction()
            continuation.resume(throwing: CardInteractionErrorFfi.Cancelled)
        }
    }

    private nonisolated func consumePreparedPin(
        operationID: UUID,
        purpose: CardPinPurpose,
        identity: CardIdentityFfi
    ) throws -> String {
        do {
            return try CallbackWait.wait { [self] in
                try await takePreparedPin(
                    operationID: operationID,
                    purpose: purpose,
                    identity: identity
                )
            }
        } catch let error as CardInteractionErrorFfi {
            throw error
        } catch {
            throw CardInteractionErrorFfi.Unavailable
        }
    }

    private func takePreparedPin(
        operationID: UUID,
        purpose: CardPinPurpose,
        identity: CardIdentityFfi
    ) throws -> String {
        defer { preparedPin = nil }
        guard let preparedPin,
              preparedPin.operationID == operationID,
              preparedPin.purpose == purpose,
              preparedPin.identity == identity else {
            throw CardInteractionErrorFfi.Unavailable
        }
        return preparedPin.value
    }

    private func obtainPin(
        purpose: CardPinPurpose,
        identity: CardIdentityFfi,
        id: UUID = UUID(),
        minimumLength: Int = 6,
        maximumLength: Int = 64,
        remainingRetries: Int? = nil,
        opensNFCSession: Bool = false
    ) async throws -> String {
        guard pending == nil else {
            throw CardInteractionErrorFfi.Unavailable
        }
        try checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard pending == nil else {
                    continuation.resume(throwing: CardInteractionErrorFfi.Unavailable)
                    return
                }
                guard !Task.isCancelled else {
                    continuation.resume(throwing: CardInteractionErrorFfi.Cancelled)
                    return
                }
                pending = .pin(id, continuation)
                pin = ""
                pinRequest = CardPinRequest(
                    id: id,
                    purpose: purpose,
                    identity: identity,
                    minimumLength: minimumLength,
                    maximumLength: maximumLength,
                    remainingRetries: remainingRetries,
                    opensNFCSession: opensNFCSession
                )
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                self?.cancelInteraction(id: id)
            }
        }
    }

    private func acknowledgeTouch(slot: CardSlot) async throws {
        guard pending == nil else {
            throw CardInteractionErrorFfi.Unavailable
        }
        try checkCancellation()
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                guard pending == nil else {
                    continuation.resume(throwing: CardInteractionErrorFfi.Unavailable)
                    return
                }
                guard !Task.isCancelled else {
                    continuation.resume(throwing: CardInteractionErrorFfi.Cancelled)
                    return
                }
                pending = .touch(id, continuation)
                touchRequest = CardTouchRequest(id: id, slot: slot)
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                self?.cancelInteraction(id: id)
            }
        }
    }

    private func checkCancellation() throws {
        if Task.isCancelled {
            throw CardInteractionErrorFfi.Cancelled
        }
    }

    private func clearInteraction() {
        pending = nil
        preparedPin = nil
        pin = ""
        pinRequest = nil
        touchRequest = nil
    }
}

extension CardInteractionCoordinator: CardPinProvider, CardTouchPrompt {}

private extension CardSlot {
    var pinPurpose: CardPinPurpose {
        switch self {
        case .signing: .signing
        case .decryption, .authentication: .user
        }
    }
}
