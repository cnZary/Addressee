import Foundation

#if canImport(CryptoTokenKit)
@preconcurrency import CryptoTokenKit

public enum CryptoTokenKitTransportError: Error, Equatable, Sendable {
    case unavailable
    case readerNotFound
    case noCard
    case busy
    case closed
    case disconnected
    case invalidCapabilities
    case invalidResponse
    case timeout
    case cancelled
    case transport(domain: String, code: Int)
}

/// CryptoTokenKit objects are confined to `stateQueue`. This wrapper carries them between
/// framework callbacks without asserting that the underlying objects are thread-safe.
private struct CTKEvent<Value>: @unchecked Sendable {
    let value: Value
}

private enum CTKSessionState {
    case idle
    case connecting
    case connected
    case closed
}

public final class CryptoTokenKitTransport: NSObject, @unchecked Sendable, APDUTransport {
    private let stateQueue = DispatchQueue(label: "app.addressee.crypto-token-kit")
    private let queueKey = DispatchSpecificKey<UInt8>()
    private let timeout: TimeInterval
    private var state: CTKSessionState = .idle
    private var card: TKSmartCard?
    private var slot: TKSmartCardSlot?
    private var configuredCapabilities = APDUTransportCapabilities.shortOnly
    private var connectionOperation: TransportOperation<Void>?
    private var transmissionOperation: TransportOperation<Data>?
    private var timeoutWorkItem: DispatchWorkItem?

    public init(timeout: TimeInterval = 60) {
        self.timeout = timeout
        super.init()
        stateQueue.setSpecific(key: queueKey, value: 1)
    }

    public var capabilities: APDUTransportCapabilities {
        sync { [self] in configuredCapabilities }
    }

    public func updateCapabilities(_ capabilities: APDUTransportCapabilities) async throws {
        try sync { [self] in
            guard state == .connected else {
                throw CryptoTokenKitTransportError.closed
            }
            guard capabilities.maximumCommandDataLength > 0,
                  capabilities.maximumResponseLength > 0,
                  capabilities.maximumContinuationRounds > 0 else {
                throw CryptoTokenKitTransportError.invalidCapabilities
            }
            configuredCapabilities = APDUTransportCapabilities(
                supportsExtendedLength: configuredCapabilities.supportsExtendedLength
                    && capabilities.supportsExtendedLength,
                maximumCommandDataLength: min(
                    configuredCapabilities.maximumCommandDataLength,
                    capabilities.maximumCommandDataLength
                ),
                maximumResponseLength: min(
                    configuredCapabilities.maximumResponseLength,
                    capabilities.maximumResponseLength
                ),
                maximumContinuationRounds: min(
                    configuredCapabilities.maximumContinuationRounds,
                    capabilities.maximumContinuationRounds
                )
            )
        }
    }

    public func connect(readerName: String) async throws {
        if Task.isCancelled {
            throw CryptoTokenKitTransportError.cancelled
        }
        let operation = TransportOperation<Void>(cancellationError: CryptoTokenKitTransportError.cancelled)
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                sync { [self] in
                    guard operation.register(continuation) else { return }
                    guard operation.isActive && !Task.isCancelled else {
                        operation.cancel()
                        operation.complete(throwing: CryptoTokenKitTransportError.cancelled)
                        return
                    }
                    guard state == .idle else {
                        let error: CryptoTokenKitTransportError = state == .connecting ? .busy : .closed
                        operation.complete(throwing: error)
                        return
                    }
                    guard let manager = TKSmartCardSlotManager.default else {
                        state = .closed
                        operation.complete(throwing: CryptoTokenKitTransportError.unavailable)
                        return
                    }
                    guard manager.slotNames.contains(readerName) else {
                        state = .closed
                        operation.complete(throwing: CryptoTokenKitTransportError.readerNotFound)
                        return
                    }
                    state = .connecting
                    connectionOperation = operation
                    armTimeout()
                    manager.getSlot(withName: readerName) { slot in
                        let event = CTKEvent(value: slot)
                        self.stateQueue.async {
                            self.receiveSlot(event.value, operation: operation)
                        }
                    }
                }
            }
        } onCancel: {
            guard operation.cancel() else { return }
            stateQueue.async {
                self.cancelConnection(operation)
            }
        }
    }

    public func transmit(_ command: Data) async throws -> Data {
        if Task.isCancelled {
            throw CryptoTokenKitTransportError.cancelled
        }
        let rawCommand = command
        let command = try APDUCommand(raw: rawCommand)
        let operation = TransportOperation<Data>(cancellationError: CryptoTokenKitTransportError.cancelled)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                sync { [self] in
                    guard operation.register(continuation) else { return }
                    guard operation.isActive && !Task.isCancelled else {
                        operation.cancel()
                        operation.complete(throwing: CryptoTokenKitTransportError.cancelled)
                        return
                    }
                    guard state == .connected, let card else {
                        operation.complete(throwing: CryptoTokenKitTransportError.closed)
                        return
                    }
                    guard card.isValid else {
                        operation.complete(throwing: CryptoTokenKitTransportError.disconnected)
                        return
                    }
                    guard transmissionOperation == nil else {
                        operation.complete(throwing: CryptoTokenKitTransportError.busy)
                        return
                    }
                    do {
                        try command.validate(using: configuredCapabilities)
                    } catch {
                        operation.complete(throwing: error)
                        return
                    }
                    card.cla = command.instructionClass
                    card.useExtendedLength = command.requiresExtendedLength
                    card.useCommandChaining = false
                    transmissionOperation = operation
                    armTimeout()
                    card.transmit(rawCommand) { data, error in
                        let event = CTKEvent(value: (data, error))
                        self.stateQueue.async {
                            self.completeTransmission(event.value, operation: operation)
                        }
                    }
                }
            }
        } onCancel: {
            guard operation.cancel() else { return }
            stateQueue.async {
                self.cancelTransmission(operation)
            }
        }
    }

    public func close() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            stateQueue.async {
                self.failAndInvalidate(.closed)
                continuation.resume()
            }
        }
    }

    public static func readerNames() throws -> [String] {
        guard let manager = TKSmartCardSlotManager.default else {
            throw CryptoTokenKitTransportError.unavailable
        }
        return Array(Set(manager.slotNames)).sorted()
    }

    static func capabilities(
        maxInputLength: Int,
        maxOutputLength: Int
    ) -> APDUTransportCapabilities {
        let supportsExtendedLength = maxInputLength >= 264 && maxOutputLength >= 259
        let commandData = supportsExtendedLength
            ? min(65_535, maxInputLength - 9)
            : maxInputLength > 0 ? max(0, min(255, maxInputLength - 5)) : 255
        let responseData = maxOutputLength > 0
            ? min(65_536, max(0, maxOutputLength - 2))
            : 65_536
        return APDUTransportCapabilities(
            supportsExtendedLength: supportsExtendedLength && commandData > 255,
            maximumCommandDataLength: commandData,
            maximumResponseLength: responseData
        )
    }

    private func receiveSlot(_ slot: TKSmartCardSlot?, operation: TransportOperation<Void>) {
        guard state == .connecting, connectionOperation === operation, operation.isActive else { return }
        guard let slot, let card = slot.makeSmartCard() else {
            failAndInvalidate(.noCard)
            return
        }
        self.slot = slot
        self.card = card
        card.useExtendedLength = false
        card.useCommandChaining = false
        configuredCapabilities = Self.capabilities(
            maxInputLength: slot.maxInputLength,
            maxOutputLength: slot.maxOutputLength
        )
        card.beginSession(reply: { success, error in
            let event = CTKEvent(value: (success, error))
            self.stateQueue.async {
                self.completeConnection(event.value, operation: operation)
            }
        })
    }

    private func completeConnection(
        _ event: (Bool, Error?),
        operation: TransportOperation<Void>
    ) {
        let (success, error) = event
        guard state == .connecting, connectionOperation === operation, operation.isActive else { return }
        if let error {
            failAndInvalidate(Self.mapError(error))
            return
        }
        guard success else {
            failAndInvalidate(.noCard)
            return
        }
        state = .connected
        cancelTimeout()
        connectionOperation = nil
        operation.complete(returning: ())
    }

    private func completeTransmission(
        _ event: (Data?, Error?),
        operation: TransportOperation<Data>
    ) {
        let (data, error) = event
        guard state == .connected, transmissionOperation === operation, operation.isActive else { return }
        transmissionOperation = nil
        cancelTimeout()
        do {
            if let error { throw Self.mapError(error) }
            operation.complete(returning: try Self.rawResponse(data))
        } catch {
            operation.complete(throwing: error)
        }
    }

    static func rawResponse(_ response: Data?) throws -> Data {
        guard let response, response.count >= 2 else {
            throw CryptoTokenKitTransportError.invalidResponse
        }
        return response
    }

    private func cancelConnection(_ operation: TransportOperation<Void>) {
        guard connectionOperation === operation else { return }
        failAndInvalidate(.cancelled)
    }

    private func cancelTransmission(_ operation: TransportOperation<Data>) {
        guard transmissionOperation === operation else { return }
        failAndInvalidate(.cancelled)
    }

    private func failAndInvalidate(_ error: CryptoTokenKitTransportError) {
        guard state != .closed else { return }
        cancelTimeout()
        connectionOperation?.complete(throwing: error)
        transmissionOperation?.complete(throwing: error)
        connectionOperation = nil
        transmissionOperation = nil
        card?.endSession()
        card = nil
        slot = nil
        state = .closed
    }

    private func armTimeout() {
        cancelTimeout()
        let work = DispatchWorkItem { [weak self] in
            self?.timeoutReached()
        }
        timeoutWorkItem = work
        stateQueue.asyncAfter(deadline: .now() + timeout, execute: work)
    }

    private func cancelTimeout() {
        timeoutWorkItem?.cancel()
        timeoutWorkItem = nil
    }

    private func timeoutReached() {
        guard connectionOperation != nil || transmissionOperation != nil else { return }
        failAndInvalidate(.timeout)
    }

    private static func mapError(_ error: Error) -> CryptoTokenKitTransportError {
        let error = error as NSError
        if error.domain == TKErrorDomain, error.code == TKError.Code.canceledByUser.rawValue {
            return .cancelled
        }
        return .transport(domain: error.domain, code: error.code)
    }

    private func sync<T>(_ body: @escaping () throws -> T) rethrows -> T {
        if DispatchQueue.getSpecific(key: queueKey) == 1 {
            return try body()
        }
        return try stateQueue.sync(execute: body)
    }
}
#endif
