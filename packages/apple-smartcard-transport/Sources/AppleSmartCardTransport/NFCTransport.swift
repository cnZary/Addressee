import Foundation

#if canImport(CoreNFC)
@preconcurrency import CoreNFC

public enum NFCTransportError: Error, Equatable, Sendable {
    case unavailable
    case busy
    case closed
    case disconnected
    case invalidCommand
    case invalidCapabilities
    case multipleTags
    case unsupportedTag
    case timeout
    case cancelled
    case transport(domain: String, code: Int)
}

/// NFC objects are confined to `stateQueue`. This wrapper carries them between framework callbacks
/// without asserting that the underlying Objective-C objects are thread-safe.
private struct NFCEvent<Value>: @unchecked Sendable {
    let value: Value
}

private enum NFCSessionState {
    case idle
    case connecting
    case connected
    case closing
    case closed
}

public final class NFCTransport: NSObject, @unchecked Sendable, APDUTransport, NFCTagReaderSessionDelegate {
    private let stateQueue = DispatchQueue(label: "app.addressee.nfc-transport")
    private let queueKey = DispatchSpecificKey<UInt8>()
    private let alertMessage: String
    private let timeout: TimeInterval
    private var state: NFCSessionState = .idle
    private var session: NFCTagReaderSession?
    private var tag: (any NFCISO7816Tag)?
    private var configuredCapabilities = APDUTransportCapabilities.shortOnly
    private var connectionOperation: TransportOperation<Void>?
    private var transmissionOperation: TransportOperation<Data>?
    private var closeContinuations: [CheckedContinuation<Void, Never>] = []
    private var timeoutWorkItem: DispatchWorkItem?
    private var terminalError: NFCTransportError?

    public init(alertMessage: String, timeout: TimeInterval = 60) {
        self.alertMessage = alertMessage
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
                throw NFCTransportError.closed
            }
            guard capabilities.maximumCommandDataLength > 0,
                  capabilities.maximumResponseLength > 0,
                  capabilities.maximumContinuationRounds > 0 else {
                throw NFCTransportError.invalidCapabilities
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

    public func connect() async throws {
        if Task.isCancelled {
            throw NFCTransportError.cancelled
        }
        let operation = TransportOperation<Void>(cancellationError: NFCTransportError.cancelled)
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                sync { [self] in
                    guard operation.register(continuation) else { return }
                    guard operation.isActive && !Task.isCancelled else {
                        operation.cancel()
                        operation.complete(throwing: NFCTransportError.cancelled)
                        return
                    }
                    guard NFCTagReaderSession.readingAvailable else {
                        operation.complete(throwing: NFCTransportError.unavailable)
                        return
                    }
                    guard state == .idle else {
                        let error: NFCTransportError = state == .connecting ? .busy : .closed
                        operation.complete(throwing: error)
                        return
                    }
                    state = .connecting
                    connectionOperation = operation
                    guard let session = NFCTagReaderSession(
                        pollingOption: [.iso14443],
                        delegate: self,
                        queue: stateQueue
                    ) else {
                        state = .closed
                        connectionOperation = nil
                        operation.complete(throwing: NFCTransportError.unavailable)
                        return
                    }
                    session.alertMessage = alertMessage
                    self.session = session
                    armTimeout()
                    session.begin()
                }
            }
        } onCancel: {
            guard operation.cancel() else { return }
            stateQueue.async {
                self.cancelConnection(operation)
            }
        }
    }

    public func updateAlertMessage(_ message: String) {
        sync { [self] in
            guard state == .connecting || state == .connected, !message.isEmpty else { return }
            session?.alertMessage = message
        }
    }

    public func transmit(_ command: Data) async throws -> Data {
        if Task.isCancelled {
            throw NFCTransportError.cancelled
        }
        let rawCommand = command
        let command: APDUCommand
        do {
            command = try APDUCommand(raw: rawCommand)
        } catch {
            throw NFCTransportError.invalidCommand
        }
        let operation = TransportOperation<Data>(cancellationError: NFCTransportError.cancelled)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                sync { [self] in
                    guard operation.register(continuation) else { return }
                    guard operation.isActive && !Task.isCancelled else {
                        operation.cancel()
                        operation.complete(throwing: NFCTransportError.cancelled)
                        return
                    }
                    guard state == .connected else {
                        operation.complete(throwing: NFCTransportError.closed)
                        return
                    }
                    guard let tag, session?.isReady == true else {
                        operation.complete(throwing: NFCTransportError.disconnected)
                        return
                    }
                    guard transmissionOperation == nil else {
                        operation.complete(throwing: NFCTransportError.busy)
                        return
                    }
                    do {
                        try command.validate(using: configuredCapabilities)
                    } catch {
                        operation.complete(throwing: error)
                        return
                    }
                    guard let apdu = NFCISO7816APDU(data: rawCommand) else {
                        operation.complete(throwing: NFCTransportError.invalidCommand)
                        return
                    }
                    transmissionOperation = operation
                    armTimeout()
                    tag.sendCommand(apdu: apdu) { result in
                        let event = NFCEvent(value: result)
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
        await close(successMessage: nil)
    }

    public func close(successMessage: String) async {
        await close(successMessage: Optional(successMessage))
    }

    private func close(successMessage: String?) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            sync { [self] in
                guard state != .closed else {
                    continuation.resume()
                    return
                }
                closeContinuations.append(continuation)
                guard state != .closing else { return }
                if let successMessage, state == .connected {
                    session?.alertMessage = successMessage
                }
                state = .closing
                terminalError = .closed
                cancelTimeout()
                connectionOperation?.complete(throwing: NFCTransportError.closed)
                transmissionOperation?.complete(throwing: NFCTransportError.closed)
                connectionOperation = nil
                transmissionOperation = nil
                if let session {
                    session.invalidate()
                } else {
                    state = .closed
                    finishClose()
                }
            }
        }
    }

    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    public func tagReaderSession(
        _ session: NFCTagReaderSession,
        didInvalidateWithError error: Error
    ) {
        let event = NFCEvent(value: (session, error))
        stateQueue.async {
            self.completeInvalidation(event.value)
        }
    }

    public func tagReaderSession(
        _ session: NFCTagReaderSession,
        didDetect tags: [NFCTag]
    ) {
        let event = NFCEvent(value: (session, tags))
        stateQueue.async {
            self.detectTags(event.value)
        }
    }

    private func detectTags(_ event: (NFCTagReaderSession, [NFCTag])) {
        let (session, tags) = event
        guard state == .connecting, self.session === session,
              let operation = connectionOperation, operation.isActive else { return }
        guard tags.count == 1 else {
            failAndInvalidate(.multipleTags)
            return
        }
        guard let detectedTag = tags.first, case .iso7816(let tag) = detectedTag else {
            failAndInvalidate(.unsupportedTag)
            return
        }
        let connection = NFCEvent(value: (session, tag))
        session.connect(to: detectedTag) { error in
            let event = NFCEvent(value: (connection.value.0, connection.value.1, error))
            self.stateQueue.async {
                self.completeConnection(event.value, operation: operation)
            }
        }
    }

    private func completeConnection(
        _ event: (NFCTagReaderSession, any NFCISO7816Tag, Error?),
        operation: TransportOperation<Void>
    ) {
        let (session, tag, error) = event
        guard state == .connecting, self.session === session,
              connectionOperation === operation, operation.isActive else { return }
        if let error {
            failAndInvalidate(Self.mapError(error))
            return
        }
        self.tag = tag
        state = .connected
        cancelTimeout()
        connectionOperation = nil
        operation.complete(returning: ())
    }

    private func completeTransmission(
        _ result: Result<NFCISO7816ResponseAPDU, Error>,
        operation: TransportOperation<Data>
    ) {
        guard state == .connected, transmissionOperation === operation, operation.isActive else { return }
        transmissionOperation = nil
        cancelTimeout()
        switch result {
        case .success(let response):
            var data = response.payload ?? Data()
            data.append(response.statusWord1)
            data.append(response.statusWord2)
            operation.complete(returning: data)
        case .failure(let error):
            operation.complete(throwing: Self.mapError(error))
        }
    }

    private func completeInvalidation(_ event: (NFCTagReaderSession, Error)) {
        let (session, error) = event
        guard self.session === session else { return }
        cancelTimeout()
        let failure = terminalError ?? Self.mapError(error)
        connectionOperation?.complete(throwing: failure)
        transmissionOperation?.complete(throwing: failure)
        connectionOperation = nil
        transmissionOperation = nil
        self.session = nil
        tag = nil
        state = .closed
        finishClose()
    }

    private func cancelConnection(_ operation: TransportOperation<Void>) {
        guard connectionOperation === operation else { return }
        failAndInvalidate(.cancelled)
    }

    private func cancelTransmission(_ operation: TransportOperation<Data>) {
        guard transmissionOperation === operation else { return }
        failAndInvalidate(.cancelled)
    }

    private func failAndInvalidate(_ error: NFCTransportError) {
        guard state != .closed else { return }
        state = .closing
        terminalError = error
        cancelTimeout()
        connectionOperation?.complete(throwing: error)
        transmissionOperation?.complete(throwing: error)
        connectionOperation = nil
        transmissionOperation = nil
        if let session {
            session.invalidate()
        } else {
            state = .closed
            finishClose()
        }
    }

    private func finishClose() {
        let continuations = closeContinuations
        closeContinuations.removeAll()
        for continuation in continuations {
            continuation.resume()
        }
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

    private static func mapError(_ error: Error) -> NFCTransportError {
        let error = error as NSError
        if error.domain == NFCErrorDomain {
            switch error.code {
            case NFCReaderError.readerSessionInvalidationErrorUserCanceled.rawValue:
                return .cancelled
            case NFCReaderError.readerSessionInvalidationErrorSessionTimeout.rawValue:
                return .timeout
            default:
                break
            }
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
