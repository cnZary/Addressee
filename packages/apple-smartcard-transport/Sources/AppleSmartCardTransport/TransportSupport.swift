import Foundation

final class TransportOperation<Value: Sendable>: @unchecked Sendable {
    private enum State {
        case pending
        case registered
        case cancelled
        case finished
    }

    private let lock = NSLock()
    private let cancellationError: Error
    private var state = State.pending
    private var continuation: CheckedContinuation<Value, Error>?

    init(cancellationError: Error) {
        self.cancellationError = cancellationError
    }

    var isActive: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state == .registered
    }

    func register(_ continuation: CheckedContinuation<Value, Error>) -> Bool {
        lock.lock()
        switch state {
        case .pending:
            self.continuation = continuation
            state = .registered
            lock.unlock()
            return true
        case .cancelled:
            state = .finished
        case .registered, .finished:
            break
        }
        lock.unlock()
        continuation.resume(throwing: cancellationError)
        return false
    }

    @discardableResult
    func cancel() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        switch state {
        case .pending:
            state = .cancelled
            return false
        case .registered:
            state = .cancelled
            return true
        case .cancelled, .finished:
            return false
        }
    }

    @discardableResult
    func complete(with result: Result<Value, Error>) -> Bool {
        lock.lock()
        guard state == .registered || state == .cancelled, let continuation else {
            lock.unlock()
            return false
        }
        state = .finished
        self.continuation = nil
        lock.unlock()
        continuation.resume(with: result)
        return true
    }

    @discardableResult
    func complete(returning value: Value) -> Bool {
        complete(with: .success(value))
    }

    @discardableResult
    func complete(throwing error: Error) -> Bool {
        complete(with: .failure(error))
    }
}

extension APDUCommand {
    var requiresExtendedLength: Bool {
        data.count > 255 || (expectedResponseLength ?? 0) > 256
    }

    func validate(using capabilities: APDUTransportCapabilities) throws {
        if requiresExtendedLength && !capabilities.supportsExtendedLength {
            throw APDUError.extendedLengthUnsupported
        }
        guard data.count <= capabilities.maximumCommandDataLength else {
            throw APDUError.commandTooLarge
        }
        if let expectedResponseLength, expectedResponseLength > capabilities.maximumResponseLength {
            throw APDUError.responseTooLarge
        }
    }
}
