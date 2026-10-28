import Foundation
import AppleSmartCardTransport

#if canImport(CoreNFC)
import CoreNFC
#endif
#if canImport(CryptoTokenKit)
import CryptoTokenKit
#endif

private enum CallbackWaitError: Error {
    case mainThread
    case missingResult
}

private final class CallbackResult<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Value, Error>?

    func complete(with result: Result<Value, Error>) {
        lock.lock()
        if self.result == nil {
            self.result = result
        }
        lock.unlock()
    }

    func get() throws -> Value {
        lock.lock()
        let result = result
        lock.unlock()
        guard let result else {
            throw CallbackWaitError.missingResult
        }
        return try result.get()
    }
}

enum CallbackWait {
    static func wait<Value: Sendable>(
        for operation: @escaping @Sendable () async throws -> Value
    ) throws -> Value {
        guard !Thread.isMainThread else {
            throw CallbackWaitError.mainThread
        }
        let semaphore = DispatchSemaphore(value: 0)
        let result = CallbackResult<Value>()
        Task.detached(priority: .userInitiated) {
            do {
                let value = try await operation()
                result.complete(with: .success(value))
            } catch {
                result.complete(with: .failure(error))
            }
            semaphore.signal()
        }
        semaphore.wait()
        return try result.get()
    }
}

enum CardOperationStage: String, Sendable {
    case connecting
    case reading
    case privateKeyOperation
    case management
}

enum CardDiagnosticKind: String, Sendable {
    case unavailable
    case disconnected
    case timeout
    case cancelled
    case invalidResponse
    case transport
    case operation
}

struct CardSessionDiagnostic: Equatable, Sendable {
    let stage: CardOperationStage
    let method: CardConnectionMethod
    let kind: CardDiagnosticKind
    let domain: String?
    let code: Int?
    let status: UInt16?

    var presentation: String {
        var lines = [
            NSLocalizedString("hardware.transport.\(method.rawValue)", comment: ""),
            NSLocalizedString("error.cardStage.\(stage.rawValue)", comment: ""),
            NSLocalizedString("error.cardKind.\(kind.rawValue)", comment: ""),
        ]
        if let domain, let code {
            lines.append("\(domain) \(code)")
        }
        if let status {
            lines.append(String(format: "SW %04X", status))
        }
        return lines.joined(separator: "\n")
    }
}

struct CardSessionFailure: Error {
    let underlying: Error
    let diagnostic: CardSessionDiagnostic
}

final class CardSessionDiagnostics: @unchecked Sendable {
    private let lock = NSLock()
    private let method: CardConnectionMethod
    private var stage = CardOperationStage.reading
    private var status: UInt16?
    private var transportFailure: Error?

    init(method: CardConnectionMethod) {
        self.method = method
    }

    func begin(_ stage: CardOperationStage) {
        lock.lock()
        self.stage = stage
        lock.unlock()
    }

    func record(status: UInt16) {
        lock.lock()
        self.status = status == 0x9000 ? nil : status
        if status == 0x9000 { transportFailure = nil }
        lock.unlock()
    }

    func record(_ error: Error) {
        lock.lock()
        transportFailure = error
        lock.unlock()
    }

    func failure(_ error: Error, stage override: CardOperationStage? = nil) -> Error {
        if let error = error as? CardSessionFailure { return error }
        lock.lock()
        let stage = override ?? stage
        let transportFailure = transportFailure
        let status = status
        lock.unlock()
        let diagnosticError = transportFailure ?? error
        var kind = CardDiagnosticKind.operation
        var domain: String?
        var code: Int?
        #if canImport(CryptoTokenKit)
        if let error = diagnosticError as? CryptoTokenKitTransportError {
            switch error {
            case .unavailable, .readerNotFound, .noCard, .busy, .closed:
                kind = .unavailable
            case .disconnected:
                kind = .disconnected
            case .invalidCapabilities, .invalidResponse:
                kind = .invalidResponse
            case .timeout:
                kind = .timeout
            case .cancelled:
                kind = .cancelled
            case .transport(let reportedDomain, let reportedCode):
                kind = .transport
                domain = Self.safeDomain(reportedDomain)
                code = reportedCode
            }
        }
        #endif
        #if canImport(CoreNFC)
        if let error = diagnosticError as? NFCTransportError {
            switch error {
            case .unavailable, .busy, .closed, .multipleTags, .unsupportedTag:
                kind = .unavailable
            case .cancelled:
                kind = .cancelled
            case .timeout:
                kind = .timeout
            case .disconnected:
                kind = .disconnected
            case .invalidCommand, .invalidCapabilities:
                kind = .invalidResponse
            case .transport(let reportedDomain, let reportedCode):
                kind = .transport
                domain = Self.safeDomain(reportedDomain)
                code = reportedCode
            }
        }
        #endif
        if diagnosticError is APDUError { kind = .invalidResponse }
        return CardSessionFailure(
            underlying: error,
            diagnostic: CardSessionDiagnostic(
                stage: stage,
                method: method,
                kind: kind,
                domain: domain,
                code: code,
                status: status
            )
        )
    }

    private static func safeDomain(_ domain: String) -> String? {
        #if canImport(CryptoTokenKit)
        if domain == TKErrorDomain { return domain }
        #endif
        #if canImport(CoreNFC)
        if domain == NFCErrorDomain { return domain }
        #endif
        return domain == NSOSStatusErrorDomain ? domain : nil
    }
}

final class CardTransportBridge: CardTransport {
    private let transport: any APDUTransport
    private let transportCapabilities: CardTransportCapabilities
    private let onFailure: @Sendable (CardTransportError) -> Void
    private let onStatus: @Sendable (UInt16) -> Void
    private let onDiagnostic: @Sendable (Error) -> Void

    init(
        transport: any APDUTransport,
        capabilities: APDUTransportCapabilities,
        onFailure: (@Sendable (CardTransportError) -> Void)? = nil,
        onStatus: (@Sendable (UInt16) -> Void)? = nil,
        onDiagnostic: (@Sendable (Error) -> Void)? = nil
    ) {
        self.transport = transport
        let commandData = min(65_535, UInt32(clamping: capabilities.maximumCommandDataLength))
        let maximumCommandLength = capabilities.supportsExtendedLength
            ? min(65_544, commandData + 9)
            : min(261, commandData + 6)
        let responseData = min(65_536, UInt32(clamping: capabilities.maximumResponseLength))
        transportCapabilities = CardTransportCapabilities(
            supportsExtendedLength: capabilities.supportsExtendedLength,
            supportsCommandChaining: true,
            maximumCommandLength: maximumCommandLength,
            maximumCommandDataLength: commandData,
            maximumResponseLength: responseData + 2
        )
        self.onFailure = onFailure ?? { _ in }
        self.onStatus = onStatus ?? { _ in }
        self.onDiagnostic = onDiagnostic ?? { _ in }
    }

    func capabilities() -> CardTransportCapabilities {
        transportCapabilities
    }

    func transmit(command: Data, responseBufferSize: UInt32) throws -> Data {
        guard !Thread.isMainThread else {
            throw CardTransportError.Failure
        }
        guard command.count >= 4,
              command.count <= Int(transportCapabilities.maximumCommandLength) else {
            throw CardTransportError.Failure
        }
        let responseLimit = responseBufferSize >= 2
            ? min(transportCapabilities.maximumResponseLength, responseBufferSize)
            : transportCapabilities.maximumResponseLength
        do {
            let response = try CallbackWait.wait { [transport] in
                try await transport.transmit(command)
            }
            guard response.count >= 2, response.count <= Int(responseLimit) else {
                onFailure(.Failure)
                throw CardTransportError.Failure
            }
            onStatus(UInt16(response[response.count - 2]) << 8 | UInt16(response[response.count - 1]))
            return response
        } catch let error as CardTransportError {
            throw error
        } catch {
            onDiagnostic(error)
            let mapped = Self.map(error)
            onFailure(mapped)
            throw mapped
        }
    }

    private static func map(_ error: Error) -> CardTransportError {
        if error is CancellationError {
            return .Cancelled
        }
        #if canImport(CoreNFC)
        if let error = error as? NFCTransportError {
            switch error {
            case .unavailable, .busy, .closed:
                return .Unavailable
            case .cancelled:
                return .Cancelled
            case .timeout:
                return .Timeout
            case .disconnected:
                return .Disconnected
            case .invalidCommand, .invalidCapabilities, .multipleTags, .unsupportedTag, .transport:
                return .Failure
            }
        }
        #endif
        #if canImport(CryptoTokenKit)
        if let error = error as? CryptoTokenKitTransportError {
            switch error {
            case .unavailable, .readerNotFound, .busy, .closed:
                return .Unavailable
            case .cancelled:
                return .Cancelled
            case .timeout:
                return .Timeout
            case .noCard, .disconnected:
                return .Disconnected
            case .invalidCapabilities, .invalidResponse, .transport:
                return .Failure
            }
        }
        #endif
        return .Failure
    }
}
