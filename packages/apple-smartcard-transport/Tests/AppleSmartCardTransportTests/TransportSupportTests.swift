import Foundation
import Testing
@testable import AppleSmartCardTransport

// Host-only tests; these do not exercise framework sessions or hardware.
private enum OperationTestError: Error, Equatable {
    case cancelled
}

private actor OperationStartGate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func open() {
        isOpen = true
        let waiters = self.waiters
        self.waiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }
}

private func runPreCancelled<T: Sendable>(
    _ body: @escaping @Sendable () async throws -> T
) async throws -> T {
    let gate = OperationStartGate()
    let task = Task<T, Error> {
        await gate.wait()
        return try await body()
    }
    task.cancel()
    await gate.open()
    return try await task.value
}

@Test func preCancellationPreventsOperationActivation() async {
    let operation = TransportOperation<Int>(cancellationError: OperationTestError.cancelled)
    #expect(!operation.cancel())
    do {
        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int, Error>) in
            #expect(!operation.register(continuation))
        }
        Issue.record("Expected pre-cancellation failure")
    } catch {
        #expect(error as? OperationTestError == .cancelled)
    }
    #expect(!operation.isActive)
    #expect(!operation.complete(returning: 0))
}

@Test func cancellationAfterRegistrationCompletesOnce() async {
    let operation = TransportOperation<Int>(cancellationError: OperationTestError.cancelled)
    do {
        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int, Error>) in
            #expect(operation.register(continuation))
            #expect(operation.cancel())
            #expect(!operation.cancel())
            #expect(operation.complete(throwing: OperationTestError.cancelled))
            #expect(!operation.complete(returning: 0))
        }
        Issue.record("Expected cancellation failure")
    } catch {
        #expect(error as? OperationTestError == .cancelled)
    }
}

@Test func completionBeforeCancellationFinishesOnce() async throws {
    let operation = TransportOperation<Int>(cancellationError: OperationTestError.cancelled)
    let value = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int, Error>) in
        #expect(operation.register(continuation))
        #expect(operation.complete(returning: 42))
        #expect(!operation.cancel())
        #expect(!operation.complete(returning: 0))
    }
    #expect(value == 42)
}

@Test func cancellationRegistrationRaceAlwaysCompletes() async {
    for _ in 0..<100 {
        let operation = TransportOperation<Int>(cancellationError: OperationTestError.cancelled)
        let task = Task<Int, Error> {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int, Error>) in
                    guard operation.register(continuation) else { return }
                    guard operation.isActive && !Task.isCancelled else {
                        operation.cancel()
                        operation.complete(throwing: OperationTestError.cancelled)
                        return
                    }
                }
            } onCancel: {
                if operation.cancel() {
                    operation.complete(throwing: OperationTestError.cancelled)
                }
            }
        }
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Expected raced cancellation failure")
        } catch {
            #expect(error as? OperationTestError == .cancelled)
        }
        #expect(!operation.complete(returning: 0))
    }
}

@Test func capabilityValidationAcceptsSupportedLengths() throws {
    let short = APDUCommand(
        instructionCode: 0x2A,
        data: Data(repeating: 0xA5, count: 255),
        expectedResponseLength: 256
    )
    #expect(!short.requiresExtendedLength)
    try short.validate(using: .shortOnly)

    let extended = APDUCommand(
        instructionCode: 0x2A,
        data: Data(repeating: 0x5A, count: 256),
        expectedResponseLength: 65_536
    )
    let capabilities = APDUTransportCapabilities(
        supportsExtendedLength: true,
        maximumCommandDataLength: 512,
        maximumResponseLength: 65_536
    )
    #expect(extended.requiresExtendedLength)
    try extended.validate(using: capabilities)
}

@Test func capabilityValidationRejectsExtendedLengthForShortOnly() {
    let command = APDUCommand(instructionCode: 0xDB, data: Data(repeating: 0, count: 256))
    #expect(throws: APDUError.extendedLengthUnsupported) {
        try command.validate(using: .shortOnly)
    }

    let response = APDUCommand(instructionCode: 0xCA, expectedResponseLength: 257)
    #expect(throws: APDUError.extendedLengthUnsupported) {
        try response.validate(using: .shortOnly)
    }
}

@Test func capabilityValidationEnforcesConfiguredLimits() {
    let capabilities = APDUTransportCapabilities(
        supportsExtendedLength: true,
        maximumCommandDataLength: 4,
        maximumResponseLength: 8
    )
    let command = APDUCommand(instructionCode: 0x20, data: Data(repeating: 0, count: 5))
    #expect(throws: APDUError.commandTooLarge) {
        try command.validate(using: capabilities)
    }

    let response = APDUCommand(instructionCode: 0xCA, expectedResponseLength: 9)
    #expect(throws: APDUError.responseTooLarge) {
        try response.validate(using: capabilities)
    }
}

#if canImport(CryptoTokenKit)
@Test func cryptoTokenKitRawResponsesPreserveStatusAndAllData() throws {
    let response = Data([0x01, 0x02, 0x61, 0x25])
    #expect(try CryptoTokenKitTransport.rawResponse(response) == response)
    #expect(throws: CryptoTokenKitTransportError.invalidResponse) {
        try CryptoTokenKitTransport.rawResponse(Data([0x90]))
    }
    #expect(throws: CryptoTokenKitTransportError.invalidResponse) {
        try CryptoTokenKitTransport.rawResponse(nil)
    }
}

@Test func cryptoTokenKitCapabilitiesAccountForAPDUFraming() {
    let short = CryptoTokenKitTransport.capabilities(maxInputLength: 261, maxOutputLength: 258)
    #expect(!short.supportsExtendedLength)
    #expect(short.maximumCommandDataLength == 255)
    #expect(short.maximumResponseLength == 256)

    let extended = CryptoTokenKitTransport.capabilities(maxInputLength: 4096, maxOutputLength: 4096)
    #expect(extended.supportsExtendedLength)
    #expect(extended.maximumCommandDataLength == 4087)
    #expect(extended.maximumResponseLength == 4094)

    let insufficient = CryptoTokenKitTransport.capabilities(maxInputLength: 263, maxOutputLength: 258)
    #expect(!insufficient.supportsExtendedLength)
    #expect(insufficient.maximumCommandDataLength == 255)

    let unknown = CryptoTokenKitTransport.capabilities(maxInputLength: 0, maxOutputLength: 0)
    #expect(unknown == .shortOnly)
}

@Test func cryptoTokenKitConnectRejectsPreCancelledTask() async {
    let transport = CryptoTokenKitTransport()
    do {
        try await runPreCancelled {
            try await transport.connect(readerName: "host-only-no-reader")
        }
        Issue.record("Expected pre-cancellation failure")
    } catch {
        #expect(error as? CryptoTokenKitTransportError == .cancelled)
    }
    await transport.close()
}

@Test func cryptoTokenKitTransmitRejectsPreCancelledTask() async {
    let transport = CryptoTokenKitTransport()
    let command = Data([0x00, 0xA4, 0x00, 0x00])
    do {
        _ = try await runPreCancelled {
            try await transport.transmit(command)
        }
        Issue.record("Expected pre-cancellation failure")
    } catch {
        #expect(error as? CryptoTokenKitTransportError == .cancelled)
    }
    await transport.close()
}

@Test func cryptoTokenKitCommandValidationWorksWithoutHardware() async {
    let transport = CryptoTokenKitTransport()
    do {
        _ = try await transport.transmit(Data([0x00, 0xA4, 0x00]))
        Issue.record("Expected malformed-command failure")
    } catch {
        #expect(error as? APDUError == .malformedCommand)
    }

    do {
        _ = try await transport.transmit(Data([0x00, 0xA4, 0x00, 0x00]))
        Issue.record("Expected closed-transport failure")
    } catch {
        #expect(error as? CryptoTokenKitTransportError == .closed)
    }
    await transport.close()
}
#endif
