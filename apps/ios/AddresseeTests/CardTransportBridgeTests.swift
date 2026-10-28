import XCTest
import AppleSmartCardTransport
@testable import Addressee

private actor ScriptedAPDUTransport: APDUTransport {
    nonisolated let capabilities: APDUTransportCapabilities
    private let handler: @Sendable (Data) async throws -> Data

    init(
        capabilities: APDUTransportCapabilities = .shortOnly,
        handler: @escaping @Sendable (Data) async throws -> Data
    ) {
        self.capabilities = capabilities
        self.handler = handler
    }

    func transmit(_ command: Data) async throws -> Data {
        try await handler(command)
    }

    func close() async throws {}
}

final class CardTransportBridgeTests: XCTestCase {
    func testRawStatusIsReturnedWithoutTransportLevelRetry() async throws {
        let transport = ScriptedAPDUTransport { _ in Data([0x61, 0x02]) }
        let bridge = CardTransportBridge(transport: transport, capabilities: .shortOnly)

        let response = try await Task.detached {
            try bridge.transmit(command: Data([0x00, 0xCA, 0x00, 0x6E, 0x00]), responseBufferSize: 258)
        }.value

        XCTAssertEqual(response, Data([0x61, 0x02]))
        XCTAssertEqual(bridge.capabilities().maximumCommandLength, 261)
        XCTAssertEqual(bridge.capabilities().maximumResponseLength, 65_538)
    }

    func testOversizedResponseFailsWithoutTruncationAndReportsFailure() async throws {
        let capabilities = APDUTransportCapabilities(
            supportsExtendedLength: false,
            maximumCommandDataLength: 255,
            maximumResponseLength: 4
        )
        let transport = ScriptedAPDUTransport(capabilities: capabilities) { _ in
            Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x90, 0x00])
        }
        let recorder = FailureRecorder()
        let bridge = CardTransportBridge(
            transport: transport,
            capabilities: capabilities,
            onFailure: { recorder.record($0) }
        )

        do {
            _ = try await Task.detached {
                try bridge.transmit(command: Data([0x00, 0xCA, 0x00, 0x6E]), responseBufferSize: 6)
            }.value
            XCTFail("Expected an oversized response to fail")
        } catch {
            XCTAssertEqual(error as? CardTransportError, .Failure)
        }
        XCTAssertEqual(recorder.error, .Failure)
    }

    func testCancellationIsPreservedAcrossTheAsyncBridge() async {
        let transport = ScriptedAPDUTransport { _ in throw CancellationError() }
        let bridge = CardTransportBridge(transport: transport, capabilities: .shortOnly)

        do {
            _ = try await Task.detached {
                try bridge.transmit(command: Data([0x00, 0x20, 0x00, 0x82]), responseBufferSize: 2)
            }.value
            XCTFail("Expected cancellation")
        } catch {
            XCTAssertEqual(error as? CardTransportError, .Cancelled)
        }
    }

    func testDiagnosticsPreserveRawStatusAndSanitizedSystemCode() async throws {
        let diagnostics = CardSessionDiagnostics(method: .usb)
        let transport = ScriptedAPDUTransport { _ in Data([0x63, 0xC2]) }
        let bridge = CardTransportBridge(
            transport: transport,
            capabilities: .shortOnly,
            onStatus: { diagnostics.record(status: $0) },
            onDiagnostic: { diagnostics.record($0) }
        )
        _ = try await Task.detached {
            try bridge.transmit(command: Data([0x00, 0x20, 0x00, 0x82]), responseBufferSize: 2)
        }.value
        #if canImport(CryptoTokenKit)
        diagnostics.record(CryptoTokenKitTransportError.transport(domain: NSOSStatusErrorDomain, code: -600))
        #endif
        let failure = try XCTUnwrap(
            diagnostics.failure(AddresseeError.InvalidPassword, stage: .privateKeyOperation)
                as? CardSessionFailure
        )
        XCTAssertEqual(failure.underlying as? AddresseeError, .InvalidPassword)
        XCTAssertEqual(failure.diagnostic.stage, .privateKeyOperation)
        XCTAssertEqual(failure.diagnostic.method, .usb)
        XCTAssertEqual(failure.diagnostic.status, 0x63C2)
        let message = ErrorPresenter.message(for: failure)
        XCTAssertTrue(message.hasPrefix(String(localized: "error.invalidPassword")))
        XCTAssertTrue(message.contains("SW 63C2"))
        #if canImport(CryptoTokenKit)
        XCTAssertTrue(message.contains("NSOSStatusErrorDomain -600"))
        #endif
    }

    func testDiagnosticPresentationNeverIncludesArbitraryErrorText() throws {
        let marker = "synthetic-secret-that-must-not-appear"
        let diagnostics = CardSessionDiagnostics(method: .nfc)
        diagnostics.record(NSError(domain: marker, code: -7))
        let failure = try XCTUnwrap(
            diagnostics.failure(AddresseeError.ConflictingCertificate, stage: .reading)
                as? CardSessionFailure
        )
        let message = ErrorPresenter.message(for: failure)
        XCTAssertTrue(message.hasPrefix(String(localized: "error.conflictingCertificate")))
        XCTAssertFalse(message.contains(marker))
        XCTAssertNil(failure.diagnostic.domain)
        #if canImport(CryptoTokenKit)
        diagnostics.record(CryptoTokenKitTransportError.transport(domain: marker, code: -8))
        let transportFailure = try XCTUnwrap(
            diagnostics.failure(AddresseeError.RemoteKeyUnavailable, stage: .privateKeyOperation)
                as? CardSessionFailure
        )
        XCTAssertNil(transportFailure.diagnostic.domain)
        XCTAssertEqual(transportFailure.diagnostic.code, -8)
        XCTAssertFalse(ErrorPresenter.message(for: transportFailure).contains(marker))
        #endif
    }

    func testReaderGuidanceIsForwardedWithoutChangingTheTransport() async {
        let recorder = ReaderGuidanceRecorder()
        let transport = ScriptedAPDUTransport { _ in Data([0x90, 0x00]) }
        let connection = ConnectedCardTransport(
            transport: transport,
            capabilities: .shortOnly,
            onAlertMessage: { recorder.record($0) }
        )

        connection.updateAlertMessage("Card detected")
        connection.updateAlertMessage("Operation in progress")

        XCTAssertEqual(recorder.messages, ["Card detected", "Operation in progress"])
    }

    @MainActor
    func testSynchronousFFICallbackNeverBlocksTheMainThread() {
        let transport = ScriptedAPDUTransport { _ in Data([0x90, 0x00]) }
        let bridge = CardTransportBridge(transport: transport, capabilities: .shortOnly)

        XCTAssertThrowsError(
            try bridge.transmit(command: Data([0x00, 0x20, 0x00, 0x82]), responseBufferSize: 2)
        ) {
            XCTAssertEqual($0 as? CardTransportError, .Failure)
        }
    }
}

private final class FailureRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recordedError: CardTransportError?

    var error: CardTransportError? {
        lock.lock()
        defer { lock.unlock() }
        return recordedError
    }

    func record(_ error: CardTransportError) {
        lock.lock()
        recordedError = error
        lock.unlock()
    }
}

final class ReaderGuidanceRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recordedMessages: [String] = []

    var messages: [String] {
        lock.lock()
        defer { lock.unlock() }
        return recordedMessages
    }

    func record(_ message: String) {
        lock.lock()
        recordedMessages.append(message)
        lock.unlock()
    }

    func removeAll() {
        lock.lock()
        recordedMessages.removeAll()
        lock.unlock()
    }
}
