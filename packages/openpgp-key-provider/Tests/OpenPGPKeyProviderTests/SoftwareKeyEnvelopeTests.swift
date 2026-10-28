import Foundation
import XCTest
@testable import OpenPGPKeyProvider

@MainActor
final class SoftwareKeyEnvelopeTests: XCTestCase {
    private var store: SoftwareKeyEnvelopeStore!
    private let identifier = String(repeating: "A", count: 40)

    override func setUp() async throws {
        store = SoftwareKeyEnvelopeStore(
            service: "app.addressee.tests.\(UUID().uuidString)"
        )
    }

    override func tearDown() async throws {
        if ProcessInfo.processInfo.environment["ADDRESSEE_KEYCHAIN_TESTS"] == "1" {
            try await store.deleteWrappingKey(identifier: identifier)
        }
    }

    func testInvalidIdentifiersAndPoliciesAreRejectedBeforeKeychainAccess() async throws {
        do {
            _ = try await store.seal(Data(), identifier: "invalid", exportPolicy: .allowed)
            XCTFail("Expected identifier rejection")
        } catch let error as SoftwareKeyEnvelopeError {
            XCTAssertEqual(error, .invalidIdentifier)
        }
        do {
            _ = try await store.seal(Data(), identifier: identifier, exportPolicy: .hardwareNonExportable)
            XCTFail("Expected policy rejection")
        } catch let error as SoftwareKeyEnvelopeError {
            XCTAssertEqual(error, .invalidExportPolicy)
        }
        do {
            _ = try await store.unseal(
                SoftwareKeyEnvelope(formatVersion: 99, payload: Data()),
                identifier: identifier,
                exportPolicy: .allowed
            )
            XCTFail("Expected envelope-version rejection")
        } catch let error as SoftwareKeyEnvelopeError {
            XCTAssertEqual(error, .invalidEnvelope)
        }
    }

    func testRoundTripAuthenticationAndDeletion() async throws {
        try requireKeychainTests()
        let plaintext = Data("disposable protected test material".utf8)
        let first = try await store.seal(plaintext, identifier: identifier, exportPolicy: .allowed)
        let second = try await store.seal(plaintext, identifier: identifier, exportPolicy: .allowed)

        XCTAssertNotEqual(first.payload, second.payload)
        XCTAssertNotEqual(first.payload, plaintext)
        let opened = try await store.unseal(first, identifier: identifier, exportPolicy: .allowed)
        XCTAssertEqual(opened, plaintext)

        do {
            _ = try await store.unseal(first, identifier: identifier, exportPolicy: .applicationDisabled)
            XCTFail("Expected export-policy authentication failure")
        } catch let error as SoftwareKeyEnvelopeError {
            XCTAssertEqual(error, .authenticationFailed)
        }

        var tamperedPayload = first.payload
        tamperedPayload[tamperedPayload.count - 1] ^= 1
        let tampered = SoftwareKeyEnvelope(formatVersion: first.formatVersion, payload: tamperedPayload)
        do {
            _ = try await store.unseal(tampered, identifier: identifier, exportPolicy: .allowed)
            XCTFail("Expected ciphertext authentication failure")
        } catch let error as SoftwareKeyEnvelopeError {
            XCTAssertEqual(error, .authenticationFailed)
        }

        let hasKey = try await store.hasWrappingKey(identifier: identifier)
        XCTAssertTrue(hasKey)
        try await store.deleteWrappingKey(identifier: identifier)
        let stillHasKey = try await store.hasWrappingKey(identifier: identifier)
        XCTAssertFalse(stillHasKey)
        do {
            _ = try await store.unseal(first, identifier: identifier, exportPolicy: .allowed)
            XCTFail("Expected missing wrapping key")
        } catch let error as SoftwareKeyEnvelopeError {
            XCTAssertEqual(error, .keyNotFound)
        }
    }

    private func requireKeychainTests() throws {
        guard ProcessInfo.processInfo.environment["ADDRESSEE_KEYCHAIN_TESTS"] == "1" else {
            throw XCTSkip("Keychain integration tests are opt-in")
        }
    }
}
