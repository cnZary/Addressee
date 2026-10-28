import XCTest
@testable import Addressee

final class SignatureModeTests: XCTestCase {
    func testSignatureModesMapToTheirOperations() {
        XCTAssertEqual(SignatureMode.allCases.map(\.rawValue), ["sign", "verify"])
        XCTAssertEqual(SignatureMode.sign.operation, .signing)
        XCTAssertEqual(SignatureMode.verify.operation, .verification)
        XCTAssertEqual(SignatureMode.sign.accessibilityIdentifier, "mode.signature.sign")
        XCTAssertEqual(SignatureMode.verify.accessibilityIdentifier, "mode.signature.verify")
    }
}

final class EncryptionModeTests: XCTestCase {
    func testEncryptionModesMapToTheirOperations() {
        XCTAssertEqual(EncryptionMode.allCases.map(\.rawValue), ["encrypt", "decrypt"])
        XCTAssertEqual(EncryptionMode.encrypt.operation, .encryption)
        XCTAssertEqual(EncryptionMode.decrypt.operation, .decryption)
        XCTAssertEqual(EncryptionMode.encrypt.accessibilityIdentifier, "mode.encryption.encrypt")
        XCTAssertEqual(EncryptionMode.decrypt.accessibilityIdentifier, "mode.encryption.decrypt")
    }
}
