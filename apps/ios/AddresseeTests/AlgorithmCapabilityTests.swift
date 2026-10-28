import XCTest
@testable import Addressee

final class AlgorithmCapabilityTests: XCTestCase {
    func testRustRegistryLoadsWithoutEnablingUnverifiedAlgorithms() async throws {
        let registry = try await AlgorithmCapabilityService.loadRegistry()

        XCTAssertEqual(registry.schemaVersion, 1)
        XCTAssertEqual(registry.entries.count, 86)
        XCTAssertEqual(registry.entries(enabledFor: .generate).count, 17)
        XCTAssertEqual(registry.entries(enabledFor: .sign).count, 10)
        XCTAssertEqual(registry.entries(fullySupporting: .generate).count, 13)
        XCTAssertEqual(registry.entries(fullySupporting: .sign).count, 8)
        XCTAssertEqual(registry.entries(fullySupporting: .verify).count, 7)
        XCTAssertEqual(registry.entries(fullySupporting: .encrypt).count, 7)
        XCTAssertEqual(registry.entries(fullySupporting: .decrypt).count, 8)

        for algorithm in ["rsa-3072", "rsa-4096"] {
            let entry = try XCTUnwrap(registry.entry(
                algorithm: algorithm,
                backend: "software",
                keyVersion: "v4"
            ))
            for operation in [CapabilityOperation.import, .verify, .decrypt] {
                XCTAssertTrue(
                    entry.isFullySupported(operation),
                    "\(algorithm) \(operation.rawValue) lacks bidirectional evidence"
                )
            }
        }

        // v6 Ed25519/X25519 and Curve448 remain without independent evidence
        // because GnuPG rejects their public-key algorithm identifiers on import.
        let unverifiedAlgorithms: Set<String> = ["ed25519", "x25519", "ed448", "x448"]
        for operation in [CapabilityOperation.sign, .verify, .encrypt, .decrypt] {
            XCTAssertTrue(
                registry.entries(fullySupporting: operation).allSatisfy {
                    !unverifiedAlgorithms.contains($0.algorithm)
                }
            )
        }
    }

    func testSecureEnclaveClaimsRemainLimitedToP256() async throws {
        let registry = try await AlgorithmCapabilityService.loadRegistry()
        let enclaveEntries = registry.entries.filter { $0.backend == "secure-enclave" }

        XCTAssertEqual(enclaveEntries.count, 2)
        XCTAssertEqual(
            Set(enclaveEntries.map(\.algorithm)),
            ["nist-p256-ecdsa", "nist-p256-ecdh"]
        )
        XCTAssertTrue(enclaveEntries.allSatisfy(\.isHardwareNonExportable))
        XCTAssertTrue(enclaveEntries.allSatisfy { !$0.canImport && !$0.canExportPrivate })

        let ecdh = try XCTUnwrap(registry.entry(
            algorithm: "nist-p256-ecdh",
            backend: "secure-enclave",
            keyVersion: "v4"
        ))
        for operation in [CapabilityOperation.generate, .decrypt] {
            XCTAssertTrue(
                ecdh.isFullySupported(operation),
                "Secure Enclave P-256 \(operation.rawValue) lacks verified evidence"
            )
        }
    }
}
