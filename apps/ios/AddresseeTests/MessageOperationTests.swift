import XCTest
@testable import Addressee

@MainActor
final class MessageOperationTests: XCTestCase {
    private static var sharedModel: OpenPgpApplicationModel?
    private static var sharedKey: GeneratedKeyFfi?

    private var model: OpenPgpApplicationModel!
    private var generatedKey: GeneratedKeyFfi!

    override func setUp() async throws {
        if Self.sharedModel == nil {
            let model = OpenPgpApplicationModel()
            await model.load()
            let generated = try await model.generate(
                profile: .modernV6,
                userID: "Message Tests <messages@example.invalid>",
                password: Self.password,
                exportPolicy: .disabled
            )
            Self.sharedModel = model
            Self.sharedKey = generated
        }
        model = Self.sharedModel
        generatedKey = Self.sharedKey
    }

    func testSignatureFormatsUnknownSignerAndTampering() async throws {
        let fingerprint = generatedKey.summary.fingerprint
        let at = Self.now
        let payload = Data("binary\0payload\r\nwith text".utf8)
        XCTAssertTrue(model.signingKeys.contains { $0.fingerprint == fingerprint })
        XCTAssertTrue(model.decryptionKeys.contains { $0.fingerprint == fingerprint })
        XCTAssertTrue(model.encryptionRecipientKeys.contains { $0.fingerprint == fingerprint })

        let detached = try await model.signDetached(
            signingKey: fingerprint,
            password: Self.password,
            atUnixSeconds: at,
            data: payload,
            format: .armored
        )
        let detachedResult = try await model.verifyDetached(
            data: payload,
            signature: detached.artifact,
            atUnixSeconds: at
        )
        XCTAssertEqual(detachedResult.status, .valid)
        XCTAssertEqual(detachedResult.signatures.count, 1)
        XCTAssertEqual(detachedResult.signatures[0].trust, .unknown)

        let unknownModel = OpenPgpApplicationModel()
        let unknown = try await unknownModel.verifyDetached(
            data: payload,
            signature: detached.artifact,
            atUnixSeconds: at
        )
        XCTAssertEqual(unknown.status, .unknownSigner)

        let tampered = try await model.verifyDetached(
            data: Data("tampered payload".utf8),
            signature: detached.artifact,
            atUnixSeconds: at
        )
        XCTAssertEqual(tampered.status, .invalid)

        let attached = try await model.signAttached(
            signingKey: fingerprint,
            password: Self.password,
            atUnixSeconds: at,
            data: payload,
            format: .binary
        )
        let attachedResult = try await model.verifyAttached(
            input: attached.artifact,
            atUnixSeconds: at
        )
        XCTAssertEqual(attachedResult.outcome.status, .valid, "at=\(at) outcome=\(attachedResult.outcome)")
        XCTAssertEqual(attachedResult.plaintext, payload)

        let text = "First line\r\nSecond line\r\n"
        let cleartext = try await model.signCleartext(
            signingKey: fingerprint,
            password: Self.password,
            atUnixSeconds: at,
            text: text
        )
        let cleartextResult = try await model.verifyCleartext(
            input: cleartext.artifact,
            atUnixSeconds: at
        )
        XCTAssertEqual(cleartextResult.outcome.status, .valid, "at=\(at) outcome=\(cleartextResult.outcome)")
        XCTAssertEqual(cleartextResult.text, text)
    }

    func testEncryptionOutcomesAndPlaintextCommitRules() async throws {
        let signerFingerprint = generatedKey.summary.fingerprint
        let text = "First line\r\nSecond line\r\n"
        let config = EncryptionConfigFfi.seipdV2(cipher: .aes256, mode: .ocb)

        // Generate every certificate before capturing the evaluation timestamp so
        // validity checks never see keys created after that timestamp.
        let recipientModel = OpenPgpApplicationModel()
        await recipientModel.load()
        let recipient = try await recipientModel.generate(
            profile: .modernV6,
            userID: "Message Recipient <recipient@example.invalid>",
            password: "recipient-test-only",
            exportPolicy: .disabled
        )
        let recipientFingerprint = recipient.summary.fingerprint
        let outsiderModel = OpenPgpApplicationModel()
        await outsiderModel.load()
        let outsider = try await outsiderModel.generate(
            profile: .modernV6,
            userID: "Message Outsider <outsider@example.invalid>",
            password: "outsider-test-only",
            exportPolicy: .disabled
        )
        let at = Self.now

        let encryptedText = try await model.encryptText(
            recipients: [signerFingerprint],
            atUnixSeconds: at,
            config: config,
            text: text,
            format: .armored
        )
        let unsigned = try await model.decryptText(
            decryptionKey: signerFingerprint,
            password: Self.password,
            atUnixSeconds: at,
            input: encryptedText
        )
        XCTAssertEqual(unsigned.report.status, .unsigned)
        XCTAssertEqual(unsigned.text, text)
        XCTAssertTrue(unsigned.report.mayCommitStaging)

        _ = try await model.importPublic(recipient.publicCertificate)

        let signed = try await model.signAndEncryptText(
            request: SignEncryptTextRequestFfi(
                signingKey: signerFingerprint,
                password: Self.password,
                recipients: [signerFingerprint, recipientFingerprint],
                atUnixSeconds: at,
                config: config,
                text: text,
                format: .armored
            )
        )
        let valid = try await model.decryptText(
            decryptionKey: signerFingerprint,
            password: Self.password,
            atUnixSeconds: at,
            input: signed.artifact
        )
        XCTAssertEqual(valid.report.status, .valid)
        XCTAssertEqual(valid.text, text)
        XCTAssertEqual(valid.report.trust, .unknown)

        let unknown = try await recipientModel.decryptText(
            decryptionKey: recipientFingerprint,
            password: "recipient-test-only",
            atUnixSeconds: at,
            input: signed.artifact
        )
        XCTAssertEqual(unknown.report.status, .unknownSigner)
        XCTAssertEqual(unknown.text, text)
        XCTAssertEqual(unknown.report.trust, .unknown)
        XCTAssertTrue(unknown.report.mayCommitStaging)

        let failed = try await outsiderModel.decryptText(
            decryptionKey: outsider.summary.fingerprint,
            password: "outsider-test-only",
            atUnixSeconds: at,
            input: signed.artifact
        )
        XCTAssertEqual(failed.report.status, .decryptionFailed)
        XCTAssertNil(failed.text)
        XCTAssertFalse(failed.report.mayCommitStaging)

        let payload = Data([0, 1, 2, 3, 0, 255, 10, 13])
        let encrypted = try await model.encrypt(
            recipients: [signerFingerprint],
            atUnixSeconds: at,
            config: config,
            data: payload,
            format: .binary
        )
        let decrypted = try await model.decrypt(
            decryptionKey: signerFingerprint,
            password: Self.password,
            atUnixSeconds: at,
            input: encrypted
        )
        XCTAssertEqual(decrypted.report.status, .unsigned)
        XCTAssertEqual(decrypted.plaintext, payload)

        let signedBinary = try await model.signAndEncrypt(
            request: SignEncryptRequestFfi(
                signingKey: signerFingerprint,
                password: Self.password,
                recipients: [signerFingerprint],
                atUnixSeconds: at,
                config: config,
                data: payload,
                format: .binary
            )
        )
        let decryptedBinary = try await model.decrypt(
            decryptionKey: signerFingerprint,
            password: Self.password,
            atUnixSeconds: at,
            input: signedBinary.artifact
        )
        XCTAssertEqual(decryptedBinary.report.status, .valid)
        XCTAssertEqual(decryptedBinary.plaintext, payload)
    }

    func testFileSignatureAndEncryptionRoundtrips() async throws {
        let fingerprint = generatedKey.summary.fingerprint
        let at = Self.now
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("MessageOperationTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let payload = Data((0..<16_384).map { UInt8($0 % 251) })
        let input = directory.appendingPathComponent("payload.bin")
        try payload.write(to: input)

        let detached = directory.appendingPathComponent("payload.bin.asc")
        _ = try await model.signDetachedFile(
            signingKey: fingerprint,
            password: Self.password,
            atUnixSeconds: at,
            inputPath: input.path,
            outputPath: detached.path,
            format: .armored
        )
        let detachedResult = try await model.verifyDetachedFile(
            dataPath: input.path,
            signaturePath: detached.path,
            atUnixSeconds: at
        )
        XCTAssertEqual(detachedResult.status, .valid)

        let attached = directory.appendingPathComponent("payload-attached.pgp")
        _ = try await model.signAttachedFile(
            signingKey: fingerprint,
            password: Self.password,
            atUnixSeconds: at,
            inputPath: input.path,
            outputPath: attached.path,
            format: .binary
        )
        let verifiedOutput = directory.appendingPathComponent("verified.bin")
        let attachedResult = try await model.verifyAttachedFile(
            inputPath: attached.path,
            outputPath: verifiedOutput.path,
            atUnixSeconds: at
        )
        XCTAssertEqual(attachedResult.status, .valid)
        XCTAssertEqual(try Data(contentsOf: verifiedOutput), payload)

        let config = EncryptionConfigFfi.seipdV2(cipher: .aes256, mode: .ocb)
        let encrypted = directory.appendingPathComponent("payload.pgp")
        try await model.encryptFile(
            recipients: [fingerprint],
            atUnixSeconds: at,
            config: config,
            inputPath: input.path,
            outputPath: encrypted.path,
            format: .binary
        )
        let decryptedOutput = directory.appendingPathComponent("decrypted.bin")
        let unsigned = try await model.decryptFile(
            decryptionKey: fingerprint,
            password: Self.password,
            atUnixSeconds: at,
            inputPath: encrypted.path,
            outputPath: decryptedOutput.path
        )
        XCTAssertEqual(unsigned.status, .unsigned)
        XCTAssertTrue(unsigned.mayCommitStaging)
        XCTAssertEqual(try Data(contentsOf: decryptedOutput), payload)

        let signedEncrypted = directory.appendingPathComponent("payload-signed.asc")
        _ = try await model.signAndEncryptFile(
            request: SignEncryptFileRequestFfi(
                signingKey: fingerprint,
                password: Self.password,
                recipients: [fingerprint],
                atUnixSeconds: at,
                config: config,
                inputPath: input.path,
                outputPath: signedEncrypted.path,
                format: .armored
            )
        )
        let signedOutput = directory.appendingPathComponent("signed-decrypted.bin")
        let valid = try await model.decryptFile(
            decryptionKey: fingerprint,
            password: Self.password,
            atUnixSeconds: at,
            inputPath: signedEncrypted.path,
            outputPath: signedOutput.path
        )
        XCTAssertEqual(valid.status, .valid)
        XCTAssertTrue(valid.mayCommitStaging)
        XCTAssertEqual(try Data(contentsOf: signedOutput), payload)
    }

    func testLegacyPolicyPresentationSeparatesWarningsRejectionsAndTrust() {
        let warning = LegacyPolicyDecisionFfi(
            disposition: .allowWithWarning,
            warning: LegacyAlgorithmWarningFfi(kind: .weakSignatureHash, algorithm: "sha1")
        )
        let valid = VerificationOutcomeFfi(status: .valid, signatures: [makeVerification(decision: warning)])
        XCTAssertEqual(
            valid.policyPresentation,
            MessagePolicyPresentation(level: .warning, kind: .weakSignatureHash, algorithm: "SHA-1")
        )
        XCTAssertEqual(valid.signatures[0].trust, .unknown)

        let rejected = LegacyPolicyDecisionFfi(
            disposition: .reject,
            warning: LegacyAlgorithmWarningFfi(kind: .weakSignatureHash, algorithm: "md5")
        )
        let cipherWarning = LegacyPolicyDecisionFfi(
            disposition: .allowWithWarning,
            warning: LegacyAlgorithmWarningFfi(kind: .legacySymmetricCipher, algorithm: "cast5")
        )
        let report = DecryptionReportFfi(
            status: .invalid,
            signatures: [makeVerification(decision: rejected)],
            trust: .unknown,
            symmetricAlgorithm: "cast5",
            legacyDecision: cipherWarning,
            detail: nil,
            mayCommitStaging: false
        )
        XCTAssertEqual(
            report.policyPresentation,
            MessagePolicyPresentation(level: .rejected, kind: .weakSignatureHash, algorithm: "MD5")
        )
        XCTAssertEqual(report.trust, .unknown)
        XCTAssertFalse(report.mayCommitStaging)

        let modern = VerificationOutcomeFfi(
            status: .valid,
            signatures: [makeVerification(decision: LegacyPolicyDecisionFfi(disposition: .allow, warning: nil))]
        )
        XCTAssertNil(modern.policyPresentation)
    }

    func testCapabilityPolicyRejectionIsDistinctFromLegacyWarnings() {
        let outcome = VerificationOutcomeFfi(
            status: .invalid,
            signatures: [
                makeVerification(
                    decision: LegacyPolicyDecisionFfi(disposition: .allow, warning: nil),
                    capabilityRejected: true
                )
            ]
        )
        XCTAssertTrue(outcome.signatures[0].capabilityRejected)
        XCTAssertNil(outcome.signatures[0].cryptographicallyValid)
        XCTAssertNil(outcome.policyPresentation)
    }

    private func makeVerification(
        decision: LegacyPolicyDecisionFfi,
        capabilityRejected: Bool = false
    ) -> SignatureVerificationFfi {
        SignatureVerificationFfi(
            status: decision.disposition == .reject || capabilityRejected ? .invalid : .valid,
            cryptographicallyValid: capabilityRejected ? nil : true,
            capabilityRejected: capabilityRejected,
            certificateFingerprint: nil,
            signerFingerprint: nil,
            signerKeyId: nil,
            algorithm: nil,
            hashAlgorithm: decision.warning?.algorithm,
            legacyDecision: decision,
            createdAt: nil,
            keyValidity: nil,
            trust: .unknown
        )
    }

    private static var password: String { "message-tests-only" }

    // Signing uses the wall clock at operation time while verification evaluates
    // `signature.created() <= at`. A timestamp captured before signing can therefore
    // precede the signature and intermittently mark it invalid, especially on slow
    // or heavily loaded test hosts. Match the Rust tests' evaluation window instead
    // of accepting that race. Expiry behavior is not under test here.
    private static var now: UInt64 { UInt64(Date().timeIntervalSince1970) + 60 }
}
