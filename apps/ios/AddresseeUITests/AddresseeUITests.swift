import UIKit
import UIKit
import XCTest

@MainActor
final class AddresseeUITests: XCTestCase {
    private lazy var app: XCUIApplication = {
        let app = XCUIApplication()
        app.launchArguments = [
            "-AppleLanguages", "(en)", "-AppleLocale", "en_US",
            "-DisableKeyPersistence", "-DisablePasswordAutofill",
        ]
        app.launch()
        XCTAssertTrue(app.tabBars.firstMatch.waitForExistence(timeout: 15))
        return app
    }()

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testAllFourTabsAndNestedModes() {
        assertTabOrder()

        let keysTab = tabButton("tab.keys")
        keysTab.tap()
        XCTAssertTrue(element("screen.keys").waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["action.keys.import"].isEnabled)

        tabButton("tab.sign").tap()
        let signaturePicker = app.segmentedControls["mode.signature.picker"]
        XCTAssertTrue(signaturePicker.waitForExistence(timeout: 5))
        XCTAssertTrue(element("panel.signature.sign").exists)
        assertActionDisabled("action.signature.sign")
        XCTAssertTrue(signaturePicker.buttons["mode.signature.sign"].exists)
        signaturePicker.buttons["mode.signature.verify"].tap()
        XCTAssertTrue(element("panel.signature.verify").waitForExistence(timeout: 5))
        assertActionDisabled("action.signature.verify")

        tabButton("tab.encrypt").tap()
        let encryptionPicker = app.segmentedControls["mode.encryption.picker"]
        XCTAssertTrue(encryptionPicker.waitForExistence(timeout: 5))
        XCTAssertTrue(element("panel.encryption.encrypt").exists)
        assertActionDisabled("action.encryption.encrypt")
        XCTAssertTrue(encryptionPicker.buttons["mode.encryption.encrypt"].exists)
        encryptionPicker.buttons["mode.encryption.decrypt"].tap()
        XCTAssertTrue(element("panel.encryption.decrypt").waitForExistence(timeout: 5))
        assertActionDisabled("action.encryption.decrypt")

        tabButton("tab.more").tap()
        XCTAssertTrue(element("screen.more").waitForExistence(timeout: 5))
        XCTAssertTrue(app.tabBars.firstMatch.exists)
    }

    func testMultilineKeyboardDismissalPreservesTextWithoutSubmitting() {
        tabButton("tab.sign").tap()
        let editor = app.textViews["field.signature.signText"]
        XCTAssertTrue(editor.waitForExistence(timeout: 5))
        editor.tap()
        editor.typeText("First line\nSecond line")
        let dismissKeyboard = app.buttons["action.keyboard.dismiss"]
        XCTAssertTrue(dismissKeyboard.waitForExistence(timeout: 5))
        dismissKeyboard.tap()
        XCTAssertTrue(app.keyboards.firstMatch.waitForNonExistence(timeout: 5))
        XCTAssertEqual(editor.value as? String, "First line\nSecond line")
        assertActionDisabled("action.signature.sign")
    }

    func testLongTextInputsClearAndPaste() {
        UIPasteboard.general.string = "Pasted first line\nPasted second line"
        tabButton("tab.sign").tap()
        assertClearAndPaste("field.signature.signText")

        app.segmentedControls["mode.signature.picker"].buttons["mode.signature.verify"].tap()
        assertClearAndPaste("field.signature.verifyDataText")
        assertClearAndPaste("field.signature.signatureText")
        let verifyFormat = reveal("field.signature.verifyFormat", towardBottom: false)
        verifyFormat.tap()
        app.buttons["Attached"].tap()
        assertClearAndPaste("field.signature.verifyMessageText")

        tabButton("tab.keys").tap()
        reveal("action.keys.import").tap()
        assertClearAndPaste("field.keys.importArmored")

        tabButton("tab.encrypt").tap()
        assertClearAndPaste("field.encryption.encryptText")
        app.segmentedControls["mode.encryption.picker"].buttons["mode.encryption.decrypt"].tap()
        assertClearAndPaste("field.encryption.decryptText")
    }

    func testPublicCertificateOffersCardAssociationFromKeyDetails() {
        let publicCertificate = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----

        xlIEat6vthMIKoZIzj0DAQcCAwSJvW2AqSO64cHY05TPd3RxfRrrj8R86Rv1CJW1
        H5MK1F5C1W/g3aT3U4LEsiGbgN7LvxtCRkhAo58a5nqNoTBVzTlBZGRyZXNzZWUg
        ZGlzcG9zYWJsZSBjYXJkIHRlc3Q7IG5vdCBhIHByb2R1Y3Rpb24gaWRlbnRpdHnC
        hgQTEwgALgUCat6vuBYhBJapMa5EQw8kD5sQBpMeWTpJSAssAhsBAh4BAQsBFQEW
        AScCGQEACgkQkx5ZOklICyxlfQEA1HRa448T/TXBcQl8UEBQyG02nTa6FxsN9a4O
        SdNyBTEA/2O5qG+BRmEFieMsZ4J2hkt3cvD1zwLtEBhxmIiB46byzlIEat6vthMI
        KoZIzj0DAQcCAwQxesbTkO1owQdnaqsxmQ3XGb0T7DpDeByccnPXaeNeKZ4L7MVg
        ZvKl/jzhRHhsrD1wHjEGMFuBLeTWp8BbZm4AwsAvBBgTCACXBQJq3q+5AhsCFiEE
        lqkxrkRDDyQPmxAGkx5ZOklICyx2IAQZEwgAHQUCat6vtxYhBLyRr+fApEyckH/w
        MaNvv5OgiPmzAAoJEKNvv5OgiPmzYSMBAOndbkdakucQiSLdF/YJ2dahrRoVx3p0
        Lcn8Kuo6Em+nAP9R/alTj9loFp1comvqxg7VkK8zUYTa0TrZPXaN+C0JjgAKCRCT
        Hlk6SUgLLBz+AQCdgRLOW6Lk1tJhOM6BtYBbxhcX43EfiLkBOdIAxul1hwD+MGmX
        CFhhNaNex+CrRxDdD5tI3hmh8e9wumYLkz7cxr/OVgRq3q+2EggqhkjOPQMBBwID
        BKLCEoFXBJvbueAUjkiAFTPBprurw4F8Klb4MJLt73CaeUj2nBftBh+MsXxcsbJ3
        Ik119HpaHm+/QI48y4YzdbQDAQgHwngEGBMIACAFAmrer7oCGwwWIQSWqTGuREMP
        JA+bEAaTHlk6SUgLLAAKCRCTHlk6SUgLLOVGAQCvnyb+iREXrl23UuQypwiE72Ar
        nu5AvgCYDJeMKpeZuQEAj9cGzcQKPFpqx7kEfNq40/ti+3X9ISh5cNxlLsWdG84=
        =TSQg
        -----END PGP PUBLIC KEY BLOCK-----
        """
        tabButton("tab.keys").tap()
        element("action.keys.import").tap()
        let editor = app.textViews["field.keys.importArmored"]
        XCTAssertTrue(editor.waitForExistence(timeout: 5))
        editor.tap()
        editor.typeText(publicCertificate)
        let dismissKeyboard = app.buttons["action.keyboard.dismiss"]
        XCTAssertTrue(dismissKeyboard.waitForExistence(timeout: 5))
        dismissKeyboard.tap()
        let importButton = app.buttons["action.keys.import.confirm"]
        for _ in 0..<4 where !importButton.isHittable {
            app.swipeUp()
        }
        XCTAssertTrue(importButton.isEnabled)
        importButton.tap()

        let certificate = element("key.cell.96A931AE44430F240F9B1006931E593A49480B2C")
        XCTAssertTrue(certificate.waitForExistence(timeout: 10))
        certificate.tap()
        let link = element("navigation.keys.hardware.link")
        for _ in 0..<5 where !link.exists {
            app.swipeUp()
        }
        XCTAssertTrue(link.waitForExistence(timeout: 5))
        link.tap()
        XCTAssertTrue(element("screen.keys.hardware.associate").waitForExistence(timeout: 5))
        XCTAssertTrue(element("action.keys.hardware.connect").waitForExistence(timeout: 5))
        XCTAssertFalse(element("action.keys.hardware.connect").isEnabled)

        tabButton("tab.more").tap()
        XCTAssertTrue(element("navigation.more.application").waitForExistence(timeout: 5))
        element("navigation.more.application").tap()
        let modeToggle = app.switches["settings.application.multipleHardwareKeys"]
        XCTAssertTrue(modeToggle.waitForExistence(timeout: 5))
        if modeToggle.value as? String == "1" {
            modeToggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
        }
        let singleHardwareMode = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "value == %@", "0"),
            object: modeToggle
        )
        XCTAssertEqual(XCTWaiter.wait(for: [singleHardwareMode], timeout: 5), .completed)
        tabButton("tab.keys").tap()
        let transport = app.segmentedControls["field.keys.hardware.associate.transport"]
        XCTAssertTrue(transport.waitForExistence(timeout: 5))
        let usbTransport = transport.buttons["field.keys.hardware.associate.transport.usb"]
        XCTAssertTrue(usbTransport.waitForExistence(timeout: 5))
        usbTransport.tap()
        let usbSelected = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "selected == true"),
            object: usbTransport
        )
        XCTAssertEqual(XCTWaiter.wait(for: [usbSelected], timeout: 5), .completed)
        XCTAssertFalse(element("field.keys.hardware.associate.reader").exists)
        XCTAssertFalse(element("action.keys.hardware.associate.reader.refresh").exists)

        tabButton("tab.more").tap()
        XCTAssertTrue(modeToggle.waitForExistence(timeout: 5))
        modeToggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
        let multipleHardwareMode = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "value == %@", "1"),
            object: modeToggle
        )
        XCTAssertEqual(XCTWaiter.wait(for: [multipleHardwareMode], timeout: 5), .completed)
        tabButton("tab.keys").tap()
        XCTAssertTrue(element("field.keys.hardware.associate.reader").waitForExistence(timeout: 5))
        XCTAssertTrue(element("action.keys.hardware.associate.reader.refresh").exists)
    }

    func testModernKeyGenerationAppearsInKeyList() {
        tabButton("tab.keys").tap()
        let generateLink = element("action.keys.generate")
        XCTAssertTrue(generateLink.waitForExistence(timeout: 5))
        generateLink.tap()

        let userIDField = app.textFields["field.generation.userId"]
        XCTAssertTrue(userIDField.waitForExistence(timeout: 5))
        userIDField.tap()
        userIDField.typeText("UI Test <ui@example.invalid>")
        let dismissKeyboard = app.buttons["action.keyboard.dismiss"]
        XCTAssertTrue(dismissKeyboard.waitForExistence(timeout: 5))
        dismissKeyboard.tap()
        XCTAssertTrue(app.keyboards.firstMatch.waitForNonExistence(timeout: 5))
        XCTAssertEqual(userIDField.value as? String, "UI Test <ui@example.invalid>")

        let passwordField = app.secureTextFields["field.generation.password"]
        passwordField.tap()
        passwordField.typeText("ui-test-only")
        let confirmationField = app.secureTextFields["field.generation.confirmPassword"]
        confirmationField.tap()
        confirmationField.typeText("ui-test-only")

        XCTAssertEqual(userIDField.value as? String, "UI Test <ui@example.invalid>")
        XCTAssertEqual((passwordField.value as? String)?.count, "ui-test-only".count)
        XCTAssertEqual((confirmationField.value as? String)?.count, "ui-test-only".count)

        let generateButton = app.buttons["action.keys.generate.confirm"]
        for _ in 0..<4 where !generateButton.exists {
            app.swipeUp()
        }
        XCTAssertTrue(generateButton.waitForExistence(timeout: 5))
        XCTAssertTrue(generateButton.isEnabled)
        if !generateButton.isHittable {
            app.swipeUp()
        }
        generateButton.tap()

        let generatedIdentity = app.staticTexts["UI Test <ui@example.invalid>"]
        XCTAssertTrue(generatedIdentity.waitForExistence(timeout: 60))
        generatedIdentity.tap()
        XCTAssertTrue(element("screen.keys.details").waitForExistence(timeout: 5))
        app.swipeUp()
        XCTAssertTrue(app.buttons["action.keys.export.public"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["action.keys.export.public"].isEnabled)
        XCTAssertFalse(app.buttons["action.keys.export.private"].exists)
        XCTAssertTrue(app.tabBars.firstMatch.exists)
    }

    func testArmoredTextSignatureCopiesBeforeSharingAndBinaryOutputDoesNotCopy() throws {
        generateKeyForMessageOperations()

        tabButton("tab.sign").tap()
        fillText("field.signature.signText", text: "First line\nSecond line")
        fillSecureField("field.signature.signPassword", text: "ui-test-only")
        reveal("action.signature.sign").tap()
        try assertCopyResult(armorHeader: "-----BEGIN PGP SIGNATURE-----")

        let armorToggle = app.switches["field.signature.signArmor"]
        _ = reveal(armorToggle, towardBottom: false)
        XCTAssertEqual(armorToggle.value as? String, "1")
        armorToggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
        let armorDisabled = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "value == %@", "0"),
            object: armorToggle
        )
        XCTAssertEqual(XCTWaiter.wait(for: [armorDisabled], timeout: 5), .completed)
        fillSecureField("field.signature.signPassword", text: "ui-test-only")
        let binarySignButton = reveal("action.signature.sign")
        XCTAssertTrue(binarySignButton.isEnabled)
        binarySignButton.tap()
        XCTAssertTrue(reveal("action.message.share").waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["File, message.txt.sig"].exists)
        XCTAssertTrue(element("message.output.preview").waitForNonExistence(timeout: 10))
        XCTAssertTrue(element("action.message.copy").waitForNonExistence(timeout: 10))
    }

    func testArmoredTextEncryptionCopiesBeforeSharing() throws {
        generateKeyForMessageOperations()

        tabButton("tab.encrypt").tap()
        fillText("field.encryption.encryptText", text: "Encrypted text\nwith a second line")
        let recipient = app.buttons.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "field.encryption.recipient.")
        ).firstMatch
        _ = reveal(recipient)
        recipient.tap()
        reveal("action.encryption.encrypt").tap()
        try assertCopyResult(armorHeader: "-----BEGIN PGP MESSAGE-----")
    }

    func testEveryMoreDestinationKeepsTheBottomTabBar() {
        tabButton("tab.more").tap()
        XCTAssertTrue(element("screen.more").waitForExistence(timeout: 5))

        let destinations = [
            ("navigation.more.hardware", "screen.more.hardware"),
            ("navigation.more.security", "screen.more.security"),
            ("navigation.more.application", "screen.more.application"),
            ("navigation.more.about", "screen.more.about")
        ]

        for (linkIdentifier, screenIdentifier) in destinations {
            let link = element(linkIdentifier)
            XCTAssertTrue(link.waitForExistence(timeout: 5), "Missing link \(linkIdentifier)")
            link.tap()
            XCTAssertTrue(element(screenIdentifier).waitForExistence(timeout: 5))
            XCTAssertTrue(app.tabBars.firstMatch.exists)

            if linkIdentifier == "navigation.more.hardware" {
                XCTAssertTrue(element("hardware.standaloneManagement").waitForExistence(timeout: 5))
                XCTAssertTrue(element("action.hardware.connect").exists)
                XCTAssertFalse(element("hardware.linkFromKeys").exists)
            }

            app.navigationBars.buttons.element(boundBy: 0).tap()
            XCTAssertTrue(element("screen.more").waitForExistence(timeout: 5))
        }
    }

    private func generateKeyForMessageOperations() {
        tabButton("tab.keys").tap()
        reveal("action.keys.generate").tap()
        fillText("field.generation.userId", text: "Output UI Test <output@example.invalid>")
        fillSecureField("field.generation.password", text: "ui-test-only")
        fillSecureField("field.generation.confirmPassword", text: "ui-test-only")
        reveal("action.keys.generate.confirm").tap()
        XCTAssertTrue(
            app.staticTexts["Output UI Test <output@example.invalid>"].waitForExistence(timeout: 60)
        )
    }

    private func fillText(_ identifier: String, text: String) {
        let field = app.textViews[identifier].exists
            ? app.textViews[identifier]
            : app.textFields[identifier]
        _ = reveal(field)
        field.tap()
        field.typeText(text)
        dismissKeyboard()
    }

    private func fillSecureField(_ identifier: String, text: String) {
        let field = app.secureTextFields[identifier]
        _ = reveal(field)
        field.tap()
        field.typeText(text)
        XCTAssertEqual((field.value as? String)?.count, text.count)
        dismissKeyboard()
    }

    private func dismissKeyboard() {
        let button = app.buttons["action.keyboard.dismiss"]
        XCTAssertTrue(button.waitForExistence(timeout: 5))
        button.tap()
        XCTAssertTrue(app.keyboards.firstMatch.waitForNonExistence(timeout: 5))
    }

    private func assertClearAndPaste(_ identifier: String) {
        let editor = app.textViews[identifier]
        _ = reveal(editor)
        editor.tap()
        editor.typeText("Temporary input")
        dismissKeyboard()

        let clear = app.buttons["\(identifier).clear"]
        _ = reveal(clear)
        XCTAssertTrue(clear.isEnabled)
        clear.tap()
        assertEditorValue("", editor: editor)

        let paste = app.buttons["\(identifier).paste"]
        _ = reveal(paste)
        XCTAssertTrue(paste.isEnabled)
        paste.tap()
        assertEditorValue("Pasted first line\nPasted second line", editor: editor)
        XCTAssertTrue(clear.isEnabled)
    }

    private func assertEditorValue(_ expected: String, editor: XCUIElement) {
        let expectation = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "value == %@", expected),
            object: editor
        )
        XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: 5), .completed)
    }

    private func assertCopyResult(armorHeader: String) throws {
        let preview = app.staticTexts["message.output.preview"]
        _ = reveal(preview, mustBeHittable: false)
        let expected = preview.label
        XCTAssertTrue(expected.hasPrefix(armorHeader), "Unexpected output: \(expected)")
        let copy = reveal("action.message.copy")
        let share = reveal("action.message.share")
        XCTAssertTrue(copy.isEnabled)
        XCTAssertTrue(share.isEnabled)
        XCTAssertLessThan(copy.frame.midX, share.frame.midX)
        copy.tap()
        let expectation = FileManager.default.temporaryDirectory
            .appendingPathComponent("addressee-copy-expectation")
        try Data(expected.utf8).write(to: expectation, options: .atomic)
    }

    private func reveal(
        _ identifier: String,
        towardBottom: Bool = true,
        mustBeHittable: Bool = true
    ) -> XCUIElement {
        reveal(element(identifier), towardBottom: towardBottom, mustBeHittable: mustBeHittable)
    }

    @discardableResult
    private func reveal(
        _ target: XCUIElement,
        towardBottom: Bool = true,
        mustBeHittable: Bool = true
    ) -> XCUIElement {
        for _ in 0..<10 where !target.exists || (mustBeHittable && !target.isHittable) {
            if towardBottom {
                app.swipeUp()
            } else {
                app.swipeDown()
            }
        }
        XCTAssertTrue(target.waitForExistence(timeout: 10), "Missing element \(target.identifier)")
        if mustBeHittable {
            let hittable = XCTNSPredicateExpectation(
                predicate: NSPredicate(format: "hittable == true"),
                object: target
            )
            XCTAssertEqual(
                XCTWaiter.wait(for: [hittable], timeout: 5),
                .completed,
                "Element is not hittable: \(target.identifier)"
            )
        }
        return target
    }

    private let tabTitles = [
        "tab.keys": "Keys",
        "tab.sign": "Sign",
        "tab.encrypt": "Encrypt",
        "tab.more": "More"
    ]

    private func assertTabOrder() {
        let tabBar = app.tabBars.firstMatch
        let identifiers = ["tab.keys", "tab.sign", "tab.encrypt", "tab.more"]
        let titles = identifiers.map { tabTitles[$0]! }

        XCTAssertEqual(tabBar.buttons.count, identifiers.count)
        for title in titles {
            XCTAssertTrue(tabBar.buttons[title].waitForExistence(timeout: 5), "Missing tab \(title)")
        }

        let tabFrames = titles.map { tabBar.buttons[$0].frame }
        for (left, right) in zip(tabFrames, tabFrames.dropFirst()) {
            XCTAssertLessThan(left.maxX, right.maxX)
        }
    }

    private func assertActionDisabled(_ identifier: String) {
        // Form cells below the fold are rendered lazily; scroll a bounded number
        // of times before asserting the action exists and stays disabled.
        let button = app.buttons[identifier]
        for _ in 0..<4 where !button.exists {
            app.swipeUp()
        }
        XCTAssertTrue(button.waitForExistence(timeout: 5), "Missing action \(identifier)")
        XCTAssertFalse(button.isEnabled)
    }

    private func tabButton(_ identifier: String) -> XCUIElement {
        let title = tabTitles[identifier]!
        let button = app.tabBars.buttons[title]
        XCTAssertTrue(button.waitForExistence(timeout: 5), "Missing tab \(title)")
        return button
    }

    private func element(_ identifier: String) -> XCUIElement {
        app.descendants(matching: .any)[identifier].firstMatch
    }
}
