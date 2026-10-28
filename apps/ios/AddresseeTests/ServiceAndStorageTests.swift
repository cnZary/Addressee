import SwiftUI
import UIKit
import XCTest
@testable import Addressee

final class ServiceAvailabilityTests: XCTestCase {
    func testDefaultAvailabilityDisablesEveryOperation() {
        let services = ServiceAvailability.unavailable

        XCTAssertTrue(services.isUnavailable)
        for operation in CryptographicOperation.allCases {
            XCTAssertFalse(services.isAvailable(operation))
        }
    }

    func testAvailabilityIsLimitedToExplicitOperations() {
        let services = ServiceAvailability(availableOperations: [.signing])

        XCTAssertFalse(services.isUnavailable)
        XCTAssertTrue(services.isAvailable(.signing))
        XCTAssertFalse(services.isAvailable(.verification))
        XCTAssertFalse(services.isAvailable(.hardwareKeyManagement))
    }
}

final class KeyInventoryTests: XCTestCase {
    func testDefaultInventoryIsReallyEmpty() {
        let inventory = KeyInventory()

        XCTAssertTrue(inventory.isEmpty)
        XCTAssertEqual(inventory.count, 0)
        XCTAssertEqual(inventory, .empty)
    }
}

final class SecuritySettingsTests: XCTestCase {
    func testSoftwareExportIsDeniedByDefault() {
        let settings = SecuritySettings()

        XCTAssertFalse(settings.allowsSoftwareKeyExport)
        XCTAssertFalse(settings.permitsPrivateKeyExport(for: .software))
    }

    func testSoftwareExportCanBeAllowedAtTheAppLevel() {
        let settings = SecuritySettings(allowsSoftwareKeyExport: true)

        XCTAssertTrue(settings.permitsPrivateKeyExport(for: .software))
    }

    func testSecureEnclaveKeysAreNeverExportable() {
        XCTAssertFalse(SecuritySettings().permitsPrivateKeyExport(for: .secureEnclaveP256))
        XCTAssertFalse(
            SecuritySettings(allowsSoftwareKeyExport: true)
                .permitsPrivateKeyExport(for: .secureEnclaveP256)
        )
    }
}

@MainActor
final class AppAppearanceTests: XCTestCase {
    func testAppearanceValuesHaveStablePersistenceIdentifiers() {
        XCTAssertEqual(AppAppearance.storageKey, "application.appearance")
        XCTAssertEqual(AppAppearance.allCases.map(\.rawValue), ["system", "light", "dark"])
        XCTAssertNil(AppAppearance(rawValue: "unknown"))
    }

    func testAppearanceMapsToNativeColorSchemes() {
        XCTAssertNil(AppAppearance.system.colorScheme)
        XCTAssertEqual(AppAppearance.light.colorScheme, .light)
        XCTAssertEqual(AppAppearance.dark.colorScheme, .dark)
    }

    func testAppearanceModifierOverridesSystemAndReactsToChanges() throws {
        let suite = "AppAppearanceTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        defer { defaults.removePersistentDomain(forName: suite) }

        let recorder = ColorSchemeRecorder()
        let controller = UIHostingController(
            rootView: ColorSchemeObservingView(recorder: recorder)
                .applicationAppearance()
                .defaultAppStorage(defaults)
        )
        let windowScene = try XCTUnwrap(
            UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first
        )
        let window = UIWindow(windowScene: windowScene)
        window.frame = CGRect(x: 0, y: 0, width: 320, height: 640)
        window.overrideUserInterfaceStyle = .dark
        window.rootViewController = controller
        controller.loadViewIfNeeded()
        window.makeKeyAndVisible()
        controller.view.layoutIfNeeded()
        window.layoutIfNeeded()
        defer { window.isHidden = true }

        assertColorScheme(2, in: recorder)
        defaults.set(AppAppearance.light.rawValue, forKey: AppAppearance.storageKey)
        assertColorScheme(1, in: recorder)
        defaults.set(AppAppearance.dark.rawValue, forKey: AppAppearance.storageKey)
        assertColorScheme(2, in: recorder)
        defaults.set(AppAppearance.system.rawValue, forKey: AppAppearance.storageKey)
        window.overrideUserInterfaceStyle = .light
        assertColorScheme(1, in: recorder)
    }

    private func assertColorScheme(_ rawValue: Int, in recorder: ColorSchemeRecorder) {
        let expectation = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "rawValue == %d", rawValue),
            object: recorder
        )
        XCTAssertEqual(
            XCTWaiter.wait(for: [expectation], timeout: 5),
            .completed,
            "Expected \(rawValue), actual \(recorder.rawValue)"
        )
    }
}

@MainActor
private final class ColorSchemeRecorder: NSObject {
    @objc dynamic var rawValue = 0
}

@MainActor
private struct ColorSchemeObservingView: View {
    @Environment(\.colorScheme) private var colorScheme
    let recorder: ColorSchemeRecorder

    var body: some View {
        Color.clear
            .onAppear { update(colorScheme) }
            .onChange(of: colorScheme) { update($0) }
    }

    private func update(_ colorScheme: ColorScheme) {
        recorder.rawValue = colorScheme == .light ? 1 : 2
    }
}

final class HardwareConnectionSettingsTests: XCTestCase {
    func testMultipleHardwareKeysDefaultsOffAndPersists() throws {
        let suite = "HardwareConnectionSettingsTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = HardwareConnectionSettings(defaults: defaults)

        XCTAssertFalse(settings.allowsMultipleHardwareKeys)
        settings.allowsMultipleHardwareKeys = true
        XCTAssertTrue(HardwareConnectionSettings(defaults: defaults).allowsMultipleHardwareKeys)
    }

    func testUSBConnectionCompletenessDependsOnTheReaderSelectionMode() {
        let automatic = CardConnectionSelection(method: .usb)
        let explicit = CardConnectionSelection(method: .usb, readerName: "USB Reader")
        let malformed = CardConnectionSelection(method: .usb, readerName: " \n")

        XCTAssertTrue(automatic.isComplete)
        XCTAssertFalse(automatic.isComplete(allowsMultipleHardwareKeys: true))
        XCTAssertTrue(explicit.isComplete(allowsMultipleHardwareKeys: true))
        XCTAssertFalse(malformed.isComplete)
        XCTAssertThrowsError(try malformed.validate())
    }
}
