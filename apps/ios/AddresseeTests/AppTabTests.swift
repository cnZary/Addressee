import XCTest
@testable import Addressee

final class AppTabTests: XCTestCase {
    func testTabsHaveRequiredOrderAndAccessibilityIdentifiers() {
        XCTAssertEqual(AppTab.allCases.map(\.rawValue), ["keys", "sign", "encrypt", "more"])
        XCTAssertEqual(
            AppTab.allCases.map(\.accessibilityIdentifier),
            ["tab.keys", "tab.sign", "tab.encrypt", "tab.more"]
        )
    }

    func testTabsHaveRequiredNativeIconsAndUniqueIdentifiers() {
        XCTAssertEqual(AppTab.allCases.map(\.systemImage), ["key", "signature", "lock", "ellipsis.circle"])
        XCTAssertEqual(Set(AppTab.allCases.map(\.id)).count, AppTab.allCases.count)
    }
}
