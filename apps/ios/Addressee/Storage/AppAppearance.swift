import SwiftUI

enum AppAppearance: String, CaseIterable, Identifiable, Sendable {
    static let storageKey = "application.appearance"

    case system
    case light
    case dark

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .system: "appearance.system"
        case .light: "appearance.light"
        case .dark: "appearance.dark"
        }
    }

    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}

private struct AppAppearanceModifier: ViewModifier {
    @AppStorage(AppAppearance.storageKey) private var appearanceRawValue = AppAppearance.system.rawValue

    func body(content: Content) -> some View {
        let appearance = AppAppearance(rawValue: appearanceRawValue) ?? .system
        return content.preferredColorScheme(appearance.colorScheme)
    }
}

extension View {
    func applicationAppearance() -> some View {
        modifier(AppAppearanceModifier())
    }
}
