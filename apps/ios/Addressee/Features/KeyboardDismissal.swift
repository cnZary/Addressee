import SwiftUI
import UIKit

private struct KeyboardDismissal: ViewModifier {
    func body(content: Content) -> some View {
        content
            .scrollDismissesKeyboard(.interactively)
            .toolbar {
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("keyboard.done") {
                        UIApplication.shared.sendAction(
                            #selector(UIResponder.resignFirstResponder),
                            to: nil,
                            from: nil,
                            for: nil
                        )
                    }
                    .accessibilityIdentifier("action.keyboard.dismiss")
                }
            }
    }
}

extension View {
    func dismissKeyboard() -> some View {
        modifier(KeyboardDismissal())
    }
}
