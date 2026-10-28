import SwiftUI

struct RootTabView: View {
    @State private var selectedTab = AppTab.keys
    @StateObject private var model: OpenPgpApplicationModel
    @StateObject private var cardInteraction: CardInteractionCoordinator

    init() {
        let interaction = CardInteractionCoordinator()
        _cardInteraction = StateObject(wrappedValue: interaction)
        _model = StateObject(wrappedValue: OpenPgpApplicationModel.live(cardInteraction: interaction))
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            KeysView(model: model)
                .tabItem { tabLabel(for: .keys) }
                .tag(AppTab.keys)

            SignaturesView(model: model)
                .tabItem { tabLabel(for: .sign) }
                .tag(AppTab.sign)

            EncryptionView(model: model)
                .tabItem { tabLabel(for: .encrypt) }
                .tag(AppTab.encrypt)

            MoreView(model: model)
                .tabItem { tabLabel(for: .more) }
                .tag(AppTab.more)
        }
        .accessibilityIdentifier("navigation.rootTabs")
        .task { await model.load() }
        .sheet(item: Binding(
            get: { cardInteraction.pinRequest },
            set: { _ in }
        )) { request in
            CardPinEntryView(request: request, coordinator: cardInteraction)
                .onDisappear {
                    cardInteraction.cancelInteraction(id: request.id)
                }
        }
        .sheet(item: Binding(
            get: { cardInteraction.touchRequest },
            set: { _ in }
        )) { request in
            CardTouchPromptView(request: request, coordinator: cardInteraction)
                .onDisappear {
                    cardInteraction.cancelInteraction(id: request.id)
                }
        }
    }

    private func tabLabel(for tab: AppTab) -> some View {
        Label {
            Text(tab.title)
        } icon: {
            Image(systemName: tab.systemImage)
                .accessibilityIdentifier(tab.accessibilityIdentifier)
        }
    }
}
