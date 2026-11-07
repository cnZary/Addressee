import SwiftUI

struct RootTabView: View {
    @State private var selectedTab = AppTab.keys
    @StateObject private var model: OpenPgpApplicationModel
    @StateObject private var cardInteraction: CardInteractionCoordinator

    init(cardInteraction: CardInteractionCoordinator? = nil) {
        let interaction = cardInteraction ?? CardInteractionCoordinator()
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
        .sheet(isPresented: Binding(
            get: { cardInteraction.isPresentationActive },
            set: { isPresented in
                if !isPresented { cardInteraction.cancelActiveInteraction() }
            }
        )) {
            if let request = cardInteraction.pinRequest {
                CardPinEntryView(request: request, coordinator: cardInteraction)
                    .onDisappear {
                        cardInteraction.cancelInteraction(id: request.id)
                    }
            } else if let request = cardInteraction.touchRequest {
                CardTouchProgressView(request: request)
            } else {
                ProgressView("operation.inProgress")
                    .padding()
                    .presentationDetents([.medium])
                    .interactiveDismissDisabled()
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
