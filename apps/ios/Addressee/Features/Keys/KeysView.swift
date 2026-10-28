import SwiftUI

struct KeysView: View {
    enum KeyFilter: String, CaseIterable, Identifiable {
        case all
        case secrets
        case publicOnly

        var id: String { rawValue }
        var title: LocalizedStringKey {
            switch self {
            case .all: "keys.filter.all"
            case .secrets: "keys.filter.secrets"
            case .publicOnly: "keys.filter.publicOnly"
            }
        }
    }

    @ObservedObject var model: OpenPgpApplicationModel
    @State private var searchText = ""
    @State private var filter: KeyFilter = .all

    var body: some View {
        NavigationStack {
            Group {
                if filteredKeys.isEmpty {
                    VStack {
                        Spacer()
                        EmptyStateView(
                            systemImage: "key",
                            title: "keys.empty.title",
                            message: "keys.empty.message"
                        )
                        Spacer()
                    }
                } else {
                    List(filteredKeys, id: \.fingerprint) { key in
                        NavigationLink(destination: KeyDetailsView(summary: key, model: model)) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(key.displayName)
                                Text(key.primary.algorithm.name)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text(model.protectionTitle(for: key))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .accessibilityElement(children: .combine)
                        }
                        .accessibilityIdentifier("key.cell.\(key.fingerprint)")
                    }
                }
            }
            .navigationTitle("keys.title")
            .searchable(text: $searchText, prompt: "keys.search")
            .dismissKeyboard()
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    NavigationLink(destination: GenerateKeyView(model: model)) {
                        Label("keys.generate", systemImage: "plus")
                            .labelStyle(.iconOnly)
                    }
                    .accessibilityLabel("keys.generate")
                    .accessibilityIdentifier("action.keys.generate")
                    .help("keys.generate")
                    NavigationLink(destination: ImportKeyView(model: model)) {
                        Label("keys.import", systemImage: "square.and.arrow.down")
                            .labelStyle(.iconOnly)
                    }
                    .accessibilityLabel("keys.import")
                    .accessibilityIdentifier("action.keys.import")
                    .help("keys.import")
                }
                ToolbarItem(placement: .secondaryAction) {
                    Menu("keys.filter") {
                        Picker("keys.filter", selection: $filter) {
                            ForEach(KeyFilter.allCases) { filter in
                                Text(filter.title).tag(filter)
                            }
                        }
                    }
                    .accessibilityIdentifier("action.keys.filter")
                }
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("screen.keys")
            if model.isBusy {
                ProgressView("operation.inProgress")
            }
            if let errorMessage = model.errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
            }
        }
    }

    private var filteredKeys: [CertificateSummary] {
        model.keys.filter { key in
            let matchesFilter = switch filter {
            case .all: true
            case .secrets: key.isSecret
            case .publicOnly: !key.isSecret
            }
            guard matchesFilter else { return false }
            guard !searchText.isEmpty else { return true }
            return key.displayName.localizedCaseInsensitiveContains(searchText)
                || key.fingerprint.uppercased().contains(searchText.uppercased())
        }
    }
}
