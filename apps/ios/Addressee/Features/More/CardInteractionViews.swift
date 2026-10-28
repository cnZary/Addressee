import SwiftUI

struct CardConnectionPicker: View {
    @ObservedObject var model: OpenPgpApplicationModel
    @Binding var selection: CardConnectionSelection
    let identifier: String
    @AppStorage(HardwareConnectionSettings.multipleHardwareKeysStorageKey)
    private var allowsMultipleHardwareKeys = false
    @State private var readerNames: [String] = []
    @State private var isLoadingReaders = false

    var body: some View {
        Section("hardware.operationConnection") {
            Picker("hardware.transport", selection: methodBinding) {
                Text("hardware.transport.nfc")
                    .accessibilityIdentifier("field.\(identifier).transport.nfc")
                    .tag(CardConnectionMethod.nfc)
                Text("hardware.transport.usb")
                    .accessibilityIdentifier("field.\(identifier).transport.usb")
                    .tag(CardConnectionMethod.usb)
            }
            .pickerStyle(.segmented)
            .accessibilityIdentifier("field.\(identifier).transport")

            if selection.method == .usb {
                if allowsMultipleHardwareKeys {
                    Picker("hardware.reader", selection: readerBinding) {
                        Text("hardware.reader.select").tag("")
                        ForEach(readerNames, id: \.self) { name in
                            Text(name).tag(name)
                        }
                    }
                    .accessibilityIdentifier("field.\(identifier).reader")
                    Button("hardware.reader.refresh") {
                        Task { await refreshReaders() }
                    }
                    .disabled(isLoadingReaders)
                    .accessibilityIdentifier("action.\(identifier).reader.refresh")
                    if readerNames.isEmpty && !isLoadingReaders {
                        Text("hardware.reader.none")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else if let readerName = selection.readerName,
                              !readerName.isEmpty,
                              !readerNames.contains(readerName) {
                        Text("hardware.reader.savedUnavailable")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("hardware.reader.automatic")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } else if !CardTransportFactory.nfcIsAvailable() {
                Text("hardware.nfc.unavailable")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .task(id: selection.method) {
            await refreshReadersIfNeeded()
        }
        .onChange(of: allowsMultipleHardwareKeys) { _ in
            Task { await refreshReadersIfNeeded() }
        }
    }

    private var methodBinding: Binding<CardConnectionMethod> {
        Binding(
            get: { selection.method },
            set: { selection = CardConnectionSelection(method: $0) }
        )
    }

    private var readerBinding: Binding<String> {
        Binding(
            get: { selection.readerName ?? "" },
            set: {
                selection = CardConnectionSelection(
                    method: .usb,
                    readerName: $0.isEmpty ? nil : $0
                )
            }
        )
    }

    private func refreshReadersIfNeeded() async {
        guard selection.method == .usb, allowsMultipleHardwareKeys else {
            readerNames = []
            return
        }
        await refreshReaders()
    }

    private func refreshReaders() async {
        isLoadingReaders = true
        defer { isLoadingReaders = false }
        let originalReader = selection.readerName
        do {
            let names = try await model.readerNames()
            guard selection.method == .usb, selection.readerName == originalReader,
                  allowsMultipleHardwareKeys else { return }
            readerNames = names
            if let originalReader, !names.contains(originalReader) {
                selection = CardConnectionSelection(method: .usb)
            }
        } catch {}
    }
}

struct CardPinEntryView: View {
    let request: CardPinRequest
    @ObservedObject var coordinator: CardInteractionCoordinator

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label(request.purpose.title, systemImage: "creditcard")
                    LabeledContent("card.identity", value: request.identity.displayIdentifier)
                    Text("card.pin.noStorage")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Section {
                    SecureField("card.pin.field", text: $coordinator.pin)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("card.pin.field")
                } footer: {
                    if let retries = request.remainingRetries {
                        Text("card.pin.remainingRetries \(retries)")
                    }
                    if request.opensNFCSession {
                        Text("card.pin.nfcPreparation")
                    }
                }
                Section {
                    Button("card.pin.submit") {
                        coordinator.submitPin()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        coordinator.pin.utf8.count < request.minimumLength
                            || coordinator.pin.utf8.count > request.maximumLength
                    )
                    .accessibilityIdentifier("card.pin.submit")
                    Button("card.interaction.cancel", role: .cancel) {
                        coordinator.cancelActiveInteraction()
                    }
                    .accessibilityIdentifier("card.pin.cancel")
                }
            }
            .dismissKeyboard()
            .navigationTitle(request.purpose.title)
            .navigationBarTitleDisplayMode(.inline)
        }
        .presentationDetents([.medium])
    }
}

struct CardTouchPromptView: View {
    let request: CardTouchRequest
    @ObservedObject var coordinator: CardInteractionCoordinator

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Image(systemName: "hand.point.up.left.fill")
                    .font(.system(size: 44))
                    .accessibilityHidden(true)
                Text(request.slot.touchMessage)
                    .multilineTextAlignment(.center)
                Text("card.touch.notVerified")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Button("card.touch.continue") {
                    coordinator.confirmTouch()
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("card.touch.continue")
                Button("card.interaction.cancel", role: .cancel) {
                    coordinator.cancelActiveInteraction()
                }
                .accessibilityIdentifier("card.touch.cancel")
            }
            .padding()
            .navigationTitle("card.touch.title")
            .navigationBarTitleDisplayMode(.inline)
        }
        .presentationDetents([.medium])
    }
}

extension CardPinPurpose {
    var title: LocalizedStringKey {
        switch self {
        case .signing: "card.pin.signing"
        case .user: "card.pin.user"
        }
    }
}

extension CardSlot {
    var title: LocalizedStringKey {
        switch self {
        case .signing: "card.slot.signing"
        case .decryption: "card.slot.decryption"
        case .authentication: "card.slot.authentication"
        }
    }

    var touchMessage: LocalizedStringKey {
        switch self {
        case .signing: "card.touch.signing"
        case .decryption: "card.touch.decryption"
        case .authentication: "card.touch.authentication"
        }
    }
}

extension CardIdentityFfi {
    var displayIdentifier: String {
        String(format: "%04X-%08X", manufacturer, serial)
    }
}
