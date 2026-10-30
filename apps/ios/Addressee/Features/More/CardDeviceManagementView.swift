import SwiftUI

struct CardDeviceManagementView: View {
    @ObservedObject var model: OpenPgpApplicationModel
    let identity: CardIdentityFfi
    @State private var information: CardInformationFfi?
    @State private var connection: CardConnectionSelection
    @State private var pinKind = CardPinKind.user
    @State private var showPinChange = false
    @State private var touchSlot = CardSlot.signing
    @State private var showTouchChange = false

    init(
        model: OpenPgpApplicationModel,
        identity: CardIdentityFfi,
        information: CardInformationFfi?,
        connection: CardConnectionSelection
    ) {
        self.model = model
        self.identity = identity
        _information = State(initialValue: information)
        _connection = State(initialValue: connection)
    }

    var body: some View {
        Form {
            Section("hardware.device.identity") {
                LabeledContent("card.identity", value: identity.displayIdentifier)
                LabeledContent("hardware.openpgpVersion", value: version)
            }

            CardConnectionPicker(
                model: model,
                selection: $connection,
                identifier: "hardware.management"
            )

            Section {
                if let information {
                    LabeledContent("hardware.pin.userRetries", value: String(information.userPinRetries))
                    LabeledContent("hardware.pin.adminRetries", value: String(information.adminPinRetries))
                    LabeledContent("hardware.pin.resetRetries", value: String(information.resetCodeRetries))
                    LabeledContent(
                        "hardware.pin.signatureOnce",
                        value: information.signaturePinValidOnce
                            ? String(localized: "common.enabled")
                            : String(localized: "common.disabled")
                    )
                } else {
                    Text("hardware.inspectRequired")
                        .foregroundStyle(.secondary)
                }
                Button("hardware.inspect") {
                    Task { await inspect() }
                }
                .accessibilityIdentifier("action.hardware.inspect")
                if model.isBusy {
                    ProgressView("operation.inProgress")
                }
            } footer: {
                Text("hardware.inspectNote")
            }

            if let information {
                Section("hardware.slots") {
                    ForEach(information.slots, id: \.slot) { slot in
                        VStack(alignment: .leading, spacing: 7) {
                            Text(slot.slot.title)
                                .font(.headline)
                            LabeledContent("hardware.keyPresence", value: keyPresence(slot.keyPresent))
                            if let reference = slot.keyReference {
                                LabeledContent("hardware.keyReference", value: String(reference))
                            }
                            LabeledContent("hardware.currentAlgorithm", value: slot.algorithmAttributes)
                                .font(.caption)
                            if let fingerprint = slot.fingerprint {
                                Text(fingerprint)
                                    .font(.caption2)
                                    .textSelection(.enabled)
                                ForEach(matchingCertificates(for: fingerprint), id: \.fingerprint) { certificate in
                                    LabeledContent("hardware.certificateMatch") {
                                        Text(certificate.displayName)
                                    }
                                }
                            }
                            if let createdAt = slot.createdAt {
                                LabeledContent(
                                    "hardware.keyCreated",
                                    value: Date(
                                        timeIntervalSince1970: TimeInterval(createdAt)
                                    ).formatted(date: .abbreviated, time: .shortened)
                                )
                            }
                            LabeledContent("hardware.touch.current", value: touchTitle(slot.touchPolicy))
                            if !slot.advertisedAlgorithms.isEmpty {
                                Text("hardware.advertisedAlgorithms")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                ForEach(Array(slot.advertisedAlgorithms.enumerated()), id: \.offset) { _, algorithm in
                                    Text(algorithm)
                                        .font(.caption2)
                                        .textSelection(.enabled)
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }

                Section("hardware.pinManagement") {
                    Button("hardware.pin.user.change") {
                        pinKind = .user
                        showPinChange = true
                    }
                    .accessibilityIdentifier("action.hardware.pin.user")
                    Button("hardware.pin.admin.change") {
                        pinKind = .admin
                        showPinChange = true
                    }
                    .accessibilityIdentifier("action.hardware.pin.admin")
                    if information.userPinRetries < 2 || information.adminPinRetries < 2 {
                        Label("hardware.pin.lowRetries", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }

                Section {
                    ForEach(information.slots, id: \.slot) { slot in
                        LabeledContent(slot.slot.title) {
                            Button("hardware.touch.change") {
                                touchSlot = slot.slot
                                showTouchChange = true
                            }
                            .disabled(!canEditTouch(slot))
                        }
                    }
                } header: {
                    Text("hardware.touchManagement")
                } footer: {
                    Text("hardware.touch.fixedUnsupported")
                }

                Section("hardware.currentLimitations") {
                    Text("hardware.managementPending")
                    Text("hardware.advertisedNotVerified")
                }
            }

            if let errorMessage = model.errorMessage {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
        .disabled(model.isBusy)
        .navigationTitle("hardware.device.title")
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("screen.more.hardware.device")
        .sheet(isPresented: $showPinChange) {
            CardPinChangeView(
                model: model,
                identity: identity,
                kind: pinKind,
                connection: connection
            ) { information = $0 }
        }
        .sheet(isPresented: $showTouchChange) {
            if let information {
                CardTouchPolicyView(
                    model: model,
                    identity: identity,
                    slot: touchSlot,
                    information: information,
                    connection: connection
                ) { self.information = $0 }
            }
        }
    }

    private var version: String {
        "\(identity.version >> 8).\(identity.version & 0xFF)"
    }

    private func matchingCertificates(for fingerprint: String) -> [CertificateSummary] {
        model.keys.filter { certificate in
            certificate.fingerprint == fingerprint
                || certificate.subkeys.contains { $0.fingerprint == fingerprint }
        }
    }

    private func keyPresence(_ present: Bool?) -> String {
        switch present {
        case .some(true): String(localized: "hardware.keyPresent")
        case .some(false): String(localized: "hardware.keyAbsent")
        case nil: String(localized: "hardware.unknown")
        }
    }

    private func touchTitle(_ policy: String?) -> String {
        switch policy {
        case "Off": String(localized: "hardware.touch.off")
        case "On": String(localized: "hardware.touch.on")
        case "Cached": String(localized: "hardware.touch.cached")
        case "Fixed", "CachedFixed": String(localized: "hardware.touch.fixed")
        case .some(let value): value
        case nil: String(localized: "hardware.unknown")
        }
    }

    private func canEditTouch(_ slot: CardSlotInformationFfi) -> Bool {
        slot.touchPolicy.map { ["Off", "On", "Cached"].contains($0) } ?? false
    }

    private func inspect() async {
        do {
            information = try await model.inspectHardware(
                identity: identity,
                connection: connection
            )
        } catch {}
    }
}

private struct CardPinChangeView: View {
    @ObservedObject var model: OpenPgpApplicationModel
    let identity: CardIdentityFfi
    let kind: CardPinKind
    let connection: CardConnectionSelection
    let onUpdate: (CardInformationFfi) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var current = ""
    @State private var new = ""
    @State private var confirmation = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("hardware.pin.current", text: $current)
                        .textContentType(.password)
                        .accessibilityIdentifier("field.hardware.pin.current")
                    SecureField("hardware.pin.new", text: $new)
                        .textContentType(.newPassword)
                        .accessibilityIdentifier("field.hardware.pin.new")
                    SecureField("hardware.pin.confirm", text: $confirmation)
                        .textContentType(.newPassword)
                        .accessibilityIdentifier("field.hardware.pin.confirm")
                } footer: {
                    Text(kind == .user
                        ? "hardware.pin.userRequirements"
                        : "hardware.pin.adminRequirements")
                }

                Section {
                    Button("hardware.pin.apply") {
                        Task { await apply() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmit)
                    .accessibilityIdentifier("action.hardware.pin.submit")
                } footer: {
                    Text("card.pin.noStorage")
                }

                if model.isBusy {
                    ProgressView("operation.inProgress")
                }
                if let errorMessage = model.errorMessage {
                    Text(errorMessage)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
            .disabled(model.isBusy)
            .dismissKeyboard()
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("card.interaction.cancel") { dismiss() }
                }
            }
            .interactiveDismissDisabled(model.isBusy)
        }
        .onDisappear(perform: clearSecrets)
    }

    private var title: LocalizedStringKey {
        kind == .user ? "hardware.pin.user.title" : "hardware.pin.admin.title"
    }

    private var minimumLength: Int {
        kind == .user ? 6 : 8
    }

    private var canSubmit: Bool {
        !model.isBusy
            && current.utf8.count >= minimumLength
            && new.utf8.count >= minimumLength
            && new == confirmation
            && current != new
    }

    private func apply() async {
        do {
            let information = try await model.changeHardwarePin(
                identity: identity,
                kind: kind,
                current: current,
                new: new,
                connection: connection
            )
            clearSecrets()
            onUpdate(information)
            dismiss()
        } catch {
            clearSecrets()
        }
    }

    private func clearSecrets() {
        current = ""
        new = ""
        confirmation = ""
    }
}

private struct CardTouchPolicyView: View {
    @ObservedObject var model: OpenPgpApplicationModel
    let identity: CardIdentityFfi
    let slot: CardSlot
    let information: CardInformationFfi
    let connection: CardConnectionSelection
    let onUpdate: (CardInformationFfi) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var policy = CardTouchPolicyFfi.on
    @State private var adminPin = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent("hardware.slot") {
                        Text(slot.title)
                    }
                    LabeledContent("hardware.touch.current", value: currentPolicy)
                    Picker("hardware.touch.new", selection: $policy) {
                        Text("hardware.touch.off").tag(CardTouchPolicyFfi.off)
                        Text("hardware.touch.on").tag(CardTouchPolicyFfi.on)
                    }
                    .pickerStyle(.segmented)
                }

                Section {
                    SecureField("hardware.pin.admin.current", text: $adminPin)
                        .textContentType(.password)
                        .accessibilityIdentifier("field.hardware.touch.adminPin")
                } footer: {
                    Text("hardware.touch.adminRequired")
                }

                Section {
                    Button("hardware.touch.apply") {
                        Task { await apply() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.isBusy || adminPin.utf8.count < 8)
                    .accessibilityIdentifier("action.hardware.touch.submit")
                } footer: {
                    Text("card.pin.noStorage")
                }

                if model.isBusy {
                    ProgressView("operation.inProgress")
                }
                if let errorMessage = model.errorMessage {
                    Text(errorMessage)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
            .disabled(model.isBusy)
            .dismissKeyboard()
            .navigationTitle("hardware.touch.title")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("card.interaction.cancel") { dismiss() }
                }
            }
            .interactiveDismissDisabled(model.isBusy)
        }
        .onAppear {
            policy = currentPolicy == "On" ? .off : .on
        }
        .onDisappear { adminPin = "" }
    }

    private var currentPolicy: String {
        information.slots.first { $0.slot == slot }?.touchPolicy ?? "Unknown"
    }

    private func apply() async {
        do {
            let information = try await model.setHardwareTouchPolicy(
                identity: identity,
                slot: slot,
                policy: policy,
                adminPin: adminPin,
                connection: connection
            )
            adminPin = ""
            onUpdate(information)
            dismiss()
        } catch {
            adminPin = ""
        }
    }
}
