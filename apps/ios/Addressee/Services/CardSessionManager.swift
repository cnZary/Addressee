import Foundation
import AppleSmartCardTransport

struct CardSessionOpenRequest: Sendable {
    let certificateFingerprint: String
    let signingComponent: String?
    let decryptionComponent: String?
    let method: CardConnectionMethod
    let readerName: String?
    let candidateRegistrations: [CardRegistrationFfi]?
    let alertMessage: String
    let interactionMode: CardInteractionMode
}

struct OpenedCardSession: Sendable {
    let registration: CardRegistrationFfi
    let connection: ConnectedCardTransport
    let attach: @Sendable () async throws -> CardRegistrationFfi
    let management: @Sendable () async throws -> OpenPgpCardManagementSession
    let authorization: @Sendable (CardSlot) async throws -> CardOperationAuthorizationFfi
    var describeFailure: (@Sendable (Error, CardOperationStage) -> Error)?
}

enum CardManagementPurpose: Sendable, Equatable {
    case inspection
    case p256Provisioning

    var alertMessage: String {
        switch self {
        case .inspection: String(localized: "hardware.nfc.managementAlert")
        case .p256Provisioning: String(localized: "hardware.nfc.provisioningAlert")
        }
    }

    var progressMessage: String {
        switch self {
        case .inspection: String(localized: "hardware.nfc.managementInProgress")
        case .p256Provisioning: String(localized: "hardware.nfc.provisioningInProgress")
        }
    }

    var successMessage: String {
        switch self {
        case .inspection: String(localized: "hardware.nfc.managementComplete")
        case .p256Provisioning: String(localized: "hardware.nfc.provisioningComplete")
        }
    }
}

struct CardManagementOpenRequest: Sendable {
    let method: CardConnectionMethod
    let readerName: String?
    let expectedIdentity: CardIdentityFfi?
    let purpose: CardManagementPurpose
}

struct OpenedCardManagementSession: Sendable {
    let identity: CardIdentityFfi
    let connection: ConnectedCardTransport
    let management: @Sendable () async throws -> OpenPgpCardManagementSession
    var describeFailure: (@Sendable (Error, CardOperationStage) -> Error)?
}

@MainActor
protocol CardSessionManaging: AnyObject, Sendable {
    var registrations: [CardRegistrationFfi] { get }
    var onChange: (([CardRegistrationFfi]) -> Void)? { get set }

    func restore() async throws
    func readerNames() async throws -> [String]
    func preferredConnection(for fingerprint: String) -> CardConnectionSelection
    func connect(
        certificateFingerprint: String,
        signingComponent: String?,
        decryptionComponent: String?,
        method: CardConnectionMethod,
        readerName: String?
    ) async throws -> CardRegistrationFfi
    func disconnect(certificateFingerprint: String) async throws
    func disconnect(certificateFingerprint: String, identity: CardIdentityFfi) async throws
    func withCardSession<T: Sendable>(
        certificateFingerprint: String,
        operation: PrivateKeyOperation,
        connection: CardConnectionSelection,
        body: @escaping @Sendable () async throws -> T
    ) async throws -> T
    func withUnboundCardManagementSession<T: Sendable>(
        expectedIdentity: CardIdentityFfi?,
        connection: CardConnectionSelection,
        purpose: CardManagementPurpose,
        operation: @escaping @Sendable (OpenPgpCardManagementSession) async throws -> T
    ) async throws -> T
}

@MainActor
final class CardSessionManager: CardSessionManaging {
    private(set) var registrations: [CardRegistrationFfi] = []
    var onChange: (([CardRegistrationFfi]) -> Void)?

    private let interaction: CardInteractionCoordinator
    private let transports: any CardTransportOpening
    private let store: CardBindingStore
    private let preferences: CardConnectionPreferenceStore
    private let openSession: @Sendable (CardSessionOpenRequest) async throws -> OpenedCardSession
    private let openManagement: @Sendable (CardManagementOpenRequest) async throws -> OpenedCardManagementSession
    private let reserveCard: @Sendable (CardRegistrationFfi) async throws -> Void
    private let releaseCard: @Sendable (String) async throws -> Void
    private let detachCard: @Sendable (String) async throws -> Void
    private let publicOnlyFingerprints: @Sendable () async throws -> Set<String>
    private var bindings: [String: [CardBinding]] = [:]
    private var reservedBindings: [String: CardBinding] = [:]
    private var didRestore = false
    private var isTransitioning = false

    init(
        engine: OpenPgpEngine,
        interaction: CardInteractionCoordinator,
        transports: any CardTransportOpening = CardTransportFactory(),
        store: CardBindingStore = .inMemory(),
        preferences: CardConnectionPreferenceStore = CardConnectionPreferenceStore(),
        openSession: (@Sendable (CardSessionOpenRequest) async throws -> OpenedCardSession)? = nil,
        openManagement: (@Sendable (CardManagementOpenRequest) async throws -> OpenedCardManagementSession)? = nil,
        reserveCard: (@Sendable (CardRegistrationFfi) async throws -> Void)? = nil,
        releaseCard: (@Sendable (String) async throws -> Void)? = nil,
        detachCard: (@Sendable (String) async throws -> Void)? = nil,
        publicOnlyFingerprints: (@Sendable () async throws -> Set<String>)? = nil
    ) {
        self.interaction = interaction
        self.transports = transports
        self.store = store
        self.preferences = preferences
        self.reserveCard = reserveCard ?? { registration in
            try await Task.detached(priority: .userInitiated) { [engine] in
                let publicCertificate = try engine.exportPublicKey(
                    fingerprint: registration.certificateFingerprint,
                    format: .binary
                )
                try engine.reserveCardBinding(
                    registration: registration,
                    publicCertificate: publicCertificate
                )
            }.value
        }
        self.releaseCard = releaseCard ?? { fingerprint in
            try await Task.detached(priority: .userInitiated) { [engine] in
                try engine.releaseCardBinding(certificateFingerprint: fingerprint)
            }.value
        }
        self.detachCard = detachCard ?? { fingerprint in
            try await Task.detached(priority: .userInitiated) { [engine] in
                try engine.detachCardSession(certificateFingerprint: fingerprint)
            }.value
        }
        self.publicOnlyFingerprints = publicOnlyFingerprints ?? {
            try await Task.detached(priority: .userInitiated) { [engine] in
                Set(try engine.listKeys().filter { $0.storage == .publicOnly }.map(\.fingerprint))
            }.value
        }
        self.openSession = openSession ?? { [transports, interaction] request in
            let publicOnly = try await Task.detached(priority: .userInitiated) { [engine] in
                try engine.listKeys().contains {
                    $0.fingerprint == request.certificateFingerprint && $0.storage == .publicOnly
                }
            }.value
            guard publicOnly else { throw AddresseeError.AmbiguousPrivateKeyStorage }
            let diagnostics = CardSessionDiagnostics(method: request.method)
            let opened: ConnectedCardTransport
            do {
                opened = try await transports.connect(
                    method: request.method,
                    readerName: request.readerName,
                    alertMessage: request.alertMessage
                )
            } catch {
                throw diagnostics.failure(error, stage: .connecting)
            }
            opened.updateAlertMessage(String(localized: "hardware.nfc.reading"))
            do {
                let bridge = CardTransportBridge(
                    transport: opened.transport,
                    capabilities: opened.capabilities,
                    onStatus: { diagnostics.record(status: $0) },
                    onDiagnostic: { diagnostics.record($0) }
                )
                let callbacks = await interaction.callbacks(for: request.interactionMode)
                let session = try await Task.detached(priority: .userInitiated) { [engine] in
                    let publicCertificate = try engine.exportPublicKey(
                        fingerprint: request.certificateFingerprint,
                        format: .binary
                    )
                    let identity = try readCardIdentity(transport: bridge)
                    var signingComponent = request.signingComponent
                    var decryptionComponent = request.decryptionComponent
                    if let candidates = request.candidateRegistrations {
                        guard let selected = candidates.first(where: {
                            $0.certificateFingerprint == request.certificateFingerprint
                                && $0.identity == identity
                        }) else {
                            throw AddresseeError.CardRegistrationConflict
                        }
                        signingComponent = selected.components.first(where: {
                            $0.slot == .signing
                        })?.componentFingerprint
                        decryptionComponent = selected.components.first(where: {
                            $0.slot == .decryption
                        })?.componentFingerprint
                    }
                    return try OpenPgpCardSession.connect(
                        identity: identity,
                        publicCertificate: publicCertificate,
                        signingComponent: signingComponent,
                        decryptionComponent: decryptionComponent,
                        transport: bridge,
                        pinProvider: callbacks,
                        touchPrompt: callbacks
                    )
                }.value
                return OpenedCardSession(
                    registration: session.registration(),
                    connection: opened,
                    attach: { [engine] in
                        diagnostics.begin(.reading)
                        do {
                            let registration = try await Task.detached(priority: .userInitiated) {
                                try engine.attachCardSession(session: session)
                            }.value
                            diagnostics.begin(.privateKeyOperation)
                            return registration
                        } catch {
                            throw diagnostics.failure(error)
                        }
                    },
                    management: {
                        let identity = session.identity()
                        return try await Task.detached(priority: .userInitiated) {
                            try OpenPgpCardManagementSession.connect(
                                identity: identity,
                                transport: bridge
                            )
                        }.value
                    },
                    authorization: { slot in
                        try await Task.detached(priority: .userInitiated) {
                            try session.authorizationRequirements(slot: slot)
                        }.value
                    },
                    describeFailure: { error, stage in
                        diagnostics.failure(error, stage: stage)
                    }
                )
            } catch {
                await interaction.cancelActiveInteraction()
                try? await opened.close()
                throw diagnostics.failure(error)
            }
        }
        self.openManagement = openManagement ?? { [transports, interaction] request in
            let diagnostics = CardSessionDiagnostics(method: request.method)
            let opened: ConnectedCardTransport
            do {
                opened = try await transports.connect(
                    method: request.method,
                    readerName: request.readerName,
                    alertMessage: request.purpose.alertMessage
                )
            } catch {
                throw diagnostics.failure(error, stage: .connecting)
            }
            opened.updateAlertMessage(String(localized: "hardware.nfc.reading"))
            do {
                let bridge = CardTransportBridge(
                    transport: opened.transport,
                    capabilities: opened.capabilities,
                    onStatus: { diagnostics.record(status: $0) },
                    onDiagnostic: { diagnostics.record($0) }
                )
                let identity = try await Task.detached(priority: .userInitiated) {
                    try readCardIdentity(transport: bridge)
                }.value
                if let expected = request.expectedIdentity, identity != expected {
                    throw AddresseeError.CardRegistrationConflict
                }
                return OpenedCardManagementSession(
                    identity: identity,
                    connection: opened,
                    management: {
                        try await Task.detached(priority: .userInitiated) {
                            try OpenPgpCardManagementSession.connect(
                                identity: identity,
                                transport: bridge
                            )
                        }.value
                    },
                    describeFailure: { error, stage in
                        diagnostics.failure(error, stage: stage)
                    }
                )
            } catch {
                await interaction.cancelActiveInteraction()
                try? await opened.close()
                throw diagnostics.failure(error)
            }
        }
    }

    func restore() async throws {
        guard !didRestore else { return }
        try beginTransition()
        defer { isTransitioning = false }
        let stored = try await store.bindings()
        let publicOnly = try await publicOnlyFingerprints()
        let valid = stored.filter { publicOnly.contains($0.certificateFingerprint) }
        if valid != stored {
            try await store.replaceAll(valid)
        }
        let restored = Dictionary(grouping: valid, by: \.certificateFingerprint)
        for certificateFingerprint in restored.keys.sorted() {
            guard let binding = restored[certificateFingerprint]?.first else { continue }
            try await ensureReserved(binding)
        }
        bindings = restored
        didRestore = true
        publish()
    }

    func readerNames() async throws -> [String] {
        try await transports.readerNames()
    }

    func preferredConnection(for fingerprint: String) -> CardConnectionSelection {
        preferences.selection(for: fingerprint)
    }

    func connect(
        certificateFingerprint: String,
        signingComponent: String?,
        decryptionComponent: String?,
        method: CardConnectionMethod,
        readerName: String?
    ) async throws -> CardRegistrationFfi {
        try await restore()
        try beginTransition()
        defer { isTransitioning = false }
        let previousReservation = reservedBindings[certificateFingerprint]
        let selection = CardConnectionSelection(method: method, readerName: readerName)
        try selection.validate()
        try await ensureDetached(certificateFingerprint: certificateFingerprint)
        let opened = try await openSession(CardSessionOpenRequest(
            certificateFingerprint: certificateFingerprint,
            signingComponent: signingComponent,
            decryptionComponent: decryptionComponent,
            method: method,
            readerName: selection.readerName,
            candidateRegistrations: nil,
            alertMessage: String(localized: "hardware.nfc.alert"),
            interactionMode: .interactive
        ))
        var stored: CardBinding?
        do {
            let binding = try CardBinding(registration: opened.registration)
            guard binding.certificateFingerprint == certificateFingerprint else {
                throw AddresseeError.CardRegistrationConflict
            }
            try await store.insert(binding)
            stored = binding
            try await ensureReserved(binding)
            try await opened.connection.close(
                successMessage: String(localized: "hardware.nfc.linked")
            )
            bindings[certificateFingerprint, default: []].append(binding)
            bindings[certificateFingerprint]?.sort {
                $0.registration.identity.displayIdentifier < $1.registration.identity.displayIdentifier
            }
            preferences.record(selection, for: certificateFingerprint)
            publish()
            return binding.registration
        } catch {
            interaction.cancelActiveInteraction()
            var cleanupFailed = false
            if let stored {
                do {
                    try await store.remove(
                        certificateFingerprint: stored.certificateFingerprint,
                        identity: stored.identity.ffi()
                    )
                    if reservedBindings[certificateFingerprint] == stored {
                        if let previousReservation {
                            try await ensureReserved(previousReservation)
                        } else {
                            try await releaseCard(certificateFingerprint)
                            reservedBindings.removeValue(forKey: certificateFingerprint)
                        }
                    }
                } catch {
                    cleanupFailed = true
                }
            }
            do {
                try await opened.connection.close()
            } catch {
                cleanupFailed = true
            }
            if cleanupFailed { throw AddresseeError.CardSessionUnavailable }
            throw error
        }
    }

    func disconnect(certificateFingerprint: String) async throws {
        try await restore()
        try beginTransition()
        defer { isTransitioning = false }
        guard let existing = bindings[certificateFingerprint], !existing.isEmpty else {
            throw AddresseeError.CardSessionUnavailable
        }
        interaction.cancelActiveInteraction()
        try await ensureDetached(certificateFingerprint: certificateFingerprint)
        try await store.remove(certificateFingerprint: certificateFingerprint)
        do {
            try await releaseCard(certificateFingerprint)
        } catch {
            do {
                for binding in existing {
                    try await store.insert(binding)
                }
            } catch {
                throw AddresseeError.CardSessionUnavailable
            }
            throw error
        }
        bindings.removeValue(forKey: certificateFingerprint)
        reservedBindings.removeValue(forKey: certificateFingerprint)
        publish()
    }

    func disconnect(certificateFingerprint: String, identity: CardIdentityFfi) async throws {
        try await restore()
        try beginTransition()
        defer { isTransitioning = false }
        guard var remaining = bindings[certificateFingerprint],
              let binding = remaining.first(where: { $0.identity == CardIdentityRecord(identity) }) else {
            throw AddresseeError.CardSessionUnavailable
        }
        interaction.cancelActiveInteraction()
        try await ensureDetached(certificateFingerprint: certificateFingerprint)
        try await store.remove(certificateFingerprint: certificateFingerprint, identity: identity)
        remaining.removeAll { $0.identity == CardIdentityRecord(identity) }
        do {
            if remaining.isEmpty {
                try await releaseCard(certificateFingerprint)
                reservedBindings.removeValue(forKey: certificateFingerprint)
            } else if reservedBindings[certificateFingerprint] == binding {
                try await ensureReserved(remaining[0])
            }
        } catch {
            do {
                try await store.insert(binding)
            } catch {
                throw AddresseeError.CardSessionUnavailable
            }
            throw error
        }
        if remaining.isEmpty {
            bindings.removeValue(forKey: certificateFingerprint)
        } else {
            bindings[certificateFingerprint] = remaining
        }
        publish()
    }

    func withCardSession<T: Sendable>(
        certificateFingerprint: String,
        operation: PrivateKeyOperation,
        connection: CardConnectionSelection,
        body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await restore()
        guard let candidates = bindings[certificateFingerprint], !candidates.isEmpty else {
            throw AddresseeError.CardSessionUnavailable
        }
        try connection.validate()
        try beginTransition()
        defer {
            interaction.cancelActiveInteraction()
            isTransitioning = false
        }
        try await ensureReserved(reservedBindings[certificateFingerprint] ?? candidates[0])
        try await ensureDetached(certificateFingerprint: certificateFingerprint)
        if connection.method == .nfc {
            let operationID = UUID()
            try await interaction.preparePin(
                operationID: operationID,
                slot: operation.cardSlot,
                identities: candidates.map { $0.identity.ffi() }
            )
            return try await performAttached(
                bindings: candidates,
                selection: connection,
                interactionMode: .preparedNFC(id: operationID, slot: operation.cardSlot),
                alertMessage: String(localized: "hardware.nfc.touchPossibleAlert"),
                body: body
            )
        }
        return try await performAttached(
            bindings: candidates,
            selection: connection,
            interactionMode: .interactive,
            alertMessage: String(localized: "hardware.nfc.operationAlert"),
            body: body
        )
    }

    func withUnboundCardManagementSession<T: Sendable>(
        expectedIdentity: CardIdentityFfi?,
        connection: CardConnectionSelection,
        purpose: CardManagementPurpose = .inspection,
        operation: @escaping @Sendable (OpenPgpCardManagementSession) async throws -> T
    ) async throws -> T {
        try connection.validate()
        try beginTransition()
        defer {
            interaction.cancelActiveInteraction()
            isTransitioning = false
        }
        var opened: OpenedCardManagementSession?
        var finished = false
        do {
            let session = try await openManagement(CardManagementOpenRequest(
                method: connection.method,
                readerName: connection.readerName,
                expectedIdentity: expectedIdentity,
                purpose: purpose
            ))
            opened = session
            if let expectedIdentity, session.identity != expectedIdentity {
                throw AddresseeError.CardRegistrationConflict
            }
            let management = try await session.management()
            session.connection.updateAlertMessage(purpose.progressMessage)
            let result = try await Task.detached(priority: .userInitiated) {
                try await operation(management)
            }.value
            finished = true
            try await session.connection.close(successMessage: purpose.successMessage)
            return result
        } catch {
            interaction.cancelActiveInteraction()
            if let opened, !finished {
                try? await opened.connection.close()
            }
            throw opened?.describeFailure?(error, .management) ?? error
        }
    }

    private func performAttached<T: Sendable>(
        bindings: [CardBinding],
        selection: CardConnectionSelection,
        interactionMode: CardInteractionMode,
        alertMessage: String,
        body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        var opened: OpenedCardSession?
        var attached = false
        var finished = false
        do {
            let session = try await openSession(openRequest(
                bindings: bindings,
                selection: selection,
                alertMessage: alertMessage,
                interactionMode: interactionMode
            ))
            opened = session
            guard let binding = bindings.first(where: {
                $0.registration == session.registration
            }) else {
                throw AddresseeError.CardRegistrationConflict
            }
            if reservedBindings[binding.certificateFingerprint] != binding {
                try await ensureReserved(binding)
            }
            let registration = try await session.attach()
            attached = true
            guard registration == binding.registration else {
                throw AddresseeError.CardRegistrationConflict
            }
            session.connection.updateAlertMessage(
                String(localized: "hardware.nfc.privateOperationInProgress")
            )
            let result = try await Task.detached(priority: .userInitiated, operation: body).value
            finished = true
            try await finish(
                session,
                attached: attached,
                successMessage: String(localized: "hardware.nfc.operationComplete")
            )
            preferences.record(selection, for: binding.certificateFingerprint)
            return result
        } catch {
            interaction.cancelActiveInteraction()
            if let opened, !finished {
                try? await finish(opened, attached: attached, successMessage: nil)
            }
            throw opened?.describeFailure?(error, .privateKeyOperation) ?? error
        }
    }

    private func openRequest(
        bindings: [CardBinding],
        selection: CardConnectionSelection,
        alertMessage: String,
        interactionMode: CardInteractionMode
    ) -> CardSessionOpenRequest {
        CardSessionOpenRequest(
            certificateFingerprint: bindings[0].certificateFingerprint,
            signingComponent: bindings[0].signingComponent,
            decryptionComponent: bindings[0].decryptionComponent,
            method: selection.method,
            readerName: selection.readerName,
            candidateRegistrations: bindings.map(\.registration),
            alertMessage: alertMessage,
            interactionMode: interactionMode
        )
    }

    private func finish(
        _ session: OpenedCardSession,
        attached: Bool,
        successMessage: String?
    ) async throws {
        var failure: Error?
        if attached {
            do {
                try await detachCard(session.registration.certificateFingerprint)
            } catch {
                failure = error
            }
        }
        do {
            try await session.connection.close(successMessage: failure == nil ? successMessage : nil)
        } catch {
            if failure == nil { failure = error }
        }
        if let failure { throw failure }
    }

    private func ensureDetached(certificateFingerprint: String) async throws {
        do {
            try await detachCard(certificateFingerprint)
        } catch AddresseeError.CardSessionUnavailable {
            return
        }
    }

    private func ensureReserved(_ binding: CardBinding) async throws {
        let certificateFingerprint = binding.certificateFingerprint
        let previous = reservedBindings[certificateFingerprint]
        guard previous != binding else {
            try await reserveCard(binding.registration)
            return
        }
        if previous != nil {
            try await ensureDetached(certificateFingerprint: certificateFingerprint)
            try await releaseCard(certificateFingerprint)
            reservedBindings.removeValue(forKey: certificateFingerprint)
        }
        do {
            try await reserveCard(binding.registration)
            reservedBindings[certificateFingerprint] = binding
        } catch {
            let reservationError = error
            if let previous {
                do {
                    try await reserveCard(previous.registration)
                    reservedBindings[certificateFingerprint] = previous
                } catch {
                    reservedBindings.removeValue(forKey: certificateFingerprint)
                    throw AddresseeError.CardSessionUnavailable
                }
            }
            throw reservationError
        }
    }

    private func beginTransition() throws {
        guard !isTransitioning else { throw AddresseeError.RemoteKeyUnavailable }
        isTransitioning = true
    }

    private func publish() {
        registrations = bindings.values.flatMap { $0 }.map(\.registration).sorted {
            if $0.certificateFingerprint != $1.certificateFingerprint {
                return $0.certificateFingerprint < $1.certificateFingerprint
            }
            return $0.identity.displayIdentifier < $1.identity.displayIdentifier
        }
        onChange?(registrations)
    }
}

private extension PrivateKeyOperation {
    var cardSlot: CardSlot {
        switch self {
        case .signing: .signing
        case .decryption: .decryption
        }
    }
}
