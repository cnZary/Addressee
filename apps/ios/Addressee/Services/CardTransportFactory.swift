import Foundation
import AppleSmartCardTransport

#if canImport(CoreNFC)
@preconcurrency import CoreNFC
#endif
#if canImport(CryptoTokenKit)
@preconcurrency import CryptoTokenKit
#endif

enum CardConnectionMethod: String, CaseIterable, Identifiable, Codable, Sendable {
    case nfc
    case usb

    var id: String { rawValue }
}

struct CardConnectionSelection: Codable, Equatable, Sendable {
    var method: CardConnectionMethod
    var readerName: String?

    init(method: CardConnectionMethod = .nfc, readerName: String? = nil) {
        self.method = method
        self.readerName = method == .nfc ? nil : readerName
    }

    var isComplete: Bool {
        isComplete(allowsMultipleHardwareKeys: false)
    }

    func isComplete(allowsMultipleHardwareKeys: Bool) -> Bool {
        switch method {
        case .nfc:
            return readerName == nil
        case .usb:
            if allowsMultipleHardwareKeys {
                return hasValidReaderName
            }
            return readerName == nil || hasValidReaderName
        }
    }

    private var hasValidReaderName: Bool {
        guard let readerName else { return false }
        return !readerName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && readerName.count <= 1_024
            && readerName.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value != 0x7F }
    }

    func validate() throws {
        guard isComplete else { throw AddresseeError.InvalidInput }
    }
}

struct CardConnectionPreferenceStore {
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func selection(for fingerprint: String) -> CardConnectionSelection {
        let method = defaults.string(forKey: methodKey(fingerprint))
            .flatMap(CardConnectionMethod.init(rawValue:)) ?? .nfc
        let readerName = defaults.string(forKey: readerKey(fingerprint))
        let selection = CardConnectionSelection(method: method, readerName: readerName)
        return method == .nfc || selection.isComplete
            ? selection
            : CardConnectionSelection(method: .usb)
    }

    func record(_ selection: CardConnectionSelection, for fingerprint: String) {
        guard selection.isComplete else { return }
        defaults.set(selection.method.rawValue, forKey: methodKey(fingerprint))
        defaults.set(selection.readerName, forKey: readerKey(fingerprint))
    }

    private func methodKey(_ fingerprint: String) -> String {
        "card.connection.method.\(fingerprint)"
    }

    private func readerKey(_ fingerprint: String) -> String {
        "card.connection.reader.\(fingerprint)"
    }
}

struct ConnectedCardTransport: Sendable {
    let transport: any APDUTransport
    let capabilities: APDUTransportCapabilities
    private let alertHandler: @Sendable (String) -> Void
    private let closeHandler: @Sendable (String?) async throws -> Void

    init(
        transport: any APDUTransport,
        capabilities: APDUTransportCapabilities,
        onAlertMessage: (@Sendable (String) -> Void)? = nil,
        onClose: (@Sendable (String?) async throws -> Void)? = nil
    ) {
        self.transport = transport
        self.capabilities = capabilities
        alertHandler = onAlertMessage ?? { message in
            #if canImport(CoreNFC)
            (transport as? NFCTransport)?.updateAlertMessage(message)
            #endif
        }
        closeHandler = onClose ?? { successMessage in
            #if canImport(CoreNFC)
            if let transport = transport as? NFCTransport, let successMessage {
                await transport.close(successMessage: successMessage)
                return
            }
            #endif
            try await transport.close()
        }
    }

    func updateAlertMessage(_ message: String) {
        alertHandler(message)
    }

    func close(successMessage: String? = nil) async throws {
        try await closeHandler(successMessage)
    }
}

enum CardTransportFactoryError: Error, Equatable {
    case readerRequired
    case readerUnavailable
    case multipleReadersRequireSelection
    case unsupported
}

protocol CardTransportOpening: Sendable {
    func readerNames() async throws -> [String]
    func connect(
        method: CardConnectionMethod,
        readerName: String?,
        alertMessage: String
    ) async throws -> ConnectedCardTransport
}

struct CardTransportFactory: CardTransportOpening {
    private let settings: HardwareConnectionSettings
    private let readerNamesProvider: @Sendable () async throws -> [String]
    private let usbConnector: @Sendable (String) async throws -> ConnectedCardTransport
    private let nfcConnector: @Sendable (String) async throws -> ConnectedCardTransport

    init(
        settings: HardwareConnectionSettings = HardwareConnectionSettings(),
        readerNamesProvider: (@Sendable () async throws -> [String])? = nil,
        usbConnector: (@Sendable (String) async throws -> ConnectedCardTransport)? = nil,
        nfcConnector: (@Sendable (String) async throws -> ConnectedCardTransport)? = nil
    ) {
        self.settings = settings
        self.readerNamesProvider = readerNamesProvider ?? { try await Self.systemReaderNames() }
        self.usbConnector = usbConnector ?? { try await Self.connectUSB(readerName: $0) }
        self.nfcConnector = nfcConnector ?? { try await Self.connectNFC(alertMessage: $0) }
    }

    static func nfcIsAvailable() -> Bool {
        #if canImport(CoreNFC)
        return NFCTagReaderSession.readingAvailable
        #else
        return false
        #endif
    }

    func readerNames() async throws -> [String] {
        try await readerNamesProvider()
    }

    func connect(
        method: CardConnectionMethod,
        readerName: String?,
        alertMessage: String
    ) async throws -> ConnectedCardTransport {
        switch method {
        case .nfc:
            return try await nfcConnector(alertMessage)
        case .usb:
            let readerName = try await resolveUSBReaderName(requestedName: readerName)
            return try await usbConnector(readerName)
        }
    }

    private func resolveUSBReaderName(requestedName: String?) async throws -> String {
        let selection = CardConnectionSelection(method: .usb, readerName: requestedName)
        guard selection.isComplete(allowsMultipleHardwareKeys: settings.allowsMultipleHardwareKeys) else {
            throw CardTransportFactoryError.readerRequired
        }
        let availableReaders = try await readerNamesProvider()
        if settings.allowsMultipleHardwareKeys {
            guard let requestedName, availableReaders.contains(requestedName) else {
                throw CardTransportFactoryError.readerUnavailable
            }
            return requestedName
        }
        guard availableReaders.count == 1, let readerName = availableReaders.first else {
            throw availableReaders.isEmpty
                ? CardTransportFactoryError.readerUnavailable
                : CardTransportFactoryError.multipleReadersRequireSelection
        }
        return readerName
    }

    private static func systemReaderNames() async throws -> [String] {
        #if canImport(CryptoTokenKit)
        return try await Task.detached(priority: .userInitiated) {
            try CryptoTokenKitTransport.readerNames()
        }.value
        #else
        throw CardTransportFactoryError.unsupported
        #endif
    }

    private static func connectUSB(readerName: String) async throws -> ConnectedCardTransport {
        #if canImport(CryptoTokenKit)
        let transport = CryptoTokenKitTransport()
        do {
            try await transport.connect(readerName: readerName)
            let capabilities = transport.capabilities
            return ConnectedCardTransport(transport: transport, capabilities: capabilities)
        } catch {
            await transport.close()
            throw error
        }
        #else
        throw CardTransportFactoryError.unsupported
        #endif
    }

    private static func connectNFC(alertMessage: String) async throws -> ConnectedCardTransport {
        #if canImport(CoreNFC)
        let transport = NFCTransport(alertMessage: alertMessage)
        do {
            try await transport.connect()
            let capabilities = transport.capabilities
            return ConnectedCardTransport(transport: transport, capabilities: capabilities)
        } catch {
            await transport.close()
            throw error
        }
        #else
        throw CardTransportFactoryError.unsupported
        #endif
    }
}
