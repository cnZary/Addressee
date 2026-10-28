import SwiftUI
import AppleSmartCardTransport

#if canImport(CoreNFC)
import CoreNFC
#endif
#if canImport(CryptoTokenKit)
import CryptoTokenKit
#endif

enum ErrorPresenter {
    static func message(for error: Error) -> String {
        if let error = error as? CardSessionFailure {
            return message(for: error.underlying) + "\n" + error.diagnostic.presentation
        }
        if let error = error as? FileInputError {
            switch error {
            case .tooLarge:
                return String(localized: "error.fileTooLarge")
            case .unreadable:
                return String(localized: "error.operationFailed")
            }
        }
        if let error = error as? CardTransportFactoryError {
            let key = switch error {
            case .readerRequired: "error.cardReaderRequired"
            case .readerUnavailable: "error.cardReaderUnavailable"
            case .multipleReadersRequireSelection: "error.cardMultipleReaders"
            case .unsupported: "error.unsupportedOperation"
            }
            return String(localized: String.LocalizationValue(key))
        }
        #if canImport(CoreNFC)
        if let error = error as? NFCTransportError {
            if error == .cancelled {
                return String(localized: "error.operationCancelled")
            }
            return String(localized: error == .timeout
                ? "error.cardTimeout"
                : "error.cardTransportFailed")
        }
        #endif
        #if canImport(CryptoTokenKit)
        if let error = error as? CryptoTokenKitTransportError {
            if error == .cancelled {
                return String(localized: "error.operationCancelled")
            }
            return String(localized: error == .timeout
                ? "error.cardTimeout"
                : "error.cardTransportFailed")
        }
        #endif
        if error is APDUError {
            return String(localized: "error.cardTransportFailed")
        }
        if error is CardBindingStoreError {
            return String(localized: "error.cardBindingStorage")
        }
        if let error = error as? SecureEnclaveErrorFfi {
            return String(localized: error == .Cancelled
                ? "error.operationCancelled"
                : "error.remoteKeyUnavailable")
        }
        if error is SecureEnclaveBindingStoreError || error is SecureEnclaveLifecycleError {
            return String(localized: "error.secureEnclaveRecoveryFailed")
        }
        guard let error = error as? AddresseeError else {
            return String(localized: "error.operationFailed")
        }
        let key: String = switch error {
        case .CapabilityRegistryUnavailable: "error.capabilityRegistryUnavailable"
        case .EmptyPassword: "error.emptyPassword"
        case .EmptyUserId: "error.emptyUserId"
        case .AuthenticationRequired: "error.authenticationRequired"
        case .InvalidPassword: "error.invalidPassword"
        case .InvalidFingerprint: "error.invalidFingerprint"
        case .KeyNotFound: "error.keyNotFound"
        case .PublicKeyOnly: "error.publicKeyOnly"
        case .ExportDisabled: "error.exportDisabled"
        case .ConflictingCertificate: "error.conflictingCertificate"
        case .InvalidCertificate: "error.invalidCertificate"
        case .UnsupportedOperation: "error.unsupportedOperation"
        case .InvalidInput: "error.invalidInput"
        case .ResourceLimit: "error.resourceLimit"
        case .NotEncrypted: "error.notEncrypted"
        case .RemoteKeyUnavailable: "error.remoteKeyUnavailable"
        case .CardRegistrationConflict: "error.cardRegistrationConflict"
        case .CardSessionUnavailable: "error.cardSessionUnavailable"
        case .AmbiguousPrivateKeyStorage: "error.ambiguousPrivateKeyStorage"
        case .OperationCancelled: "error.operationCancelled"
        case .InternalFailure: "error.operationFailed"
        }
        return NSLocalizedString(key, comment: "")
    }
}

extension CertificateSummary {
    var displayName: String {
        if let primary = userIds.first(where: { $0.isPrimary && $0.utf8 != nil })?.utf8 {
            return primary
        }
        if let first = userIds.first(where: { $0.utf8 != nil })?.utf8 {
            return first
        }
        return fingerprint
    }

    var isSecret: Bool {
        storage == .softwareSecret
    }

    var protectionTitle: LocalizedStringKey {
        switch storage {
        case .publicOnly: "keys.protection.publicOnly"
        case .softwareSecret: "keys.protection.software"
        }
    }
}
