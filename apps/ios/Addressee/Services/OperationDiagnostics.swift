import Foundation
import OSLog
import AppleSmartCardTransport

enum OperationDiagnostics {
    private static let logger = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "app.addressee",
        category: "CryptographicOperation"
    )

    static func record(_ error: Error) {
        logger.error("\(description(for: error), privacy: .public)")
    }

    static func description(for error: Error) -> String {
        if let error = error as? CardSessionFailure {
            return "Card operation failed; \(error.diagnostic.consoleDescription); \(description(for: error.underlying))"
        }
        if let error = error as? AddresseeError {
            return "OpenPGP operation failed; \(String(describing: error))"
        }
        if let error = error as? APDUError {
            return "APDU validation failed; \(String(describing: error))"
        }
        return "Operation failed; type=\(String(reflecting: type(of: error)))"
    }
}
