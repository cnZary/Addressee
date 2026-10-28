import AppleSmartCardTransport
import XCTest
@testable import Addressee

final class CardTransportFactoryTests: XCTestCase {
    private var defaultsSuite = ""
    private var settings: HardwareConnectionSettings!

    override func setUpWithError() throws {
        defaultsSuite = "CardTransportFactoryTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: defaultsSuite))
        defaults.removePersistentDomain(forName: defaultsSuite)
        settings = HardwareConnectionSettings(defaults: defaults)
    }

    override func tearDownWithError() throws {
        UserDefaults(suiteName: defaultsSuite)?.removePersistentDomain(forName: defaultsSuite)
        settings = nil
    }

    func testDefaultUSBUsesTheOnlyCurrentReaderInsteadOfAStalePreference() async throws {
        let (factory, probe) = makeFactory(readers: ["Current USB Reader"])

        _ = try await factory.connect(method: .usb, readerName: "Stale USB Reader", alertMessage: "")

        let enumerationCount = await probe.enumerationCount
        let connectedReaders = await probe.connectedReaders
        XCTAssertEqual(enumerationCount, 1)
        XCTAssertEqual(connectedReaders, ["Current USB Reader"])
    }

    func testDefaultUSBRejectsNoReaderAndMultipleReadersWithoutConnecting() async throws {
        for (readers, expectedError) in [
            ([] as [String], CardTransportFactoryError.readerUnavailable),
            (["First", "Second"], .multipleReadersRequireSelection),
        ] {
            let (factory, probe) = makeFactory(readers: readers)
            do {
                _ = try await factory.connect(method: .usb, readerName: "First", alertMessage: "")
                XCTFail("Reader ambiguity must not be resolved implicitly")
            } catch {
                XCTAssertEqual(error as? CardTransportFactoryError, expectedError)
            }
            let enumerationCount = await probe.enumerationCount
            let connectedReaders = await probe.connectedReaders
            XCTAssertEqual(enumerationCount, 1)
            XCTAssertTrue(connectedReaders.isEmpty)
        }
    }

    func testMultiHardwareKeyModeRequiresAndUsesAnExplicitCurrentReader() async throws {
        let (factory, probe) = makeFactory(readers: ["First", "Second"], allowsMultipleHardwareKeys: true)
        do {
            _ = try await factory.connect(method: .usb, readerName: nil, alertMessage: "")
            XCTFail("Explicit mode must not select a reader implicitly")
        } catch {
            XCTAssertEqual(error as? CardTransportFactoryError, .readerRequired)
        }
        var enumerationCount = await probe.enumerationCount
        XCTAssertEqual(enumerationCount, 0)

        _ = try await factory.connect(method: .usb, readerName: "Second", alertMessage: "")
        let connectedReaders = await probe.connectedReaders
        XCTAssertEqual(connectedReaders, ["Second"])

        do {
            _ = try await factory.connect(method: .usb, readerName: "Missing", alertMessage: "")
            XCTFail("An unavailable selected reader must not fall back to another reader")
        } catch {
            XCTAssertEqual(error as? CardTransportFactoryError, .readerUnavailable)
        }
        enumerationCount = await probe.enumerationCount
        let readersAfterFailure = await probe.connectedReaders
        XCTAssertEqual(enumerationCount, 2)
        XCTAssertEqual(readersAfterFailure, ["Second"])
    }

    func testRepeatedUSBOperationsTakeOneFreshSnapshotEach() async throws {
        let (factory, probe) = makeFactory(readers: ["Only Reader"])
        _ = try await factory.connect(method: .usb, readerName: nil, alertMessage: "")
        await probe.setReaders(["Replacement Reader"])
        _ = try await factory.connect(method: .usb, readerName: nil, alertMessage: "")

        let enumerationCount = await probe.enumerationCount
        let connectedReaders = await probe.connectedReaders
        XCTAssertEqual(enumerationCount, 2)
        XCTAssertEqual(connectedReaders, ["Only Reader", "Replacement Reader"])
    }

    func testNFCDoesNotEnumerateUSBReaders() async throws {
        let (factory, probe) = makeFactory(readers: ["Only Reader"])
        _ = try await factory.connect(method: .nfc, readerName: nil, alertMessage: "Synthetic NFC alert")

        let enumerationCount = await probe.enumerationCount
        let nfcAlerts = await probe.nfcAlerts
        XCTAssertEqual(enumerationCount, 0)
        XCTAssertEqual(nfcAlerts, ["Synthetic NFC alert"])
    }

    func testReaderFailuresHaveDistinctLocalizedMessages() {
        XCTAssertEqual(
            ErrorPresenter.message(for: CardTransportFactoryError.readerUnavailable),
            NSLocalizedString("error.cardReaderUnavailable", comment: "")
        )
        XCTAssertEqual(
            ErrorPresenter.message(for: CardTransportFactoryError.multipleReadersRequireSelection),
            NSLocalizedString("error.cardMultipleReaders", comment: "")
        )
    }

    private func makeFactory(
        readers: [String],
        allowsMultipleHardwareKeys: Bool = false
    ) -> (CardTransportFactory, CardTransportProbe) {
        settings.allowsMultipleHardwareKeys = allowsMultipleHardwareKeys
        let probe = CardTransportProbe(readers: readers)
        return (
            CardTransportFactory(
                settings: settings,
                readerNamesProvider: { await probe.readerNames() },
                usbConnector: { await probe.connectUSB(readerName: $0) },
                nfcConnector: { await probe.connectNFC(alertMessage: $0) }
            ),
            probe
        )
    }
}

private actor CardTransportProbe {
    private var readers: [String]
    private(set) var enumerationCount = 0
    private(set) var connectedReaders: [String] = []
    private(set) var nfcAlerts: [String] = []

    init(readers: [String]) {
        self.readers = readers
    }

    func readerNames() -> [String] {
        enumerationCount += 1
        return readers
    }

    func setReaders(_ readers: [String]) {
        self.readers = readers
    }

    func connectUSB(readerName: String) -> ConnectedCardTransport {
        connectedReaders.append(readerName)
        return Self.connection()
    }

    func connectNFC(alertMessage: String) -> ConnectedCardTransport {
        nfcAlerts.append(alertMessage)
        return Self.connection()
    }

    private static func connection() -> ConnectedCardTransport {
        ConnectedCardTransport(transport: ProbeTransport(), capabilities: .shortOnly)
    }
}

private struct ProbeTransport: APDUTransport {
    let capabilities = APDUTransportCapabilities.shortOnly

    func transmit(_ command: Data) async throws -> Data {
        throw APDUError.transportClosed
    }

    func close() async throws {}
}
