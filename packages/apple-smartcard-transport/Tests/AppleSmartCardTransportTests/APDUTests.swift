import Foundation
import Testing
@testable import AppleSmartCardTransport

private actor ScriptedTransport: APDUTransport {
    private let configuredCapabilities: APDUTransportCapabilities
    private var responses: [Data]
    private var commands: [Data] = []
    private var closed = false

    init(capabilities: APDUTransportCapabilities = .shortOnly, responses: [Data]) {
        configuredCapabilities = capabilities
        self.responses = responses
    }

    var capabilities: APDUTransportCapabilities {
        configuredCapabilities
    }

    func transmit(_ command: Data) async throws -> Data {
        if closed {
            throw APDUError.transportClosed
        }
        commands.append(command)
        if responses.isEmpty {
            throw APDUError.malformedResponse
        }
        return responses.removeFirst()
    }

    func close() async throws {
        closed = true
    }

    func recordedCommands() -> [Data] {
        commands
    }
}

@Test func shortAPDUEncodingCoversAllFourCases() throws {
    #expect(try APDUCommand(instructionCode: 0xA4).encoded() == Data([0x00, 0xA4, 0x00, 0x00]))
    #expect(try APDUCommand(instructionCode: 0xCA, expectedResponseLength: 256).encoded() == Data([0x00, 0xCA, 0x00, 0x00, 0x00]))
    #expect(try APDUCommand(instructionCode: 0x20, data: Data([1, 2, 3])).encoded() == Data([0x00, 0x20, 0x00, 0x00, 0x03, 1, 2, 3]))
    #expect(try APDUCommand(instructionCode: 0x2A, data: Data([4, 5]), expectedResponseLength: 256).encoded() == Data([0x00, 0x2A, 0x00, 0x00, 0x02, 4, 5, 0]))
}

@Test func extendedAPDUEncodingUsesCorrectLengths() throws {
    let payload = Data(repeating: 0xA5, count: 256)
    let case2 = try APDUCommand(instructionCode: 0xCA, expectedResponseLength: 65_536).encoded(mode: .extended)
    #expect(case2 == Data([0x00, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00]))

    let case3 = try APDUCommand(instructionCode: 0xDB, data: payload).encoded()
    #expect(case3.prefix(7) == Data([0x00, 0xDB, 0x00, 0x00, 0x00, 0x01, 0x00]))
    #expect(case3.count == payload.count + 7)

    let case4 = try APDUCommand(instructionCode: 0x2A, data: payload, expectedResponseLength: 65_536).encoded()
    #expect(case4.suffix(2) == Data([0x00, 0x00]))
    #expect(case4.count == payload.count + 9)
}

@Test func lengthValidationRejectsUnsupportedValues() throws {
    #expect(throws: APDUError.commandTooLarge) {
        _ = try APDUCommand(instructionCode: 0xDB, data: Data(repeating: 0, count: 256)).encoded(mode: .short)
    }
    #expect(throws: APDUError.invalidExpectedResponseLength) {
        _ = try APDUCommand(instructionCode: 0xCA, expectedResponseLength: 0).encoded()
    }
    #expect(throws: APDUError.invalidExpectedResponseLength) {
        _ = try APDUCommand(instructionCode: 0xCA).encoded(mode: .extended)
    }
}

@Test func responseParsingRejectsTruncation() throws {
    #expect(throws: APDUError.malformedResponse) {
        _ = try APDUResponse(raw: Data([0x90]))
    }
    let response = try APDUResponse(raw: Data([1, 2, 0x90, 0x00]))
    #expect(response.data == Data([1, 2]))
    #expect(response.isSuccess)
}

@Test func continuationUsesBoundedGetResponse() async throws {
    let transport = ScriptedTransport(responses: [
        Data([1, 2, 0x61, 0x02]),
        Data([3, 4, 0x61, 0x00]),
        Data([5, 0x90, 0x00]),
    ])
    let session = APDUSession(transport: transport)
    let response = try await session.execute(APDUCommand(instructionCode: 0xCA, expectedResponseLength: 256))
    #expect(response.data == Data([1, 2, 3, 4, 5]))
    #expect(response.isSuccess)
    let commands = await transport.recordedCommands()
    #expect(commands == [
        Data([0x00, 0xCA, 0x00, 0x00, 0x00]),
        Data([0x00, 0xC0, 0x00, 0x00, 0x02]),
        Data([0x00, 0xC0, 0x00, 0x00, 0x00]),
    ])
}

@Test func continuationLimitStopsLoop() async throws {
    let capabilities = APDUTransportCapabilities(
        supportsExtendedLength: false,
        maximumCommandDataLength: 255,
        maximumResponseLength: 1024,
        maximumContinuationRounds: 1
    )
    let transport = ScriptedTransport(capabilities: capabilities, responses: [
        Data([0x61, 0x01]),
        Data([0x61, 0x01]),
    ])
    let session = APDUSession(transport: transport)
    do {
        _ = try await session.execute(APDUCommand(instructionCode: 0xCA, expectedResponseLength: 256))
        Issue.record("Expected continuation limit failure")
    } catch let error as APDUError {
        #expect(error == .continuationLimitExceeded)
    }
}

@Test func aggregateResponseLimitPreventsTruncation() async throws {
    let capabilities = APDUTransportCapabilities(
        supportsExtendedLength: false,
        maximumCommandDataLength: 255,
        maximumResponseLength: 3
    )
    let transport = ScriptedTransport(capabilities: capabilities, responses: [
        Data([1, 2, 0x61, 0x02]),
        Data([3, 4, 0x90, 0x00]),
    ])
    let session = APDUSession(transport: transport)
    do {
        _ = try await session.execute(APDUCommand(instructionCode: 0xCA, expectedResponseLength: 256))
        Issue.record("Expected response size failure")
    } catch let error as APDUError {
        #expect(error == .responseTooLarge)
    }
}

@Test func lengthCorrectionRequiresExplicitPermission() async throws {
    let uncorrectedTransport = ScriptedTransport(responses: [Data([0x6C, 0x20])])
    let uncorrectedSession = APDUSession(transport: uncorrectedTransport)
    let uncorrected = try await uncorrectedSession.execute(
        APDUCommand(instructionCode: 0xCA, expectedResponseLength: 1)
    )
    #expect(uncorrected.status == 0x6C20)
    #expect(await uncorrectedTransport.recordedCommands().count == 1)

    let correctedTransport = ScriptedTransport(responses: [
        Data([0x6C, 0x20]),
        Data([0x90, 0x00]),
    ])
    let correctedSession = APDUSession(transport: correctedTransport)
    let corrected = try await correctedSession.execute(
        APDUCommand(instructionCode: 0xCA, expectedResponseLength: 1),
        policy: .readOnly
    )
    #expect(corrected.isSuccess)
    #expect(await correctedTransport.recordedCommands() == [
        Data([0x00, 0xCA, 0x00, 0x00, 0x01]),
        Data([0x00, 0xCA, 0x00, 0x00, 0x20]),
    ])
}

@Test func commandChainingSplitsOnlyWhenEnabled() async throws {
    let transport = ScriptedTransport(responses: [
        Data([0x90, 0x00]),
        Data([0x90, 0x00]),
        Data([0x90, 0x00]),
    ])
    let session = APDUSession(transport: transport)
    let response = try await session.execute(
        APDUCommand(
            instructionCode: 0xDB,
            data: Data(repeating: 0xA5, count: 600),
            expectedResponseLength: 256
        ),
        policy: APDUPolicy(allowCommandChaining: true)
    )
    #expect(response.isSuccess)
    let commands = await transport.recordedCommands()
    #expect(commands.count == 3)
    #expect(commands[0][0] == 0x10)
    #expect(commands[1][0] == 0x10)
    #expect(commands[2][0] == 0x00)
    #expect(commands[0].count == 260)
    #expect(commands[1].count == 260)
    #expect(commands[2].count == 96)
}

@Test func intermediateChainingFailureStopsWithoutRetry() async throws {
    let transport = ScriptedTransport(responses: [Data([0x69, 0x82])])
    let session = APDUSession(transport: transport)
    do {
        _ = try await session.execute(
            APDUCommand(instructionCode: 0xDB, data: Data(repeating: 0, count: 600)),
            policy: APDUPolicy(allowCommandChaining: true)
        )
        Issue.record("Expected intermediate command failure")
    } catch let error as APDUError {
        #expect(error == .intermediateCommandFailed(status: 0x6982))
    }
    #expect(await transport.recordedCommands().count == 1)
}

@Test func shortOnlyTransportRejectsExtendedResponseRequest() async throws {
    let transport = ScriptedTransport(responses: [])
    let session = APDUSession(transport: transport)
    do {
        _ = try await session.execute(APDUCommand(instructionCode: 0xCA, expectedResponseLength: 512))
        Issue.record("Expected Extended Length rejection")
    } catch let error as APDUError {
        #expect(error == .extendedLengthUnsupported)
    }
    #expect(await transport.recordedCommands().isEmpty)
}

@Test func closedSessionRejectsFurtherCommands() async throws {
    let transport = ScriptedTransport(responses: [])
    let session = APDUSession(transport: transport)
    try await session.close()
    do {
        _ = try await session.execute(APDUCommand(instructionCode: 0xCA, expectedResponseLength: 256))
        Issue.record("Expected closed-session failure")
    } catch let error as APDUError {
        #expect(error == .transportClosed)
    }
    #expect(await transport.recordedCommands().isEmpty)
}

@Test func commandDecoderRoundTripsAllLengthForms() throws {
    let commands = [
        APDUCommand(instructionCode: 0xA4),
        APDUCommand(instructionCode: 0xCA, expectedResponseLength: 256),
        APDUCommand(instructionCode: 0xCA, expectedResponseLength: 1),
        APDUCommand(instructionCode: 0x20, data: Data([1, 2, 3])),
        APDUCommand(instructionCode: 0x2A, data: Data([4, 5]), expectedResponseLength: 256),
        APDUCommand(instructionCode: 0xDB, data: Data(repeating: 0xA5, count: 256)),
        APDUCommand(instructionCode: 0x2A, data: Data(repeating: 0x5A, count: 256), expectedResponseLength: 65_536),
    ]
    for command in commands {
        #expect(try APDUCommand(raw: command.encoded()) == command)
    }

    let extendedCase2 = APDUCommand(instructionCode: 0xCA, expectedResponseLength: 1)
    let encoded = try extendedCase2.encoded(mode: .extended)
    #expect(try APDUCommand(raw: encoded) == extendedCase2)
}

@Test func commandDecoderRejectsMalformedLengths() throws {
    let malformed: [Data] = [
        Data([0x00, 0xCA, 0x00]),
        Data([0x00, 0xCA, 0x00, 0x00, 0x02, 0x01]),
        Data([0x00, 0xCA, 0x00, 0x00, 0x00, 0x00]),
        Data([0x00, 0xDB, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA]),
        Data([0x00, 0x20, 0x00, 0x00, 0x01, 0xAA, 0x01, 0x02, 0x03]),
    ]
    for raw in malformed {
        #expect(throws: APDUError.malformedCommand) {
            _ = try APDUCommand(raw: raw)
        }
    }
}

@Test func lengthCorrectionIsAttemptedOnlyOnce() async throws {
    let transport = ScriptedTransport(responses: [
        Data([0x6C, 0x20]),
        Data([0x6C, 0x20]),
    ])
    let session = APDUSession(transport: transport)
    let response = try await session.execute(
        APDUCommand(instructionCode: 0xCA, expectedResponseLength: 1),
        policy: .readOnly
    )
    #expect(response.status == 0x6C20)
    #expect(await transport.recordedCommands().count == 2)
}

@Test func oversizedCommandDoesNotChainByDefault() async throws {
    let transport = ScriptedTransport(responses: [])
    let session = APDUSession(transport: transport)
    do {
        _ = try await session.execute(
            APDUCommand(instructionCode: 0xDB, data: Data(repeating: 0, count: 600))
        )
        Issue.record("Expected oversized-command rejection")
    } catch let error as APDUError {
        #expect(error == .commandTooLarge)
    }
    #expect(await transport.recordedCommands().isEmpty)
}
