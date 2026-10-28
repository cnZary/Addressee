import Foundation

public struct APDUPolicy: Sendable {
    public var allowLengthCorrection: Bool
    public var allowCommandChaining: Bool
    public var maximumChainedDataLength: Int

    public init(
        allowLengthCorrection: Bool = false,
        allowCommandChaining: Bool = false,
        maximumChainedDataLength: Int = 255
    ) {
        self.allowLengthCorrection = allowLengthCorrection
        self.allowCommandChaining = allowCommandChaining
        self.maximumChainedDataLength = maximumChainedDataLength
    }

    public static let readOnly = APDUPolicy(allowLengthCorrection: true)
}

public actor APDUSession {
    private let transport: any APDUTransport
    private var closed = false

    public init(transport: any APDUTransport) {
        self.transport = transport
    }

    public func execute(
        _ command: APDUCommand,
        policy: APDUPolicy = APDUPolicy()
    ) async throws -> APDUResponse {
        try ensureOpen()
        let capabilities = await transport.capabilities
        guard command.data.count <= capabilities.maximumCommandDataLength else {
            if policy.allowCommandChaining {
                return try await executeChained(command, policy: policy, capabilities: capabilities)
            }
            throw APDUError.commandTooLarge
        }
        if !capabilities.supportsExtendedLength,
           command.data.count > 255 || (command.expectedResponseLength ?? 0) > 256 {
            throw APDUError.extendedLengthUnsupported
        }
        return try await executeSingle(
            command,
            allowLengthCorrection: policy.allowLengthCorrection,
            capabilities: capabilities
        )
    }

    public func close() async throws {
        guard !closed else { return }
        closed = true
        try await transport.close()
    }

    private func executeChained(
        _ command: APDUCommand,
        policy: APDUPolicy,
        capabilities: APDUTransportCapabilities
    ) async throws -> APDUResponse {
        guard policy.allowCommandChaining else {
            throw APDUError.commandChainingRequired
        }
        let segments = try command.chainedSegments(
            maximumDataLength: min(policy.maximumChainedDataLength, capabilities.maximumCommandDataLength)
        )
        guard segments.count > 1 else {
            throw APDUError.commandChainingUnsupported
        }
        for segment in segments.dropLast() {
            try ensureOpen()
            let encoded = try segment.encoded(mode: .short)
            let response = try APDUResponse(raw: await transport.transmit(encoded))
            guard response.isSuccess else {
                throw APDUError.intermediateCommandFailed(status: response.status)
            }
        }
        return try await executeSingle(
            segments[segments.count - 1],
            allowLengthCorrection: false,
            capabilities: capabilities
        )
    }

    private func executeSingle(
        _ command: APDUCommand,
        allowLengthCorrection: Bool,
        capabilities: APDUTransportCapabilities
    ) async throws -> APDUResponse {
        var command = command
        var correctionUsed = false
        var aggregate = Data()
        var continuationRounds = 0

        while true {
            try ensureOpen()
            try Task.checkCancellation()
            let extendedRequired = command.data.count > 255 || (command.expectedResponseLength ?? 0) > 256
            if extendedRequired && !capabilities.supportsExtendedLength {
                throw APDUError.extendedLengthUnsupported
            }
            let encoded = try command.encoded()
            let raw = try await transport.transmit(encoded)
            let response = try APDUResponse(raw: raw)

            if let correctedLength = response.correctedLength,
               allowLengthCorrection,
               !correctionUsed,
               command.expectedResponseLength != nil {
                correctionUsed = true
                command.expectedResponseLength = correctedLength
                continue
            }

            guard aggregate.count + response.data.count <= capabilities.maximumResponseLength else {
                throw APDUError.responseTooLarge
            }
            aggregate.append(response.data)
            guard let continuationLength = response.continuationLength else {
                return APDUResponse(data: aggregate, status: response.status)
            }
            continuationRounds += 1
            guard continuationRounds <= capabilities.maximumContinuationRounds else {
                throw APDUError.continuationLimitExceeded
            }
            command = APDUCommand(
                instructionCode: 0xC0,
                expectedResponseLength: continuationLength
            )
        }
    }

    private func ensureOpen() throws {
        if closed {
            throw APDUError.transportClosed
        }
    }
}
