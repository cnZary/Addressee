import Foundation

public enum APDUError: Error, Equatable, Sendable {
    case invalidExpectedResponseLength
    case commandTooLarge
    case responseTooLarge
    case malformedResponse
    case malformedCommand
    case extendedLengthUnsupported
    case commandChainingRequired
    case commandChainingUnsupported
    case invalidCommandClass
    case continuationLimitExceeded
    case intermediateCommandFailed(status: UInt16)
    case transportClosed
}

public enum APDULengthMode: Sendable {
    case automatic
    case short
    case extended
}

public struct APDUCommand: Equatable, Sendable {
    public var instructionClass: UInt8
    public var instructionCode: UInt8
    public var p1: UInt8
    public var p2: UInt8
    public var data: Data
    public var expectedResponseLength: Int?

    public init(
        instructionClass: UInt8 = 0,
        instructionCode: UInt8,
        p1: UInt8 = 0,
        p2: UInt8 = 0,
        data: Data = Data(),
        expectedResponseLength: Int? = nil
    ) {
        self.instructionClass = instructionClass
        self.instructionCode = instructionCode
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.expectedResponseLength = expectedResponseLength
    }

    public init(raw encoded: Data) throws {
        let bytes = [UInt8](encoded)
        guard bytes.count >= 4 else {
            throw APDUError.malformedCommand
        }
        instructionClass = bytes[0]
        instructionCode = bytes[1]
        p1 = bytes[2]
        p2 = bytes[3]
        guard bytes.count > 4 else {
            data = Data()
            expectedResponseLength = nil
            return
        }

        var index = 4
        if index + 1 == bytes.count {
            data = Data()
            expectedResponseLength = bytes[index] == 0 ? 256 : Int(bytes[index])
            return
        }

        if bytes[index] != 0 {
            let length = Int(bytes[index])
            index += 1
            guard index + length <= bytes.count else {
                throw APDUError.malformedCommand
            }
            data = Data(bytes[index..<(index + length)])
            index += length
            if index == bytes.count {
                expectedResponseLength = nil
                return
            }
            guard index + 1 == bytes.count else {
                throw APDUError.malformedCommand
            }
            expectedResponseLength = bytes[index] == 0 ? 256 : Int(bytes[index])
            return
        }

        guard index + 2 < bytes.count else {
            throw APDUError.malformedCommand
        }
        let length = Int(bytes[index + 1]) << 8 | Int(bytes[index + 2])
        if index + 3 == bytes.count {
            data = Data()
            expectedResponseLength = length == 0 ? 65_536 : length
            return
        }
        guard length > 0 else {
            throw APDUError.malformedCommand
        }
        index += 3
        guard index + length <= bytes.count else {
            throw APDUError.malformedCommand
        }
        data = Data(bytes[index..<(index + length)])
        index += length
        if index == bytes.count {
            expectedResponseLength = nil
            return
        }
        guard index + 2 == bytes.count else {
            throw APDUError.malformedCommand
        }
        let expected = Int(bytes[index]) << 8 | Int(bytes[index + 1])
        expectedResponseLength = expected == 0 ? 65_536 : expected
    }

    public func encoded(mode: APDULengthMode = .automatic) throws -> Data {
        if let expectedResponseLength, !(1...65_536).contains(expectedResponseLength) {
            throw APDUError.invalidExpectedResponseLength
        }
        let extended: Bool
        switch mode {
        case .automatic:
            extended = data.count > 255 || (expectedResponseLength ?? 0) > 256
        case .short:
            extended = false
        case .extended:
            extended = true
        }
        if extended {
            return try extendedEncoding()
        }
        guard data.count <= 255, (expectedResponseLength ?? 0) <= 256 else {
            throw APDUError.commandTooLarge
        }

        var encoded = Data([instructionClass, instructionCode, p1, p2])
        if !data.isEmpty {
            encoded.append(UInt8(data.count))
            encoded.append(data)
        }
        if let expectedResponseLength {
            encoded.append(expectedResponseLength == 256 ? 0 : UInt8(expectedResponseLength))
        }
        return encoded
    }

    private func extendedEncoding() throws -> Data {
        guard data.count <= 65_535 else {
            throw APDUError.commandTooLarge
        }
        var encoded = Data([instructionClass, instructionCode, p1, p2, 0])
        if data.isEmpty {
            guard let expectedResponseLength else {
                throw APDUError.invalidExpectedResponseLength
            }
            appendLength(expectedResponseLength == 65_536 ? 0 : expectedResponseLength, to: &encoded)
            return encoded
        }

        appendLength(data.count, to: &encoded)
        encoded.append(data)
        if let expectedResponseLength {
            appendLength(expectedResponseLength == 65_536 ? 0 : expectedResponseLength, to: &encoded)
        }
        return encoded
    }

    public func chainedSegments(maximumDataLength: Int = 255) throws -> [APDUCommand] {
        guard maximumDataLength > 0, maximumDataLength <= 65_535 else {
            throw APDUError.invalidExpectedResponseLength
        }
        guard instructionClass & 0x10 == 0 else {
            throw APDUError.invalidCommandClass
        }
        guard data.count > maximumDataLength else {
            return [self]
        }
        guard maximumDataLength <= 255 || data.count <= 65_535 else {
            throw APDUError.commandTooLarge
        }

        var segments: [APDUCommand] = []
        var offset = 0
        while offset < data.count {
            let end = min(offset + maximumDataLength, data.count)
            var segment = self
            segment.data = data.subdata(in: offset..<end)
            let isLast = end == data.count
            segment.instructionClass = isLast ? instructionClass : instructionClass | 0x10
            if !isLast {
                segment.expectedResponseLength = nil
            }
            segments.append(segment)
            offset = end
        }
        return segments
    }

    private func appendLength(_ length: Int, to data: inout Data) {
        data.append(UInt8((length >> 8) & 0xFF))
        data.append(UInt8(length & 0xFF))
    }
}

public struct APDUResponse: Equatable, Sendable {
    public let data: Data
    public let status: UInt16

    public init(data: Data = Data(), status: UInt16) {
        self.data = data
        self.status = status
    }

    public init(raw: Data) throws {
        guard raw.count >= 2 else {
            throw APDUError.malformedResponse
        }
        data = raw.dropLast(2)
        status = UInt16(raw[raw.count - 2]) << 8 | UInt16(raw[raw.count - 1])
    }

    public var isSuccess: Bool { status == 0x9000 }
    public var sw1: UInt8 { UInt8(status >> 8) }
    public var sw2: UInt8 { UInt8(status & 0xFF) }

    public var continuationLength: Int? {
        guard sw1 == 0x61 else { return nil }
        return sw2 == 0 ? 256 : Int(sw2)
    }

    public var correctedLength: Int? {
        guard sw1 == 0x6C else { return nil }
        return sw2 == 0 ? 256 : Int(sw2)
    }
}

public struct APDUTransportCapabilities: Equatable, Sendable {
    public var supportsExtendedLength: Bool
    public var maximumCommandDataLength: Int
    public var maximumResponseLength: Int
    public var maximumContinuationRounds: Int

    public init(
        supportsExtendedLength: Bool,
        maximumCommandDataLength: Int,
        maximumResponseLength: Int,
        maximumContinuationRounds: Int = 32
    ) {
        self.supportsExtendedLength = supportsExtendedLength
        self.maximumCommandDataLength = maximumCommandDataLength
        self.maximumResponseLength = maximumResponseLength
        self.maximumContinuationRounds = maximumContinuationRounds
    }

    public static let shortOnly = APDUTransportCapabilities(
        supportsExtendedLength: false,
        maximumCommandDataLength: 255,
        maximumResponseLength: 65_536
    )
}

public protocol APDUTransport: Sendable {
    var capabilities: APDUTransportCapabilities { get async }
    func transmit(_ command: Data) async throws -> Data
    func close() async throws
}
