import Foundation
import SwiftUI

enum MessageInputSource: String, CaseIterable, Identifiable, Sendable {
    case text
    case file

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .text: "message.input.text"
        case .file: "message.input.file"
        }
    }
}

enum SignatureFormat: String, CaseIterable, Identifiable, Sendable {
    case detached
    case attached
    case cleartext

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .detached: "signature.format.detached"
        case .attached: "signature.format.attached"
        case .cleartext: "signature.format.cleartext"
        }
    }
}

enum EncryptionProfile: String, CaseIterable, Identifiable, Sendable {
    case modern
    case compatibility

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .modern: "encryption.config.modern"
        case .compatibility: "encryption.config.compatibility"
        }
    }

    var config: EncryptionConfigFfi {
        switch self {
        case .modern: .seipdV2(cipher: .aes256, mode: .ocb)
        case .compatibility: .seipdV1(cipher: .aes256)
        }
    }
}

struct MessageOutput {
    let url: URL
    let preview: String?
    let metadata: SignatureMetadataFfi?
    let byteCount: Int?

    init(
        url: URL,
        preview: String? = nil,
        metadata: SignatureMetadataFfi? = nil,
        byteCount: Int? = nil
    ) {
        self.url = url
        self.preview = preview
        self.metadata = metadata
        self.byteCount = byteCount
    }
}

enum MessageFiles {
    static func makeOutputURL(named name: String) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("Addressee-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return directory.appendingPathComponent(name, isDirectory: false)
    }

    static func write(_ data: Data, named name: String) throws -> URL {
        let url = try makeOutputURL(named: name)
        try data.write(to: url, options: .atomic)
        return url
    }

    static func signatureFileName(
        source: String,
        format: SignatureFormat,
        armored: Bool
    ) -> String {
        switch format {
        case .detached:
            source + (armored ? ".asc" : ".sig")
        case .attached:
            source + (armored ? ".asc" : ".pgp")
        case .cleartext:
            source + ".asc"
        }
    }

    static func encryptedFileName(source: String, armored: Bool) -> String {
        source + (armored ? ".asc" : ".pgp")
    }

    static func verifiedFileName(source: String) -> String {
        plaintextFileName(source: source, fallbackSuffix: ".verified")
    }

    static func decryptedFileName(source: String) -> String {
        plaintextFileName(source: source, fallbackSuffix: ".decrypted")
    }

    private static func plaintextFileName(source: String, fallbackSuffix: String) -> String {
        let pathExtension = (source as NSString).pathExtension.lowercased()
        if ["pgp", "gpg", "asc"].contains(pathExtension) {
            let stripped = (source as NSString).deletingPathExtension
            return stripped.isEmpty ? "plaintext.bin" : stripped
        }
        return source + fallbackSuffix
    }
}

extension String {
    var openPgpCanonicalLineEndings: String {
        replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .replacingOccurrences(of: "\n", with: "\r\n")
    }
}

@MainActor
func withSecurityScopedResources<T>(
    _ urls: [URL],
    operation: @MainActor () async throws -> T
) async rethrows -> T {
    var accessed: [URL] = []
    for url in urls where url.startAccessingSecurityScopedResource() {
        accessed.append(url)
    }
    defer {
        for url in accessed.reversed() {
            url.stopAccessingSecurityScopedResource()
        }
    }
    return try await operation()
}
