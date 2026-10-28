import Foundation

enum FileInputError: Error {
    case tooLarge
    case unreadable
}

enum FileInput {
    static func readData(from url: URL, limit: Int = 32 * 1024 * 1024) async throws -> Data {
        try await Task.detached(priority: .userInitiated) {
            let accessing = url.startAccessingSecurityScopedResource()
            defer {
                if accessing {
                    url.stopAccessingSecurityScopedResource()
                }
            }
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            var output = Data()
            while true {
                let chunk = try handle.read(upToCount: 65_536) ?? Data()
                if chunk.isEmpty {
                    break
                }
                output.append(chunk)
                if output.count > limit {
                    throw FileInputError.tooLarge
                }
            }
            return output
        }.value
    }
}
