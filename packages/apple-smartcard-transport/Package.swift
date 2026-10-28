// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AppleSmartCardTransport",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "AppleSmartCardTransport", targets: ["AppleSmartCardTransport"])
    ],
    targets: [
        .target(name: "AppleSmartCardTransport"),
        .testTarget(
            name: "AppleSmartCardTransportTests",
            dependencies: ["AppleSmartCardTransport"]
        ),
    ]
)
