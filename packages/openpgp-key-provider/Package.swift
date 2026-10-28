// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "OpenPGPKeyProvider",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "OpenPGPKeyProvider", targets: ["OpenPGPKeyProvider"])
    ],
    dependencies: [
        .package(path: "../openpgp-apple-se"),
        .package(path: "../apple-smartcard-transport"),
    ],
    targets: [
        .target(
            name: "OpenPGPKeyProvider",
            dependencies: [
                .product(name: "OpenPGPAppleSecureEnclave", package: "openpgp-apple-se"),
                .product(name: "AppleSmartCardTransport", package: "apple-smartcard-transport"),
            ]
        ),
        .testTarget(
            name: "OpenPGPKeyProviderTests",
            dependencies: ["OpenPGPKeyProvider"]
        ),
    ]
)
