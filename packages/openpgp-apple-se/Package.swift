// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "OpenPGPAppleSecureEnclave",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "OpenPGPAppleSecureEnclave", targets: ["OpenPGPAppleSecureEnclave"])
    ],
    targets: [
        .target(name: "OpenPGPAppleSecureEnclave"),
        .testTarget(
            name: "OpenPGPAppleSecureEnclaveTests",
            dependencies: ["OpenPGPAppleSecureEnclave"]
        ),
    ]
)
