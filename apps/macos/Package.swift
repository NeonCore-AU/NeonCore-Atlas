// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AtlasMacApp",
    defaultLocalization: "en-AU",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .executable(name: "AtlasMacApp", targets: ["AtlasMacApp"])
    ],
    targets: [
        .executableTarget(
            name: "AtlasMacApp",
            path: "AtlasMacApp",
            resources: [
                .process("Localizable.xcstrings")
            ]
        )
    ]
)
