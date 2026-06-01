// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "NeonCoreMacApp",
    defaultLocalization: "en-AU",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .executable(name: "NeonCoreMacApp", targets: ["NeonCoreMacApp"])
    ],
    targets: [
        .executableTarget(
            name: "NeonCoreMacApp",
            path: "NeonCoreMacApp",
            resources: [
                .process("Localizable.xcstrings"),
                .process("Fonts")
            ]
        )
    ]
)
