// swift-tools-version: 5.9
//
// machoscope — inspect a Mach-O binary's hardening posture.
//
// Two targets, same split as any tool that wants to be usable as a library:
//   1. `MachOScopeCore` — parsing and checks, importable from other tools.
//   2. `machoscope` — the CLI, which is only argument parsing and rendering.

import PackageDescription

let package = Package(
    name: "machoscope",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "machoscope", targets: ["machoscope"]),
        .library(name: "MachOScopeCore", targets: ["MachOScopeCore"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0")
    ],
    targets: [
        .executableTarget(
            name: "machoscope",
            dependencies: [
                "MachOScopeCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ],
            path: "Sources/machoscope"
        ),
        .target(name: "MachOScopeCore", path: "Sources/MachOScopeCore"),
        .testTarget(
            name: "MachOScopeCoreTests",
            dependencies: ["MachOScopeCore"],
            path: "Tests/MachOScopeCoreTests"
        )
    ]
)
