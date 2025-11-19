// swift-tools-version:6.0

import PackageDescription

extension String {
    static let rfc7617: Self = "RFC_7617"
}

extension Target.Dependency {
    static var rfc7617: Self { .target(name: .rfc7617) }
}

let package = Package(
    name: "swift-rfc-7617",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11)
    ],
    products: [
        .library(name: .rfc7617, targets: [.rfc7617]),
    ],
    dependencies: [
        // Add RFC dependencies here as needed
        // .package(url: "https://github.com/swift-standards/swift-rfc-1123.git", branch: "main"),
    ],
    targets: [
        .target(
            name: .rfc7617,
            dependencies: [
                // Add target dependencies here
            ]
        ),
        .testTarget(
            name: .rfc7617.tests,
            dependencies: [
                .rfc7617
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

extension String { var tests: Self { self + " Tests" } }
