// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AllwIOSApprover",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "AllwIOSApprover", targets: ["AllwIOSApprover"]),
    ],
    targets: [
        .target(name: "AllwIOSApprover"),
        .executableTarget(
            name: "AllwIOSApproverTests",
            dependencies: ["AllwIOSApprover"],
            path: "Tests/AllwIOSApproverTests"
        ),
    ]
)
