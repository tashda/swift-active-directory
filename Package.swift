// swift-tools-version:6.2
import PackageDescription

let package = Package(
    name: "ad-directory",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "ADDirectory",
            targets: ["ADDirectory"]),
    ],
    targets: [
        .target(
            name: "CLDAP",
            path: "Sources/CLDAP",
            publicHeadersPath: "include",
            cSettings: [
                .define("LDAP_DEPRECATED", to: "1"),
                .unsafeFlags([
                    "-Wno-deprecated-declarations",
                ]),
            ],
            linkerSettings: [
                .linkedLibrary("ldap"),
                .linkedLibrary("lber"),
                .linkedLibrary("resolv"),
            ]
        ),
        .target(
            name: "ADDirectory",
            dependencies: [
                "CLDAP",
            ],
            path: "Sources/ADDirectory",
            linkerSettings: [
                .linkedFramework("GSS"),
            ]
        ),
        .testTarget(
            name: "ADDirectoryTests",
            dependencies: [
                "ADDirectory",
            ],
            path: "Tests/ADDirectoryTests"
        ),
    ]
)
