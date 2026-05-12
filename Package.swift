// swift-tools-version:6.2
import PackageDescription

let package = Package(
    name: "swift-active-directory",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "ActiveDirectory",
            targets: ["ActiveDirectory"]),
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
                .linkedFramework("GSS"),
                .linkedFramework("Kerberos"),
            ]
        ),
        .target(
            name: "ActiveDirectory",
            dependencies: [
                "CLDAP",
            ],
            path: "Sources/ActiveDirectory"
        ),
        .testTarget(
            name: "ActiveDirectoryTests",
            dependencies: [
                "ActiveDirectory",
            ],
            path: "Tests/ActiveDirectoryTests"
        ),
    ]
)
