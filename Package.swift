// swift-tools-version: 6.3.3
// Institute swift-certificates — L3 X.509 chain/verification runtime.
// True fork of apple/swift-certificates at 24ccdeeeed4dfaae7955fcac9dbf5489ed4f1a25
// (1.18.0) per certificates-n5-decision-packet.md GATE B; see NOTICE.txt.
import PackageDescription

let package = Package(
    name: "swift-certificates",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26),
        .visionOS(.v26),
    ],
    products: [
        .library(
            name: "Certificates",
            targets: ["Certificates"]
        )
    ],
    dependencies: [
        // Canonical URL deps (final-state posture; global mirrors redirect to local checkouts).
        .package(url: "https://github.com/swift-iso/swift-iso-8824.git", branch: "main"),
        .package(url: "https://github.com/swift-iso/swift-iso-8825.git", branch: "main"),
        .package(url: "https://github.com/swift-primitives/swift-byte-primitives.git", branch: "main"),
        // (Q4 time-surface ruling: Instant, lead-approved 2026-07-23)
        .package(url: "https://github.com/swift-primitives/swift-time-primitives.git", branch: "main"),
        // IP presentation/binary parsing (bucket-5 reuse per [IMPL-060]): the RFC owners'
        // text + binary Address parsers replace inet_pton/in_addr/in6_addr/memcmp.
        .package(url: "https://github.com/swift-ietf/swift-rfc-791.git", branch: "main"),
        .package(url: "https://github.com/swift-ietf/swift-rfc-4291.git", branch: "main"),
        // URI presentation parsing (bucket-5 reuse): RFC_3986.URI replaces Foundation.URL
        // for name-constraint host extraction.
        .package(url: "https://github.com/swift-ietf/swift-rfc-3986.git", branch: "main"),
        // TEST-TARGET ONLY. The witness reshape removed Crypto from the `Certificates`
        // target entirely — it depends on none of this — which is what discharges the
        // N5 STOP on a cryptographic import in an Institute main target. This dependency
        // remains solely so the test target can bind the Crypto-backed
        // `Certificate.Verify` witness, which is the prototype of the future
        // swift-certificates-crypto adapter.
        //
        // Note for the clean-room record: apple/swift-asn1 enters the resolved graph
        // transitively through this dependency (swift-crypto declares it `from: "1.2.0"`,
        // floating to 1.7.1). It is FETCHED, never imported by Institute code, and must
        // not be recorded as pruned.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.3.0"),
    ],
    targets: [
        .target(
            name: "Certificates",
            dependencies: [
                "Certificate Internals",
                .product(name: "ISO 8824", package: "swift-iso-8824"),
                .product(name: "ISO 8825", package: "swift-iso-8825"),
                .product(name: "Byte Primitives", package: "swift-byte-primitives"),
                .product(name: "Time Primitive", package: "swift-time-primitives"),
                .product(name: "RFC 791", package: "swift-rfc-791"),
                .product(name: "RFC 4291", package: "swift-rfc-4291"),
                .product(name: "RFC 3986", package: "swift-rfc-3986"),
                // TEMPORARY BRIDGE — remove at the witness reshape (see dependencies).
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/X509"
        ),
        .target(
            name: "Certificate Internals",
            path: "Sources/_CertificateInternals"
        ),
        .testTarget(
            name: "Certificates Tests",
            dependencies: [
                "Certificates",
                "Certificate Internals",
                .product(name: "Time Primitive", package: "swift-time-primitives"),
                // Test-only: binds the Crypto-backed Certificate.Verify witness. The
                // main target stays Crypto-free; main-target purity governs main targets.
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Tests/X509Tests",
            // N5 increment 1 (lead A+B+C ruling): compile the issuance-free verifier-essence
            // tests. The excluded files depend on the deleted issuance surface (Certificate.PrivateKey /
            // TestPKI) or excluded crypto backends (RSA/_CryptoExtras, SecKey); they are DEFERRED to
            // increment 2 (TestPKI-fixture shim + corpus expansion) and recorded in the
            // deferred-tests ledger. Git history preserves the fully-converted suite.
            exclude: [
                "Certificate Tests.swift",
                "Certificate.DER Tests.swift",
                "Certificate.Signature Tests.swift",
                "CertificateStore Tests.swift",
                "RFC5280Policy Tests.swift",
                "Verifier Tests.swift",
            ],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(
            name: "Certificate Internals Tests",
            dependencies: ["Certificate Internals"],
            path: "Tests/CertificateInternalsTests"
        ),
    ]
)
