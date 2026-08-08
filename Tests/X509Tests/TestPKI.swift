//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@preconcurrency import Crypto
import Synchronization
import Time_Primitive

// ⛔ TEST TARGET ONLY. DO NOT LIFT THIS INTO A MAIN TARGET.
//
// TX-N1E component 6: the shared certificate fixture generator the RFC5280Policy,
// Verifier and CertificateStore suites were written against. It is an adaptation, not a
// verbatim lift, of the `private enum TestPKI` at the foot of upstream's
// `Tests/X509Tests/RFC5280PolicyTests.swift` @ fork-point 24ccdee — adapted rather than
// copied because upstream buries it `private` inside one test file, while this fork split
// that file into three suites that all construct certificates through it. Every semantic
// choice below (validity windows, key algorithms, extension shapes) is preserved verbatim;
// only the construction path changed, in the two places this fork's issuance surface
// differs from upstream's:
//
//   - `Certificate(…issuerPrivateKey:)` (deleted with `Certificate.PrivateKey`) becomes
//     `Certificate.Issuance.issue(…issuerPrivateKey:)`, this fork's DER-level test-target
//     issuance shim (see `Issuance.swift`).
//   - `Date` becomes `Instant`, per the Q4 time-surface ruling. `startDate` is a fixed
//     instant rather than `Date()` — deliberately, matching the fixed-instant convention
//     already established by `Issuance Tests.swift` and `PolicyBuilder Tests.swift`, and
//     preferable to upstream's wall-clock `Date()` because it makes validity-window
//     arithmetic reproducible across runs.
//
// Depends only on the model (`@testable import Certificates`), the DER-level issuance shim
// (`Certificate.Issuance`), the DSL shims (`ExtensionsBuilder.swift`, `DNBuilder.swift` and
// its siblings), and the `Certificate.PublicKey` Crypto-typed constructors
// (`PublicKey+Crypto.swift`) — all already test-target-only for the same reason. It
// reinstates nothing in the main target.
@testable import Certificates

enum TestPKI {
    /// A fixed instant rather than `Date()`/"now" — see the file-level note.
    static let startDate = Instant(secondsSinceUnixEpoch: 1_767_225_600)

    /// Monotonic serial numbers. The main-target model has no random-serial generator
    /// (that generator was issuance-side and left with `Certificate.PrivateKey`), and
    /// these fixtures need no more than distinctness.
    private static let serialCounter = Mutex<UInt64>(1)
    static func nextSerialNumber() -> Certificate.SerialNumber {
        Certificate.SerialNumber(serialCounter.withLock { count -> UInt64 in
            defer { count += 1 }
            return count
        })
    }

    static let unconstrainedCAPrivateKey = P384.Signing.PrivateKey()
    static let unconstrainedCAName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test CA 1")
    }
    static let unconstrainedCA: Certificate = {
        try! Certificate.Issuance.issue(
            serialNumber: nextSerialNumber(),
            publicKey: .init(unconstrainedCAPrivateKey.publicKey),
            notValidBefore: startDate - .seconds(3650 * 86400),
            notValidAfter: startDate + .seconds(3650 * 86400),
            issuer: unconstrainedCAName,
            subject: unconstrainedCAName,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
            },
            issuerPrivateKey: .init(unconstrainedCAPrivateKey)
        )
    }()
    static func issueCA(version: Certificate.Version = .v3, extensions: Certificate.Extensions) -> Certificate {
        try! Certificate.Issuance.issue(
            version: version,
            serialNumber: nextSerialNumber(),
            publicKey: .init(unconstrainedCAPrivateKey.publicKey),
            notValidBefore: startDate - .seconds(3650 * 86400),
            notValidAfter: startDate + .seconds(3650 * 86400),
            issuer: unconstrainedCAName,
            subject: unconstrainedCAName,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: extensions,
            issuerPrivateKey: .init(unconstrainedCAPrivateKey)
        )
    }

    static let unconstrainedIntermediateKey = P256.Signing.PrivateKey()
    static let unconstrainedIntermediateName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test Intermediate 1")
    }
    static let unconstrainedIntermediate: Certificate = {
        issueIntermediate(
            name: unconstrainedIntermediateName,
            key: .init(unconstrainedIntermediateKey.publicKey),
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
            },
            issuer: .unconstrainedRoot
        )
    }()
    static func issueIntermediate(
        name: DistinguishedName,
        version: Certificate.Version = .v3,
        key: Certificate.PublicKey,
        extensions: Certificate.Extensions,
        issuer: Issuer
    ) -> Certificate {
        try! Certificate.Issuance.issue(
            version: version,
            serialNumber: nextSerialNumber(),
            publicKey: key,
            notValidBefore: startDate - .seconds(365 * 86400),
            notValidAfter: startDate + .seconds(365 * 86400),
            issuer: issuer.name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: issuer.key
        )
    }

    static let secondLevelIntermediateKey = P256.Signing.PrivateKey()
    static let secondLevelIntermediateName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test Intermediate 2")
    }

    struct Issuer {
        static let unconstrainedRoot = Self(
            name: TestPKI.unconstrainedCAName,
            key: .init(TestPKI.unconstrainedCAPrivateKey)
        )
        static let unconstrainedIntermediate = Self(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey)
        )
        static let secondLevelIntermediate = Self(
            name: TestPKI.secondLevelIntermediateName,
            key: .init(TestPKI.secondLevelIntermediateKey)
        )

        var name: DistinguishedName
        var key: Certificate.Issuance.Key
    }

    static func issueLeaf(
        version: Certificate.Version = .v3,
        commonName: String = "Leaf",
        notValidBefore: Instant = Self.startDate,
        notValidAfter: Instant = Self.startDate + .seconds(365 * 86400),
        issuer: Issuer,
        subjectAlternativeNames: [GeneralName]? = nil,
        customExtensions: Certificate.Extensions? = nil
    ) -> Certificate {
        let leafKey = P256.Signing.PrivateKey()
        let name = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName(commonName)
        }

        let extensions: Certificate.Extensions
        if let customExtensions {
            extensions = customExtensions
        } else {
            extensions = try! Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                if let subjectAlternativeNames {
                    SubjectAlternativeNames(subjectAlternativeNames)
                }
            }
        }

        return try! Certificate.Issuance.issue(
            version: version,
            serialNumber: nextSerialNumber(),
            publicKey: .init(leafKey.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: issuer.name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: issuer.key
        )
    }

    static func issueSelfSignedCert(
        commonName: String = "Leaf",
        version: Certificate.Version = .v3,
        basicConstraints: BasicConstraints = .notCertificateAuthority,
        customExtensions: Certificate.Extensions? = nil
    ) -> Certificate {
        let selfSignedKey = P256.Signing.PrivateKey()
        let name = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName(commonName)
        }

        let extensions: Certificate.Extensions
        if let customExtensions {
            extensions = customExtensions
        } else if version == .v3 {
            extensions = try! Certificate.Extensions {
                Critical(
                    basicConstraints
                )
            }
        } else {
            extensions = .init()
        }

        return try! Certificate.Issuance.issue(
            version: version,
            serialNumber: nextSerialNumber(),
            publicKey: .init(selfSignedKey.publicKey),
            notValidBefore: Self.startDate,
            notValidAfter: Self.startDate + .seconds(365 * 86400),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.Issuance.Key(selfSignedKey)
        )
    }
}
