//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
import ISO_8824
import ISO_8825
import Time_Primitive
@_spi(Testing) @testable import Certificates
@preconcurrency import Crypto

extension CertificateStore {
    @Suite struct Test {
        @Suite struct Unit {}

        @Suite struct `Edge Case` {
            // TX-N1E: `CertificateStore.loadTrustRoots(at:)` (filesystem PEM-bundle
            // loading) does not exist in this fork's main target — it is a distinct
            // capability from the chain/hostname/time-validation surface this transaction
            // owns (Certificate.Verifier, Certificate.Chain, Certificate.Hostname). Out of
            // TestPKI-shim scope; tracked as a follow-up API-completeness gap, not
            // silently dropped.
            #if false
            @Test func `loading fails gracefully if files do not exist`() {
                let searchPaths = [
                    "/some/path/that/does/not/exist/1",
                    "/some/path/that/does/not/exist/2",
                ]
                do {
                    _ = try CertificateStore.loadTrustRoots(at: searchPaths)
                    Issue.record("expected throw")
                } catch {
                    guard let error = error as? Certificate.Error else {
                        Issue.record("could not cast \(error) to \(Certificate.Error.self)")
                        return
                    }
                    // -> trust-witness batch: system-trust error surface pending
                    #expect(error.code == .failedToLoadSystemTrustStore)
                }
            }

            @Test func `loading fails gracefully if first file does not exist`() throws {
                let caCertificatesURL = try #require(Bundle.module.url(forResource: "ca-certificates", withExtension: "crt"))
                let searchPaths = [
                    "/some/path/that/does/not/exist/1",
                    caCertificatesURL.path,
                ]
                let log = DiagnosticsLog()
                let store = try CertificateStore.loadTrustRoots(at: searchPaths)
                #expect(log == [])
                #expect(store.values.lazy.map(\.count).reduce(0, +) == 137)
            }
            #endif
        }

        @Suite struct Integration {
            // TX-N1E: `CertificateStore.systemTrustRoots` does not exist in this fork's
            // main target — same class of out-of-scope gap as `loadTrustRoots` above.
            #if false
            #if os(Linux)
            @Test func `loading default trust roots`() async throws {
                let log = DiagnosticsLog()
                let store = await CertificateStore.systemTrustRoots.resolve(diagnosticsCallback: log.append(_:))
                #expect(store.totalCertificateCount >= 100)
                #expect(log == [])
            }
            #else
            @Test func `loading default trust roots`() async throws {
                let log = DiagnosticsLog()

                let store = await CertificateStore.systemTrustRoots.resolve(diagnosticsCallback: log.append(_:))
                #expect(store.totalCertificateCount == 0)

                #expect(log.count == 1)
            }
            #endif
            #endif

            static func normalizeDistinguishedName(_ dn: DistinguishedName) -> DistinguishedName {
                DistinguishedName(
                    dn.map {
                        RelativeDistinguishedName(
                            $0.map {
                                guard let str = String($0.value) else {
                                    return $0
                                }
                                return RelativeDistinguishedName.Attribute(
                                    type: $0.type,
                                    value: RelativeDistinguishedName.Attribute.Value(utf8String: str)
                                )
                            }
                        )
                    }
                )
            }

            struct CertStore: CustomCertificateStore {
                subscript(subject: Certificates.DistinguishedName) -> [Certificates.Certificate]? {
                    get async {
                        self.trustRoots[normalizeDistinguishedName(subject)]
                    }
                }

                func contains(_ certificate: Certificates.Certificate) async -> Bool {
                    self.trustRoots[normalizeDistinguishedName(certificate.subject)]?.contains(certificate) == true
                }

                mutating func append(contentsOf certificates: some Sequence<Certificates.Certificate>) {
                    for certificate in certificates {
                        self.trustRoots[normalizeDistinguishedName(certificate.subject), default: []].append(certificate)
                    }
                }

                @usableFromInline
                var trustRoots: [DistinguishedName: [Certificate]]

                @inlinable
                public init(_ certificates: some Sequence<Certificate>) {
                    self.trustRoots = Dictionary(grouping: certificates) {
                        normalizeDistinguishedName($0.subject)
                    }
                }
            }

            // TX-N1E: adapted (not verbatim) from the deleted issuance-surface `Certificate(
            // …issuerPrivateKey:)` initializer to the test-target DER-level shim
            // `Certificate.Issuance.issue`, and from `Date` to `Instant` per the Q4
            // time-surface ruling — same two changes `TestPKI.swift` documents. A fixed
            // instant (matching `TestPKI.startDate`) replaces upstream's wall-clock
            // `Date()`, which is more deterministic and not less correct for this test.
            private static let referenceTime = TestPKI.startDate

            private static let ca1PrivateKey = P384.Signing.PrivateKey()
            private static let ca1: Certificate = {
                // Force CA to encode using printableString:
                let ca1Name = try! DistinguishedName([
                    RelativeDistinguishedName([
                        RelativeDistinguishedName.Attribute(
                            type: .RDNAttributeType.countryName,
                            value: RelativeDistinguishedName.Attribute.Value(printableString: "US")
                        )
                    ]),
                    RelativeDistinguishedName([
                        RelativeDistinguishedName.Attribute(
                            type: .RDNAttributeType.organizationName,
                            value: RelativeDistinguishedName.Attribute.Value(printableString: "Apple")
                        )
                    ]),
                    RelativeDistinguishedName([
                        RelativeDistinguishedName.Attribute(
                            type: .RDNAttributeType.commonName,
                            value: RelativeDistinguishedName.Attribute.Value(printableString: "Swift Certificate Test CA 1")
                        )
                    ]),
                ])
                return try! Certificate.Issuance.issue(
                    version: .v3,
                    serialNumber: TestPKI.nextSerialNumber(),
                    publicKey: .init(ca1PrivateKey.publicKey),
                    notValidBefore: referenceTime - .seconds(365 * 86400),
                    notValidAfter: referenceTime + .seconds(3650 * 86400),
                    issuer: ca1Name,
                    subject: ca1Name,
                    signatureAlgorithm: .ecdsaWithSHA384,
                    extensions: try! Certificate.Extensions {
                        Critical(
                            BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                        )
                        KeyUsage(keyCertSign: true)
                        SubjectKeyIdentifier(
                            keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: ca1PrivateKey.publicKey.derRepresentation))
                        )
                    },
                    issuerPrivateKey: .init(ca1PrivateKey)
                )
            }()

            private static let leafPrivateKey = P256.Signing.PrivateKey()
            private static let leafCert: Certificate = {
                try! Certificate.Issuance.issue(
                    version: .v3,
                    serialNumber: TestPKI.nextSerialNumber(),
                    publicKey: .init(leafPrivateKey.publicKey),
                    notValidBefore: referenceTime - .seconds(365 * 86400),
                    notValidAfter: referenceTime + .seconds(365 * 86400),
                    // Force leaf to encode using utf8String:
                    issuer: DistinguishedName([
                        RelativeDistinguishedName([
                            RelativeDistinguishedName.Attribute(
                                type: .RDNAttributeType.countryName,
                                value: RelativeDistinguishedName.Attribute.Value(utf8String: "US")
                            )
                        ]),
                        RelativeDistinguishedName([
                            RelativeDistinguishedName.Attribute(
                                type: .RDNAttributeType.organizationName,
                                value: RelativeDistinguishedName.Attribute.Value(utf8String: "Apple")
                            )
                        ]),
                        RelativeDistinguishedName([
                            RelativeDistinguishedName.Attribute(
                                type: .RDNAttributeType.commonName,
                                value: RelativeDistinguishedName.Attribute.Value(utf8String: "Swift Certificate Test CA 1")
                            )
                        ]),
                    ]),
                    subject: try! DistinguishedName {
                        CountryName("US")
                        OrganizationName("Apple")
                        CommonName("localhost")
                    },
                    signatureAlgorithm: .ecdsaWithSHA256,
                    extensions: try! Certificate.Extensions {
                        Critical(
                            BasicConstraints.notCertificateAuthority
                        )
                        KeyUsage(keyCertSign: true)
                        AuthorityKeyIdentifier(keyIdentifier: try! ca1.extensions.subjectKeyIdentifier!.keyIdentifier)
                    },
                    issuerPrivateKey: .init(ca1PrivateKey)
                )
            }()

            @Test func `custom certificate store`() async throws {
                // MUST fail due to encoding of DN mismatch:
                var concreteStore = CertificateStore()
                concreteStore.append(Self.ca1)

                var concreteVerifier = Verifier(rootCertificates: concreteStore, verify: .crypto) {
                    RFC5280Policy(validationTime: Self.referenceTime)
                }
                let concreteResult = await concreteVerifier.validate(
                    leaf: Self.leafCert,
                    intermediates: CertificateStore()
                )

                guard case .couldNotValidate = concreteResult else {
                    Issue.record("Incorrectly validated: \(concreteResult)")
                    return
                }

                // The custom CertStore should normalize the DN so it no longer fails:
                var customStore = CertificateStore(custom: CertStore([]))
                customStore.append(Self.ca1)

                var customVerifier = Verifier(rootCertificates: customStore, verify: .crypto) {
                    RFC5280Policy(validationTime: Self.referenceTime)
                }
                let customResult = await customVerifier.validate(
                    leaf: Self.leafCert,
                    intermediates: CertificateStore()
                )

                guard case .validCertificate(_) = customResult else {
                    Issue.record("Failed to validate: \(customResult)")
                    return
                }
            }
        }
    }
}

// TX-N1E: dead without the disabled `systemTrustRoots`-dependent tests above; kept
// compiled out rather than deleted so it lands back the moment that capability does.
#if false
extension CertificateStore.Resolved {
    var totalCertificateCount: Int {
        if case .concrete(let inner) = self {
            inner.systemTrustRoots.values.lazy.map(\.count).reduce(0, +)
                + inner.additionalTrustRoots.values.lazy.map(\.count).reduce(0, +)
        } else {
            fatalError("Expected concrete certificate store!")
        }
    }
}
#endif
