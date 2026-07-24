//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCertificates project authors
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
@_spi(Testing) import Certificates

// These certificates are bound from the frozen DER corpus rather than issued in-test
// (issuance is an excluded surface in slice 1). Each was frozen to match the original
// in-test certificate's subject DN and SAN contents exactly, so every assertion below
// is preserved verbatim — see Fixtures/MANIFEST.md for the per-fixture provenance and
// the rationale for freezing rather than remapping onto the pre-existing leaves.
//
// This suite installs each certificate as both the trust anchor and the leaf and runs
// only ServerIdentityPolicy, so chain construction, expiry and signature validity are
// not exercised; only the subject DN and SAN contents are load-bearing.

/// This cert contains the following SAN fields:
/// DNS:*.WILDCARD.EXAMPLE.com - A straightforward wildcard, should be accepted
/// DNS:FO*.EXAMPLE.com - A suffix wildcard, should be accepted
/// DNS:*AR.EXAMPLE.com - A prefix wildcard, should be accepted
/// DNS:B*Z.EXAMPLE.com - An infix wildcard
/// DNS:TRAILING.PERIOD.EXAMPLE.com. - A domain with a trailing period, should match
/// DNS:XN--STRAE-OQA.UNICODE.EXAMPLE.com. - An IDN A-label, should match.
/// DNS:XN--X*-GIA.UNICODE.EXAMPLE.com. - An IDN A-label with a wildcard, invalid.
/// DNS:WEIRDWILDCARD.*.EXAMPLE.com. - A wildcard not in the leftmost label, invalid.
/// DNS:*.*.DOUBLE.EXAMPLE.com. - Two wildcards, invalid.
/// DNS:*.XN--STRAE-OQA.EXAMPLE.com. - A wildcard followed by a new IDN A-label, this is fine.
/// A SAN with a null in it, should be ignored.
///
/// This also contains a commonName of httpbin.org.
private let weirdoSANCert = try! Fixture.certificate("leaf-weirdo-sans")

private let multiSANCert = try! Fixture.certificate("leaf-multi-san-hosts")
private let multiCNCert = try! Fixture.certificate("leaf-multi-cn")
private let noCNCert = try! Fixture.certificate("leaf-no-cn")
private let unicodeCNCert = try! Fixture.certificate("leaf-unicode-cn")

extension ServerIdentityPolicy {
    @Suite
    struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
        // All tests in this suite are deprecated because they use deprecated API.
        @Suite struct Deprecated {}
    }
}

extension ServerIdentityPolicy.Test.Unit {
    @Test
    func `can validate hostname in first san`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `can validate hostname in second san`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "example.com", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `lowercases hostname for san`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "LoCaLhOsT", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `rejects incorrect hostname`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "httpbin.org", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `accepts ipv4 address`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "192.168.0.1")
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `accepts ipv6 address`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "2001:db8::1")
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `rejects incorrect ipv4 address`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "192.168.0.2")
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `rejects incorrect ipv6 address`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "2001:db8::2")
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `falls back to common name`() async throws {
        let roots = CertificateStore([multiCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: multiCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `lowercases for common name`() async throws {
        let roots = CertificateStore([multiCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "LoCaLhOsT", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: multiCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `handles missing common name`() async throws {
        let roots = CertificateStore([noCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: noCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `does not fall back to cn with sans`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "httpbin.org", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }
}

extension ServerIdentityPolicy.Test.`Edge Case` {
    @Test
    func `ignores trailing period`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "example.com.", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `accepts wildcards`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "this.wildcard.example.com", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `accepts suffix wildcard`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.example.com", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `accepts prefix wildcard`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "bar.example.com", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `accepts infix wildcard`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "baz.example.com", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `ignores trailing period in cert`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "trailing.period.example.com", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `rejects encoded idna label`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "straße.unicode.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `matches unencoded idna label`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--strae-oqa.unicode.example.com", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `does not match idna label with wildcard`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--xx-gia.unicode.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `does not match non leftmost wildcards`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "weirdwildcard.nomatch.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `does not match multiple wildcards`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "one.two.double.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `rejects wildcard before unencoded idna label`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.straße.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `matches wildcard before encoded idna label`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.xn--strae-oqa.example.com", serverIP: nil)
            }
        )
        await assertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `does not match san with embedded null`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "nul\u{0000}l.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `rejects unicode common name with unencoded idna label`() async throws {
        let roots = CertificateStore([unicodeCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "straße.org", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: unicodeCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @Test
    func `rejects unicode common name with encoded idna label`() async throws {
        let roots = CertificateStore([unicodeCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--strae-oqa.org", serverIP: nil)
            }
        )
        await assertInvalidCertificate(
            await verifier.validate(
                leaf: unicodeCNCert,
                intermediates: CertificateStore()
            )
        )
    }
}

extension ServerIdentityPolicy.Test.Deprecated {
    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `can validate hostname in first san`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `can validate hostname in second san`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "example.com", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `ignores trailing period`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "example.com.", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `lowercases hostname for san`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "LoCaLhOsT", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `rejects incorrect hostname`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "httpbin.org", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `accepts ipv4 address`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "192.168.0.1")
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `accepts ipv6 address`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "2001:db8::1")
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `rejects incorrect ipv4 address`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "192.168.0.2")
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `rejects incorrect ipv6 address`() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "2001:db8::2")
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `accepts wildcards`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "this.wildcard.example.com", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `accepts suffix wildcard`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.example.com", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `accepts prefix wildcard`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "bar.example.com", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `accepts infix wildcard`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "baz.example.com", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `ignores trailing period in cert`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "trailing.period.example.com", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `rejects encoded idna label`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "straße.unicode.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `matches unencoded idna label`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--strae-oqa.unicode.example.com", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `does not match idna label with wildcard`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--xx-gia.unicode.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `does not match non leftmost wildcards`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "weirdwildcard.nomatch.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `does not match multiple wildcards`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "one.two.double.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `rejects wildcard before unencoded idna label`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.straße.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `matches wildcard before encoded idna label`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.xn--strae-oqa.example.com", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `does not match san with embedded null`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "nul\u{0000}l.example.com", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `falls back to common name`() async throws {
        let roots = CertificateStore([multiCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `lowercases for common name`() async throws {
        let roots = CertificateStore([multiCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "LoCaLhOsT", serverIP: nil)
            }
        )
        await assertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `rejects unicode common name with unencoded idna label`() async throws {
        let roots = CertificateStore([unicodeCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "straße.org", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: unicodeCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `rejects unicode common name with encoded idna label`() async throws {
        let roots = CertificateStore([unicodeCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--strae-oqa.org", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: unicodeCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `handles missing common name`() async throws {
        let roots = CertificateStore([noCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: noCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    @Test
    func `does not fall back to cn with sans`() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "httpbin.org", serverIP: nil)
            }
        )
        await assertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }
}

extension ISO_8824.OctetString {
    fileprivate init(ipv4Address: String) {
        let bytes = ServerIdentityPolicy.parsingIPv4Address(ipv4Address)!
        let byteArray = Swift.withUnsafeBytes(of: bytes) { Array($0) }
        self.init(contentBytes: byteArray[...])
    }

    fileprivate init(ipv6Address: String) {
        let bytes = ServerIdentityPolicy.parsingIPv6Address(ipv6Address)!
        let byteArray = Swift.withUnsafeBytes(of: bytes) { Array($0) }
        self.init(contentBytes: byteArray[...])
    }
}

@available(*, deprecated, message: "deprecated because it uses deprecated API")
private func assertValidCertificateDeprecated(
    _ verifier: @autoclosure () async throws -> VerificationResult,
    sourceLocation: SourceLocation = #_sourceLocation
) async rethrows {
    let result = try await verifier()
    if case .couldNotValidate(let reason) = result {
        Issue.record("Could not validate certificate, reason: \(reason)", sourceLocation: sourceLocation)
    }
}

@available(*, deprecated, message: "deprecated because it uses deprecated API")
private func assertInvalidCertificateDeprecated(
    _ verifier: @autoclosure () async throws -> VerificationResult,
    sourceLocation: SourceLocation = #_sourceLocation
) async rethrows {
    let result = try await verifier()
    if case .validCertificate = result {
        Issue.record("Incorrectly validated certificate", sourceLocation: sourceLocation)
    }
}

private func assertValidCertificate(
    _ verifier: @autoclosure () async throws -> CertificateValidationResult,
    sourceLocation: SourceLocation = #_sourceLocation
) async rethrows {
    let result = try await verifier()
    if case .couldNotValidate(let reason) = result {
        Issue.record("Could not validate certificate, reason: \(reason)", sourceLocation: sourceLocation)
    }
}

private func assertInvalidCertificate(
    _ verifier: @autoclosure () async throws -> CertificateValidationResult,
    sourceLocation: SourceLocation = #_sourceLocation
) async rethrows {
    let result = try await verifier()
    if case .validCertificate = result {
        Issue.record("Incorrectly validated certificate", sourceLocation: sourceLocation)
    }
}
