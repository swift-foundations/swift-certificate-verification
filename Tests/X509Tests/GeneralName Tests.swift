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
// Covers the two GeneralName CHOICE cases whose description carries an ASN.1 ANY
// payload. `Certificate Tests`' `printing general name` covers all eight cases, but that
// file is excluded from this target, so without these two the rendering they assert would
// be changeable with nothing compiled to notice.
//
//===----------------------------------------------------------------------===//

import ISO_8824
import ISO_8825
import Testing
@testable import Certificates

extension GeneralName {
    @Suite struct Test {
        @Suite struct Unit {}
    }
}

extension GeneralName.Test.Unit {
    /// The two ANY-carrying cases render their payload as bare DER bytes.
    ///
    /// Every case of ``GeneralName``'s description is an RFC 5280 §4.2.1.6 CHOICE label
    /// over its payload — `DNSName`, `DirectoryName`, `IPAddress`, `RegisteredID`,
    /// `RFC822Name`, `URI`. These two previously rendered `String(reflecting:)` of the ANY
    /// itself, which emitted the *Swift* type's name into a description whose job is to
    /// show the *specification* shape, and which no longer even matched the type after the
    /// retarget onto ``ISO_8825/Any``.
    ///
    /// Bare bytes match `ipAddress`, which is the same situation — an opaque octet payload
    /// inside a spec-named case.
    ///
    /// `[5, 0]` is DER for ASN.1 NULL: universal tag 5, zero-length content.
    @Test func `ANY-carrying cases render bare DER bytes`() throws {
        let null = try ISO_8825.`Any`(erasing: ISO_8824.Null())

        #expect(String(describing: GeneralName.ediPartyName(null)) == "EDIPartyName([5, 0])")
        #expect(String(describing: GeneralName.x400Address(null)) == "X400Address([5, 0])")
    }

    /// Pins the sibling cases the change had to leave alone.
    ///
    /// The rendering change reaches `description` itself, so the guard that matters is not
    /// only that the two changed cases are right but that the others did not move with
    /// them. Without this, a later edit to the shared `switch` could alter every label and
    /// only the excluded file would disagree.
    @Test func `the other CHOICE cases are unchanged`() throws {
        #expect(
            String(describing: GeneralName.dnsName("www.apple.com"))
                == "DNSName(\"www.apple.com\")"
        )
        #expect(
            String(describing: GeneralName.rfc822Name("mail@example.com"))
                == "RFC822Name(\"mail@example.com\")"
        )
        #expect(
            String(describing: GeneralName.uniformResourceIdentifier("http://www.apple.com/"))
                == "URI(\"http://www.apple.com/\")"
        )
        #expect(
            String(describing: GeneralName.registeredID([1, 2, 3, 4, 5]))
                == "RegisteredID(1.2.3.4.5)"
        )
        let loopback = ISO_8824.OctetString(contentBytes: [127, 0, 0, 1])
        #expect(
            String(describing: GeneralName.ipAddress(loopback))
                == "IPAddress([127, 0, 0, 1])"
        )
    }
}
