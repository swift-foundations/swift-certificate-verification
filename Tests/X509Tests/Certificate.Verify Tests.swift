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

import Testing
@testable import Certificates

// Exercises the injected signature-verification witness directly, against the frozen
// DER corpus.
//
// This suite exists because nothing else covers the witness. Every other suite that
// builds a Verifier installs its certificate as both trust anchor and leaf, so the
// verifier takes its root-store fast path and the signature check is never reached —
// meaning a witness that always returned `true`, or one wired to the wrong bytes, would
// pass the entire rest of the test target. These cases assert the witness both accepts
// a genuine signature and rejects tampered and wrongly-signed ones, so that the
// backing-representation work behind it has a regression net that actually fires.

extension Certificate.Verify {
    @Suite struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
        @Suite struct Integration {}
    }
}

extension Certificate.Verify.Test.Unit {
    @Test func `accepts a genuine self-signed signature`() throws {
        // root-ca is self-signed: its own public key is the issuer key.
        let root = try Fixture.certificate("root-ca")
        #expect(
            Certificate.Verify.crypto.signature(
                root.signatureAlgorithm,
                root.publicKey,
                root.signature,
                root.tbsCertificateBytes
            )
        )
    }

    @Test func `accepts an intermediate signed by its issuer`() throws {
        // intermediate-ca is signed by root-ca, so it verifies under the ROOT's key —
        // which also pins that the witness is handed the issuer's key, not the subject's.
        let root = try Fixture.certificate("root-ca")
        let intermediate = try Fixture.certificate("intermediate-ca")
        #expect(
            Certificate.Verify.crypto.signature(
                intermediate.signatureAlgorithm,
                root.publicKey,
                intermediate.signature,
                intermediate.tbsCertificateBytes
            )
        )
    }

    @Test func `accepts an ed25519 signature`() throws {
        // Algorithm coverage beyond ECDSA: ed25519-root-ca is a self-signed Ed25519 root.
        let edRoot = try Fixture.certificate("ed25519-root-ca")
        #expect(
            Certificate.Verify.crypto.signature(
                edRoot.signatureAlgorithm,
                edRoot.publicKey,
                edRoot.signature,
                edRoot.tbsCertificateBytes
            )
        )
    }

    /// `ECDSASignature` stores `r`/`s` in ASN.1 integer form, with leading zero bytes
    /// stripped; the witness re-pads each back to the curve's coordinate width before
    /// handing them to the backend. **Those two halves must compose to the identity** —
    /// strip-then-pad has to return exactly the bytes signing produced, or the witness
    /// rejects signatures that are perfectly valid.
    ///
    /// Nothing else covers the composition. The witness cases above verify real frozen
    /// certificates, but a coordinate only carries a leading zero byte about once in 256,
    /// so a fixed corpus is overwhelmingly likely to miss the boundary entirely — a
    /// padding defect would sit behind a green suite until it met a certificate in the
    /// wild. These vectors hit the boundaries deliberately rather than hoping for them.
    @Test func `stripping and re-padding an ECDSA signature is the identity`() throws {
        // P-256 field element width: SEC 1 v2.0 §2.3.3, the same constant the witness uses.
        let width = 32

        func roundTrips(_ raw: [UInt8]) -> Bool {
            let signature = ECDSASignature(rawSignatureBytes: raw)
            return signature.paddedRawRepresentation(coordinateByteCount: width) == raw
        }

        // No leading zeros in either coordinate — the ordinary case.
        #expect(roundTrips(Array(repeating: 0x7F, count: 2 * width)))

        // Top bit set throughout: the shape that makes a DER INTEGER carry a sign byte.
        #expect(roundTrips(Array(repeating: 0xFF, count: 2 * width)))

        // A leading zero in r only, in s only, and in both.
        var rLeadingZero = Array(repeating: UInt8(0x11), count: 2 * width)
        rLeadingZero[0] = 0x00
        var sLeadingZero = Array(repeating: UInt8(0x11), count: 2 * width)
        sLeadingZero[width] = 0x00
        var bothLeadingZero = Array(repeating: UInt8(0x11), count: 2 * width)
        bothLeadingZero[0] = 0x00
        bothLeadingZero[width] = 0x00
        #expect(roundTrips(rLeadingZero))
        #expect(roundTrips(sLeadingZero))
        #expect(roundTrips(bothLeadingZero))

        // Degenerate: an all-zero coordinate strips to nothing and must pad back to full
        // width. This is the case where an off-by-one in the padding is most visible.
        #expect(roundTrips(Array(repeating: 0x00, count: 2 * width)))

        // Genuinely small integers — 31 leading zeros in each coordinate.
        var small = Array(repeating: UInt8(0x00), count: 2 * width)
        small[width - 1] = 0x09
        small[2 * width - 1] = 0x07
        #expect(roundTrips(small))
    }
}

extension Certificate.Verify.Test.`Edge Case` {
    @Test func `rejects a certificate whose TBS bytes were tampered with`() throws {
        // leaf-tampered-tbs is a validly-signed leaf with one TBS byte flipped after
        // signing, so the signature no longer covers the bytes it claims to.
        let intermediate = try Fixture.certificate("intermediate-ca")
        let tampered = try Fixture.certificate("leaf-tampered-tbs")
        #expect(
            !Certificate.Verify.crypto.signature(
                tampered.signatureAlgorithm,
                intermediate.publicKey,
                tampered.signature,
                tampered.tbsCertificateBytes
            )
        )
    }

    @Test func `rejects a signature made by an unrelated key`() throws {
        // leaf-wrong-key-signature names the intermediate as its issuer but was signed
        // by a key that appears in no chain.
        let intermediate = try Fixture.certificate("intermediate-ca")
        let wrongKey = try Fixture.certificate("leaf-wrong-key-signature")
        #expect(
            !Certificate.Verify.crypto.signature(
                wrongKey.signatureAlgorithm,
                intermediate.publicKey,
                wrongKey.signature,
                wrongKey.tbsCertificateBytes
            )
        )
    }

    @Test func `rejects a genuine signature checked against the wrong key`() throws {
        // A real signature, verified under a key that did not make it.
        let root = try Fixture.certificate("root-ca")
        let intermediate = try Fixture.certificate("intermediate-ca")
        #expect(
            !Certificate.Verify.crypto.signature(
                intermediate.signatureAlgorithm,
                intermediate.publicKey,  // wrong: intermediate was signed by the root
                intermediate.signature,
                intermediate.tbsCertificateBytes
            )
        )
        // Control: the same signature under the correct key must still verify, so this
        // case cannot pass merely because verification is broken in general.
        #expect(
            Certificate.Verify.crypto.signature(
                intermediate.signatureAlgorithm,
                root.publicKey,
                intermediate.signature,
                intermediate.tbsCertificateBytes
            )
        )
    }

    @Test func `the rejecting witness rejects a genuine signature`() throws {
        // Guards the fail-closed value itself: .rejectingAll must reject input that the
        // real witness accepts, otherwise it is not actually rejecting anything.
        let root = try Fixture.certificate("root-ca")
        #expect(
            !Certificate.Verify.rejectingAll.signature(
                root.signatureAlgorithm,
                root.publicKey,
                root.signature,
                root.tbsCertificateBytes
            )
        )
    }
}
