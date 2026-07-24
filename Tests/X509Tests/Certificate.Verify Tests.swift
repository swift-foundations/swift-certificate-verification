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
