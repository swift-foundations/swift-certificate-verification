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

@testable import Certificates

/// The Crypto-backed `Certificate.Verify` witness, bound in the TEST target.
///
/// This is where the cryptography lives for now. The main target is Crypto-free — that
/// is the point of the witness — and main-target purity rules govern main targets only,
/// so a test target may bind apple/swift-crypto directly.
///
/// This implementation is the prototype of `swift-certificates-crypto`'s production
/// witness: when that package is created it is a lift-and-shift of this code, not a
/// rewrite. Deliberately, the adapter package is *not* a prerequisite for clearing the
/// D3 STOP — the main target loses Crypto either way.
extension Certificate.Verify {
    /// Verification backed by apple/swift-crypto, the sanctioned backend.
    static let crypto = Certificate.Verify { signatureAlgorithm, publicKey, signature, signedBytes in
        // Delegates to the model's own verification for as long as the backing enums
        // still carry Crypto key types. When the backings become algorithm + raw bytes,
        // only the body of this closure changes — the seam, its callers, and every test
        // that binds it stay exactly as they are. That is what makes the next batch a
        // contained change rather than a ripple.
        publicKey.isValidSignature(signature, for: signedBytes, signatureAlgorithm: signatureAlgorithm)
    }
}
