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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// The signature-verification capability the verifier is given, rather than owns.
    ///
    /// This module models certificates; it does not perform cryptography. Chain
    /// verification needs exactly one cryptographic operation — "is this signature,
    /// made with this algorithm, valid for these bytes under this public key?" — and
    /// that operation is injected here instead of imported. Keeping it on this side of
    /// the boundary is what allows the module to build without Crypto or Foundation.
    ///
    /// A witness is a value of functions rather than a protocol: there is exactly one
    /// production implementation (the `swift-certificates-crypto` adapter) plus test
    /// fakes, so a protocol would buy genericity nobody spends.
    ///
    /// Verification returns `Bool`, not `throws`. A signature that fails to verify is a
    /// domain outcome consumed by the policy and result path — not an error. Structural
    /// failures that *are* errors (an unsupported algorithm, a malformed key encoding)
    /// surface earlier, as `Certificate.Error`, when the model is built.
    public struct Verify: Sendable {
        /// Answers whether `signature` is a valid signature over `signedBytes`, made
        /// under `publicKey` using `signatureAlgorithm`.
        ///
        /// Implementations must return `false` — never trap — for any input they cannot
        /// verify, including keys or signatures whose encoding is malformed for the
        /// stated algorithm. Verification is fail-closed: an unverifiable signature is
        /// an invalid one.
        public var signature:
            @Sendable (
                _ signatureAlgorithm: Certificate.SignatureAlgorithm,
                _ publicKey: Certificate.PublicKey,
                _ signature: Certificate.Signature,
                _ signedBytes: ArraySlice<UInt8>
            ) -> Bool

        @inlinable
        public init(
            signature: @escaping @Sendable (
                _ signatureAlgorithm: Certificate.SignatureAlgorithm,
                _ publicKey: Certificate.PublicKey,
                _ signature: Certificate.Signature,
                _ signedBytes: ArraySlice<UInt8>
            ) -> Bool
        ) {
            self.signature = signature
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Verify {
    /// A witness that rejects every signature.
    ///
    /// Provided for tests and callers that deliberately want a verifier which validates
    /// nothing. It is **not** a default: ``Verifier`` requires its witness explicitly,
    /// so that omitting one is a compile error rather than a verifier that silently
    /// rejects every chain. The behaviour is useful; only defaulting to it was wrong.
    public static let rejectingAll = Certificate.Verify { _, _, _, _ in false }
}
