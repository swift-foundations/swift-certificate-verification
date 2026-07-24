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
@testable import Certificates

/// The Crypto-typed ``Certificate/PublicKey`` initialisers, parked in the TEST target.
///
/// These were public API on the model until the witness reshape made
/// ``Certificate/PublicKey`` an algorithm plus the key's canonical bytes — which is what
/// removed Crypto from the main target. They are *construction* conveniences: verification
/// only ever reads a key, so nothing in the verifier needs to build one from a backend key
/// object. Keeping them on the model would drag a cryptographic dependency back into a
/// type that otherwise needs none, and charge that cost to every verification-only
/// consumer.
///
/// This is a deliberate parking place, not an architectural decision, and is recorded as
/// such so a later reader does not mistake temporary siting for intent. Their real home is
/// the `swift-certificates-crypto` adapter; when that package is created this file moves
/// there unchanged, alongside ``Certificate/Verify/crypto``, which was written as the same
/// prototype. Main-target purity rules govern main targets only, so a test target may bind
/// apple/swift-crypto directly.
///
/// RSA is absent deliberately rather than overlooked. It is outside slice 1, and the model
/// cannot represent an RSA subject public key at all: `init(spki:)` has no `.rsaKey` branch
/// and falls through to `unsupportedPublicKey`.
extension Certificate.PublicKey {
    /// Construct a public key wrapping a P-256 public key.
    /// - Parameter p256: The P-256 public key to wrap.
    public init(_ p256: P256.Signing.PublicKey) {
        self.init(backing: .p256(x963: Array(p256.x963Representation)))
    }

    /// Construct a public key wrapping a P-384 public key.
    /// - Parameter p384: The P-384 public key to wrap.
    public init(_ p384: P384.Signing.PublicKey) {
        self.init(backing: .p384(x963: Array(p384.x963Representation)))
    }

    /// Construct a public key wrapping a P-521 public key.
    /// - Parameter p521: The P-521 public key to wrap.
    public init(_ p521: P521.Signing.PublicKey) {
        self.init(backing: .p521(x963: Array(p521.x963Representation)))
    }

    /// Construct a public key wrapping an Ed25519 public key.
    /// - Parameter ed25519: The Ed25519 public key to wrap.
    public init(_ ed25519: Curve25519.Signing.PublicKey) {
        self.init(backing: .ed25519(raw: Array(ed25519.rawRepresentation)))
    }
}
