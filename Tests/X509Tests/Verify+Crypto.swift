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

/// The Crypto-backed `Certificate.Verify` witness, bound in the TEST target.
///
/// This is where the cryptography lives. The main target is Crypto-free and
/// Foundation-free — that is the point of the witness — and main-target purity rules
/// govern main targets only, so a test target may bind apple/swift-crypto directly.
///
/// The model now carries an algorithm plus the key's canonical bytes rather than a
/// backend key object, so this witness owns the whole reconstruction: bytes in, backend
/// key and signature out, `Bool` back. That reconstruction is the only place in the
/// repository that knows anything about swift-crypto's types.
///
/// This implementation is the prototype of `swift-certificates-crypto`'s production
/// witness: when that package is created it is a lift-and-shift of this code, not a
/// rewrite.
extension Certificate.Verify {
    /// Verification backed by apple/swift-crypto, the sanctioned backend.
    ///
    /// Fail-closed by construction: every reconstruction step is fallible, and any
    /// failure — an unsupported algorithm, a key/signature/algorithm combination that
    /// does not agree, malformed bytes, or a thrown backend error — returns `false`
    /// rather than trapping or propagating.
    static let crypto = Certificate.Verify { signatureAlgorithm, publicKey, signature, signedBytes in
        switch publicKey.backing {
        case .p256(let keyBytes):
            guard case .ecdsa(let sig) = signature.backing,
                let key = try? P256.Signing.PublicKey(x963Representation: keyBytes),
                let raw = sig.paddedRawRepresentation(coordinateByteCount: 32),
                let inner = try? P256.Signing.ECDSASignature(rawRepresentation: raw)
            else {
                return false
            }
            switch signatureAlgorithm {
            case .ecdsaWithSHA256:
                return key.isValidSignature(inner, for: SHA256.hash(data: signedBytes))
            case .ecdsaWithSHA384:
                return key.isValidSignature(inner, for: SHA384.hash(data: signedBytes))
            case .ecdsaWithSHA512:
                return key.isValidSignature(inner, for: SHA512.hash(data: signedBytes))
            default:
                return false
            }

        case .p384(let keyBytes):
            guard case .ecdsa(let sig) = signature.backing,
                let key = try? P384.Signing.PublicKey(x963Representation: keyBytes),
                let raw = sig.paddedRawRepresentation(coordinateByteCount: 48),
                let inner = try? P384.Signing.ECDSASignature(rawRepresentation: raw)
            else {
                return false
            }
            switch signatureAlgorithm {
            case .ecdsaWithSHA256:
                return key.isValidSignature(inner, for: SHA256.hash(data: signedBytes))
            case .ecdsaWithSHA384:
                return key.isValidSignature(inner, for: SHA384.hash(data: signedBytes))
            case .ecdsaWithSHA512:
                return key.isValidSignature(inner, for: SHA512.hash(data: signedBytes))
            default:
                return false
            }

        case .p521(let keyBytes):
            guard case .ecdsa(let sig) = signature.backing,
                let key = try? P521.Signing.PublicKey(x963Representation: keyBytes),
                let raw = sig.paddedRawRepresentation(coordinateByteCount: 66),
                let inner = try? P521.Signing.ECDSASignature(rawRepresentation: raw)
            else {
                return false
            }
            switch signatureAlgorithm {
            case .ecdsaWithSHA256:
                return key.isValidSignature(inner, for: SHA256.hash(data: signedBytes))
            case .ecdsaWithSHA384:
                return key.isValidSignature(inner, for: SHA384.hash(data: signedBytes))
            case .ecdsaWithSHA512:
                return key.isValidSignature(inner, for: SHA512.hash(data: signedBytes))
            default:
                return false
            }

        case .ed25519(let keyBytes):
            guard case .ed25519 = signatureAlgorithm,
                case .ed25519(let sigBytes) = signature.backing,
                let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyBytes)
            else {
                return false
            }
            return key.isValidSignature(sigBytes, for: signedBytes)
        }
    }
}

extension ECDSASignature {
    /// The fixed-width `r || s` form swift-crypto's `ECDSASignature(rawRepresentation:)`
    /// expects, rebuilt from this type's DER `r`/`s` pair.
    ///
    /// `ECDSASignature` stores `r` and `s` in ASN.1 integer form, with leading zero bytes
    /// stripped, so each must be left-padded back out to the curve's coordinate width.
    /// Returns `nil` — never traps — when either integer is wider than the curve allows,
    /// which is the fail-closed answer for a signature that does not belong to this key.
    ///
    /// Coordinate widths: 32 bytes (P-256), 48 (P-384), 66 (P-521) — the field element
    /// sizes of SEC 1 v2.0 §2.3.3, the same sizes the key-length checks in the model use.
    func paddedRawRepresentation(coordinateByteCount: Int) -> [UInt8]? {
        guard self.r.count <= coordinateByteCount, self.s.count <= coordinateByteCount else {
            return nil
        }

        var raw = [UInt8]()
        raw.reserveCapacity(2 * coordinateByteCount)
        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - self.r.count))
        raw.append(contentsOf: self.r)
        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - self.s.count))
        raw.append(contentsOf: self.s)
        return raw
    }
}
