// ===----------------------------------------------------------------------===//
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
// ===----------------------------------------------------------------------===//

@preconcurrency import Crypto
import ISO_8824
import ISO_8825
import Time_Primitive

@testable import Certificates

extension Certificate {
  /// Certificate issuance for the TEST target, performed at the DER level.
  ///
  /// ## Why this exists, and why it reinstates nothing
  ///
  /// Issuance is an excluded surface: `Certificate.PrivateKey` and the issuing
  /// `Certificate.init(…issuerPrivateKey:)` were deleted from the main target and belong
  /// to the future issuance package. The policy suites nevertheless need certificates
  /// whose contents vary per test — validity windows, basic constraints, name
  /// constraints, SANs — and there are far too many distinct parameterisations to freeze
  /// as fixtures.
  ///
  /// This builds them from the outside instead: assemble a `TBSCertificate`, serialize
  /// it, sign those bytes, wrap the result in the standard
  /// `SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }`, and read the
  /// whole thing back through the **public** ``Certificate/init(derEncoded:)``. Nothing
  /// deleted comes back, the main target is untouched, and the certificate that results
  /// is one the parser produced — not one a test constructed and asserted about itself.
  ///
  /// Main-target purity rules govern main targets only, which is what lets this bind
  /// apple/swift-crypto directly, exactly as ``Certificate/Verify/crypto`` does.
  ///
  /// ## ⚠️ NON-DETERMINISTIC — NEVER USE THIS TO GENERATE FROZEN FIXTURES
  ///
  /// ECDSA signing uses a randomised nonce, so issuing the same certificate twice
  /// produces **different bytes**. That is correct for suites asserting policy behaviour,
  /// which care what the verifier decides and not what the bytes are.
  ///
  /// It is wrong, and silently so, for the frozen DER corpus under `Fixtures/`. Those
  /// vectors are byte-frozen deliberately: regenerating them rewrites every file for no
  /// semantic gain and destroys the property that makes a frozen corpus worth having.
  /// If you need a new fixture, add one — do not reach for this because it is nearer.
  enum Issuance {}
}

extension Certificate.Issuance {
  /// A signing key for test issuance — the test-target stand-in for the deleted
  /// `Certificate.PrivateKey`, carrying only what issuing a certificate requires.
  struct Key {
    enum Backing {
      case p256(P256.Signing.PrivateKey)
      case p384(P384.Signing.PrivateKey)
      case p521(P521.Signing.PrivateKey)
      case ed25519(Curve25519.Signing.PrivateKey)
    }

    var backing: Backing

    init(_ key: P256.Signing.PrivateKey) { self.backing = .p256(key) }
    init(_ key: P384.Signing.PrivateKey) { self.backing = .p384(key) }
    init(_ key: P521.Signing.PrivateKey) { self.backing = .p521(key) }
    init(_ key: Curve25519.Signing.PrivateKey) { self.backing = .ed25519(key) }

    /// The matching public key, in the model's algorithm-plus-bytes form.
    var publicKey: Certificate.PublicKey {
      switch self.backing {
      case .p256(let key): return Certificate.PublicKey(key.publicKey)
      case .p384(let key): return Certificate.PublicKey(key.publicKey)
      case .p521(let key): return Certificate.PublicKey(key.publicKey)
      case .ed25519(let key): return Certificate.PublicKey(key.publicKey)
      }
    }

    /// The signature over `bytes`, encoded as the certificate's `signatureValue`
    /// expects: DER `SEQUENCE { r, s }` for ECDSA, the raw 64 bytes for Ed25519.
    ///
    /// The pairing of key and algorithm is checked rather than assumed — signing a
    /// P-256 key's bytes under an Ed25519 algorithm identifier would otherwise produce
    /// a certificate that is internally inconsistent and fails far away from here.
    func signature(
      for bytes: [UInt8],
      algorithm: Certificate.SignatureAlgorithm
    ) throws -> [UInt8] {
      switch (self.backing, algorithm) {
      case (.p256(let key), .ecdsaWithSHA256):
        return Array(try key.signature(for: SHA256.hash(data: bytes)).derRepresentation)

      case (.p256(let key), .ecdsaWithSHA384):
        return Array(try key.signature(for: SHA384.hash(data: bytes)).derRepresentation)

      case (.p256(let key), .ecdsaWithSHA512):
        return Array(try key.signature(for: SHA512.hash(data: bytes)).derRepresentation)

      case (.p384(let key), .ecdsaWithSHA256):
        return Array(try key.signature(for: SHA256.hash(data: bytes)).derRepresentation)

      case (.p384(let key), .ecdsaWithSHA384):
        return Array(try key.signature(for: SHA384.hash(data: bytes)).derRepresentation)

      case (.p384(let key), .ecdsaWithSHA512):
        return Array(try key.signature(for: SHA512.hash(data: bytes)).derRepresentation)

      case (.p521(let key), .ecdsaWithSHA256):
        return Array(try key.signature(for: SHA256.hash(data: bytes)).derRepresentation)

      case (.p521(let key), .ecdsaWithSHA384):
        return Array(try key.signature(for: SHA384.hash(data: bytes)).derRepresentation)

      case (.p521(let key), .ecdsaWithSHA512):
        return Array(try key.signature(for: SHA512.hash(data: bytes)).derRepresentation)

      case (.ed25519(let key), .ed25519):
        return Array(try key.signature(for: bytes))

      default:
        throw Failure.keyDoesNotSupportAlgorithm
      }
    }
  }

  /// Why an issuance attempt could not produce a certificate.
  enum Failure: Error {
    /// The signing key cannot sign under the requested signature algorithm.
    case keyDoesNotSupportAlgorithm
  }
}

extension Certificate.Issuance {
  /// Issue a certificate, signing `subject`'s details with `issuerPrivateKey`.
  ///
  /// The returned certificate is parsed from the bytes just written, so anything the
  /// parser would reject fails here rather than surfacing later as a puzzling policy
  /// outcome.
  ///
  /// - Note: `serialNumber` has no default because the model has no random-serial
  ///   initializer — that generator was issuance-side and left with it. Tests pass an
  ///   explicit value, which also makes issued certificates reproducible in everything
  ///   except the signature bytes.
  static func issue(
    version: Certificate.Version = .v3,
    serialNumber: Certificate.SerialNumber,
    publicKey: Certificate.PublicKey,
    notValidBefore: Instant,
    notValidAfter: Instant,
    issuer: DistinguishedName,
    subject: DistinguishedName,
    signatureAlgorithm: Certificate.SignatureAlgorithm,
    extensions: Certificate.Extensions,
    issuerPrivateKey: Key
  ) throws -> Certificate {
    let validity = Validity(
      notBefore: try Time.makeTime(from: notValidBefore),
      notAfter: try Time.makeTime(from: notValidAfter)
    )

    let tbsCertificate = TBSCertificate(
      version: version,
      serialNumber: serialNumber,
      signature: signatureAlgorithm,
      issuer: issuer,
      validity: validity,
      subject: subject,
      publicKey: publicKey,
      extensions: extensions
    )

    let tbsCertificateBytes = try ISO_8825.DER.Serializer.serialized(element: tbsCertificate)
    let signatureBytes = try issuerPrivateKey.signature(
      for: tbsCertificateBytes,
      algorithm: signatureAlgorithm
    )

    var coder = ISO_8825.DER.Serializer()
    try coder.appendConstructedNode(identifier: .sequence) { coder in
      // The TBS bytes are written verbatim rather than re-serialized from the struct:
      // the signature covers exactly these bytes, and re-encoding could canonicalise
      // them into something the signature no longer matches.
      coder.serializeRawBytes(tbsCertificateBytes[...])
      try coder.serialize(AlgorithmIdentifier(signatureAlgorithm))
      try coder.serialize(ISO_8824.BitString(bytes: signatureBytes[...]))
    }

    return try Certificate(derEncoded: coder.serializedBytes)
  }
}
