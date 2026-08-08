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
import Testing
import Time_Primitive

@testable import Certificates

extension Certificate.Issuance {
  @Suite struct Test {
    @Suite struct Unit {}
    @Suite struct Integration {}
  }
}

extension Certificate.Issuance.Test {
  /// 2026-01-01, the instant the frozen corpus is built around.
  static let now = Instant(secondsSinceUnixEpoch: 1_767_225_600)
  static let aYearEarlier = Instant(secondsSinceUnixEpoch: 1_735_689_600)
  static let aDecadeLater = Instant(secondsSinceUnixEpoch: 2_051_222_400)

  static func name(_ commonName: String) throws -> DistinguishedName {
    try DistinguishedName([
      RelativeDistinguishedName.Attribute(
        type: .RDNAttributeType.commonName,
        utf8String: commonName
      )
    ])
  }

  static func certificateAuthority() throws -> Certificate.Extensions {
    try Certificate.Extensions([
      Certificate.Extension(
        BasicConstraints.isCertificateAuthority(maxPathLength: nil),
        critical: true
      )
    ])
  }

  static func endEntity() throws -> Certificate.Extensions {
    try Certificate.Extensions([
      Certificate.Extension(BasicConstraints.notCertificateAuthority, critical: true)
    ])
  }
}

extension Certificate.Issuance.Test.Unit {
  typealias Fixtures = Certificate.Issuance.Test

  /// An issued self-signed certificate verifies under its own key, through the real
  /// witness rather than through anything this file wrote.
  ///
  /// This is the load-bearing claim of the whole issuance seam: that a certificate can be
  /// produced without the deleted `Certificate.PrivateKey` and still be a certificate the
  /// parser accepts and the verifier's cryptography agrees with.
  @Test func `an issued self-signed certificate verifies under its own key`() throws {
    let key = Certificate.Issuance.Key(P256.Signing.PrivateKey())
    let name = try Fixtures.name("Issuance Test Root")

    let root = try Certificate.Issuance.issue(
      serialNumber: Certificate.SerialNumber(1),
      publicKey: key.publicKey,
      notValidBefore: Fixtures.aYearEarlier,
      notValidAfter: Fixtures.aDecadeLater,
      issuer: name,
      subject: name,
      signatureAlgorithm: .ecdsaWithSHA256,
      extensions: try Fixtures.certificateAuthority(),
      issuerPrivateKey: key
    )

    #expect(root.subject == name)
    #expect(root.issuer == name)
    #expect(root.publicKey == key.publicKey)
    #expect(
      Certificate.Verify.crypto.signature(
        root.signatureAlgorithm,
        root.publicKey,
        root.signature,
        root.tbsCertificateBytes
      )
    )
  }

  /// A certificate issued under one key does not verify under another.
  ///
  /// Without this the case above would pass against a witness that ignored its inputs, and
  /// against an issuer that signed nothing meaningful.
  @Test func `an issued certificate does not verify under an unrelated key`() throws {
    let key = Certificate.Issuance.Key(P256.Signing.PrivateKey())
    let stranger = Certificate.Issuance.Key(P256.Signing.PrivateKey())
    let name = try Fixtures.name("Issuance Test Root")

    let root = try Certificate.Issuance.issue(
      serialNumber: Certificate.SerialNumber(2),
      publicKey: key.publicKey,
      notValidBefore: Fixtures.aYearEarlier,
      notValidAfter: Fixtures.aDecadeLater,
      issuer: name,
      subject: name,
      signatureAlgorithm: .ecdsaWithSHA256,
      extensions: try Fixtures.certificateAuthority(),
      issuerPrivateKey: key
    )

    #expect(
      !Certificate.Verify.crypto.signature(
        root.signatureAlgorithm,
        stranger.publicKey,
        root.signature,
        root.tbsCertificateBytes
      )
    )
  }

  /// Issuing across every supported key and algorithm pairing, and rejecting the rest.
  ///
  /// The curve widths are where a signature-encoding defect hides: `ECDSASignature` strips
  /// leading zeros and the witness re-pads to the curve width, so a P-521 signature that
  /// round-trips as though it were P-256 is exactly the class of bug that type-checks.
  @Test func `every supported key and algorithm pairing issues and verifies`() throws {
    let pairings: [(Certificate.Issuance.Key, Certificate.SignatureAlgorithm)] = [
      (.init(P256.Signing.PrivateKey()), .ecdsaWithSHA256),
      (.init(P256.Signing.PrivateKey()), .ecdsaWithSHA384),
      (.init(P384.Signing.PrivateKey()), .ecdsaWithSHA384),
      (.init(P521.Signing.PrivateKey()), .ecdsaWithSHA512),
      (.init(Curve25519.Signing.PrivateKey()), .ed25519),
    ]

    for (key, algorithm) in pairings {
      let name = try Fixtures.name("Issuance Test \(algorithm)")
      let certificate = try Certificate.Issuance.issue(
        serialNumber: Certificate.SerialNumber(3),
        publicKey: key.publicKey,
        notValidBefore: Fixtures.aYearEarlier,
        notValidAfter: Fixtures.aDecadeLater,
        issuer: name,
        subject: name,
        signatureAlgorithm: algorithm,
        extensions: try Fixtures.certificateAuthority(),
        issuerPrivateKey: key
      )

      #expect(
        Certificate.Verify.crypto.signature(
          certificate.signatureAlgorithm,
          certificate.publicKey,
          certificate.signature,
          certificate.tbsCertificateBytes
        ),
        "\(algorithm) issued a signature its own witness rejects"
      )
    }
  }

  /// A key/algorithm mismatch is refused at issuance rather than producing a certificate
  /// that is internally inconsistent and fails somewhere far away.
  @Test func `a key that cannot sign under the algorithm is refused`() throws {
    let ed25519 = Certificate.Issuance.Key(Curve25519.Signing.PrivateKey())
    let name = try Fixtures.name("Issuance Test Mismatch")

    #expect(throws: Certificate.Issuance.Failure.keyDoesNotSupportAlgorithm) {
      try Certificate.Issuance.issue(
        serialNumber: Certificate.SerialNumber(4),
        publicKey: ed25519.publicKey,
        notValidBefore: Fixtures.aYearEarlier,
        notValidAfter: Fixtures.aDecadeLater,
        issuer: name,
        subject: name,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: try Fixtures.certificateAuthority(),
        issuerPrivateKey: ed25519
      )
    }
  }
}

extension Certificate.Issuance.Test.Integration {
  typealias Fixtures = Certificate.Issuance.Test

  /// A two-certificate chain built entirely by this seam validates end to end.
  ///
  /// ⚠️ The leaf is deliberately **not** the trust anchor. Every other suite in this
  /// package installs one certificate as both anchor and leaf, which makes the verifier
  /// take its root-store fast path and never reach the signature check at all — a witness
  /// hard-coded to `true` passes those. Anchoring the root and validating a *separate*
  /// leaf is what forces chain building and signature verification to actually run, so
  /// this test fails if issuance produces a signature the verifier cannot confirm.
  @Test func `a chain issued by this seam validates through the real verifier`() async throws {
    let rootKey = Certificate.Issuance.Key(P384.Signing.PrivateKey())
    let rootName = try Fixtures.name("Issuance Test Root CA")
    let root = try Certificate.Issuance.issue(
      serialNumber: Certificate.SerialNumber(10),
      publicKey: rootKey.publicKey,
      notValidBefore: Fixtures.aYearEarlier,
      notValidAfter: Fixtures.aDecadeLater,
      issuer: rootName,
      subject: rootName,
      signatureAlgorithm: .ecdsaWithSHA384,
      extensions: try Fixtures.certificateAuthority(),
      issuerPrivateKey: rootKey
    )

    let leafKey = Certificate.Issuance.Key(P256.Signing.PrivateKey())
    let leafName = try Fixtures.name("Issuance Test Leaf")
    let leaf = try Certificate.Issuance.issue(
      serialNumber: Certificate.SerialNumber(11),
      publicKey: leafKey.publicKey,
      notValidBefore: Fixtures.aYearEarlier,
      notValidAfter: Fixtures.aDecadeLater,
      issuer: rootName,
      subject: leafName,
      signatureAlgorithm: .ecdsaWithSHA256,
      extensions: try Fixtures.endEntity(),
      issuerPrivateKey: rootKey
    )

    var verifier = Verifier(
      rootCertificates: CertificateStore([root]),
      verify: .crypto
    ) {
      RFC5280Policy(validationTime: Fixtures.now)
    }

    let result = await verifier.validate(leaf: leaf, intermediates: CertificateStore())

    guard case .validCertificate(let chain) = result else {
      Issue.record("issued chain failed to validate: \(result)")
      return
    }
    #expect(Array(chain) == [leaf, root])
  }

  /// The same chain fails when the leaf's signature is not the root's.
  ///
  /// Pins that the case above passes because verification succeeded, not because the
  /// verifier accepts whatever it is handed.
  @Test func `a chain whose leaf was signed by a stranger does not validate`() async throws {
    let rootKey = Certificate.Issuance.Key(P384.Signing.PrivateKey())
    let rootName = try Fixtures.name("Issuance Test Root CA")
    let root = try Certificate.Issuance.issue(
      serialNumber: Certificate.SerialNumber(20),
      publicKey: rootKey.publicKey,
      notValidBefore: Fixtures.aYearEarlier,
      notValidAfter: Fixtures.aDecadeLater,
      issuer: rootName,
      subject: rootName,
      signatureAlgorithm: .ecdsaWithSHA384,
      extensions: try Fixtures.certificateAuthority(),
      issuerPrivateKey: rootKey
    )

    // Two leaves identical in every respect the verifier inspects — same key, validity,
    // issuer name, subject, algorithm and extensions — differing ONLY in who signed
    // them. That is what makes this a test of signature verification: a bare
    // `couldNotValidate` proves nothing on its own, since expiry, basic constraints or
    // a name mismatch would produce exactly the same outcome. The control pins the
    // cause by holding every other variable fixed.
    let leafKey = Certificate.Issuance.Key(P256.Signing.PrivateKey())
    let leafName = try Fixtures.name("Issuance Test Leaf")
    let stranger = Certificate.Issuance.Key(P384.Signing.PrivateKey())

    func leaf(signedBy issuerKey: Certificate.Issuance.Key) throws -> Certificate {
      try Certificate.Issuance.issue(
        serialNumber: Certificate.SerialNumber(21),
        publicKey: leafKey.publicKey,
        notValidBefore: Fixtures.aYearEarlier,
        notValidAfter: Fixtures.aDecadeLater,
        issuer: rootName,
        subject: leafName,
        signatureAlgorithm: .ecdsaWithSHA384,
        extensions: try Fixtures.endEntity(),
        issuerPrivateKey: issuerKey
      )
    }

    var verifier = Verifier(
      rootCertificates: CertificateStore([root]),
      verify: .crypto
    ) {
      RFC5280Policy(validationTime: Fixtures.now)
    }

    // Control first: signed by the root, this must validate. If it does not, the
    // negative below would pass for a reason having nothing to do with signatures.
    let genuine = await verifier.validate(
      leaf: try leaf(signedBy: rootKey),
      intermediates: CertificateStore()
    )
    guard case .validCertificate = genuine else {
      Issue.record("control failed: the genuinely-signed leaf did not validate: \(genuine)")
      return
    }

    let impostor = await verifier.validate(
      leaf: try leaf(signedBy: stranger),
      intermediates: CertificateStore()
    )
    guard case .couldNotValidate = impostor else {
      Issue.record("a chain signed by an unrelated key validated: \(impostor)")
      return
    }
  }
}
