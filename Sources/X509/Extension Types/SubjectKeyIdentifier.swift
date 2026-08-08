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

import ISO_8824
import ISO_8825

/// Provides a means of identifying a certificate that contains a particular public key.
///
/// This extension contains a value derived from the public key of the certificate in which it appears.
/// That value can be used to build the ``AuthorityKeyIdentifier/keyIdentifier`` field in
/// any certificate issued by this certificate. This makes it possible to identify a certificate
/// possessing the key that issued another certificate.
public struct SubjectKeyIdentifier {
  public var keyIdentifier: ArraySlice<UInt8>

  /// Construct a Subject Key Identifier extension with a specific key identifier.
  ///
  /// - Parameter keyIdentifier: The identifier to associate with this certificate.
  @inlinable
  public init(keyIdentifier: ArraySlice<UInt8>) {
    self.keyIdentifier = keyIdentifier
  }

  /// Create a new ``SubjectKeyIdentifier`` object
  /// by unwrapping a ``Certificate/Extension``.
  ///
  /// - Parameter ext: The ``Certificate/Extension`` to unwrap
  /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
  ///     `ISO_8824.ObjectIdentifier.X509ExtensionID.subjectKeyIdentifier`.
  @inlinable
  @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
  public init(_ ext: Certificate.Extension) throws {
    guard ext.oid == .X509ExtensionID.subjectKeyIdentifier else {
      throw Certificate.Error.extension(
        .incorrectOID(expected: .X509ExtensionID.subjectKeyIdentifier, found: ext.oid)
      )
    }

    let asn1KeyIdentifier = try ISO_8824.OctetString(derEncoded: ext.value)
    self.keyIdentifier = asn1KeyIdentifier.bytes
  }
}

extension SubjectKeyIdentifier: Hashable {}

extension SubjectKeyIdentifier: Sendable {}

extension SubjectKeyIdentifier: CustomStringConvertible {
  public var description: String {
    return self.keyIdentifier.lazy.map { String($0, radix: 16) }.joined(separator: ":")
  }
}

extension SubjectKeyIdentifier: CustomDebugStringConvertible {
  public var debugDescription: String {
    "SubjectKeyIdentifier(\(String(describing: self)))"
  }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {
  /// Construct an opaque ``Certificate/Extension`` from this Subject Key Identifier extension.
  ///
  /// - Parameters:
  ///   - ski: The extension to wrap
  ///   - critical: Whether this extension should have the critical bit set.
  @inlinable
  public init(_ ski: SubjectKeyIdentifier, critical: Bool) throws {
    let asn1Representation = ISO_8824.OctetString(contentBytes: ski.keyIdentifier)
    var serializer = ISO_8825.DER.Serializer()
    try serializer.serialize(asn1Representation)
    self.init(
      oid: .X509ExtensionID.subjectKeyIdentifier,
      critical: critical,
      value: serializer.serializedBytes[...]
    )
  }
}

// `init(hash publicKey:)` — computing an SKI as the SHA-1 of the SPKI, per RFC 5280
// §4.2.1.2 — has moved out of this target. It is a *construction* convenience: you
// compute an SKI to place into a certificate, whereas verification only ever reads
// one. Keeping it here would drag a hashing capability (and with it Crypto and
// Foundation) into a type that otherwise needs neither, and charge that cost to every
// verification-only consumer. It belongs with the swift-certificates-crypto adapter.
