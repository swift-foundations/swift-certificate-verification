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

import ISO_8824
import ISO_8825
import Time_Primitive

/// A representation of an X.509 certificate object.
///
/// X.509 certificates are a commonly-used identity format to cryptographically
/// attest to the identity of an actor in a system. They form part of the X.509
/// standard created by the ITU-T for defining a public key infrastructure (PKI).
/// X.509-style PKIs are commonly used in cases where it is necessary to delegate
/// the authority to attest to an actor's identity to a small number of trusted
/// parties (called Certificate Authorities).
///
/// The most common usage of X.509 certificates today is as part of the WebPKI,
/// where they are used to secure TLS connections to websites. X.509 certificates
/// are also used in a wide range of other TLS-based communications, as well as
/// in code signing infrastructure.
///
/// This type is intended to be useful for users both to create new ``Certificate``
/// objects, and to handle existing ones that they have received. In particular,
/// users need to be able to create ``Certificate`` objects directly (in the case
/// of self-signed certificates) and from Certificate Signing Requests, as well
/// as from their serialized DER representation.
///
/// ### Structure
///
/// ``Certificate`` is a representation of an X.509v3 certificate, as defined in
/// [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280.html). It provides
/// support for the full range of features in RFC 5280.
///
/// The type has two main goals. The first is that it aims to be able to store and
/// represent a parsed X.509 certificate issued by an arbitrary system in full
/// fidelity. As the X.509 standards have evolved over time, a number of certificates
/// exist in circulation that do not meet the current best practice standards. It is
/// important for this type to be able to represent these older certificates.
///
/// The second goal is to make it possible for users to easily construct _new_
/// ``Certificate`` objects from whole cloth. To achieve this there are a number of
/// higher-level APIs that can be used to construct the constituent parts of the
/// certificate. These are discussed at length in their relevant API documentation
/// (e.g. ``Certificate/Extensions-swift.struct`` & ``DistinguishedName``).
///
/// Both of these goals encourage this type to be immutable. A ``Certificate`` represents
/// a specific assertion of identity. Its ``Certificate/signature-swift.property`` is signed
/// across the rest of the data. Allowing users to change this data makes it easy to accidentally modify
/// a ``Certificate`` in one part of your code and not realise that the signature has inevitably
/// been invalidated.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct Certificate {
    /// The X.509 version of this certificate.
    ///
    /// This should be set to ``Certificate/Version-swift.struct/v3`` in
    /// almost all cases.
    @inlinable
    public var version: Version {
        self.tbsCertificate.version
    }

    /// The serial number of this certificate.
    ///
    /// This should be a unique, large, random number.
    @inlinable
    public var serialNumber: SerialNumber {
        self.tbsCertificate.serialNumber
    }

    /// The public key associated with this certificate.
    ///
    /// When validating that a certificate belongs to a service, that service should be able to
    /// produce cryptographic proof that it holds the private key associated with this public key.
    @inlinable
    public var publicKey: PublicKey {
        self.tbsCertificate.publicKey
    }

    /// The instant before which this certificate is not valid.
    @inlinable
    public var notValidBefore: Instant {
        Instant(self.tbsCertificate.validity.notBefore)
    }

    /// The instant after which this certificate is not valid.
    @inlinable
    public var notValidAfter: Instant {
        Instant(self.tbsCertificate.validity.notAfter)
    }

    /// The ``DistinguishedName`` of the issuer of this certificate.
    @inlinable
    public var issuer: DistinguishedName {
        self.tbsCertificate.issuer
    }

    /// The ``DistinguishedName`` of the subject of this certificate.
    @inlinable
    public var subject: DistinguishedName {
        self.tbsCertificate.subject
    }

    /// The extensions on this certificate.
    @inlinable
    public var extensions: Extensions {
        self.tbsCertificate.extensions
    }

    @usableFromInline
    internal let tbsCertificate: TBSCertificate

    /// The bytes of the `TBSCertificate` structure.
    ///
    /// The ``signature-swift.property`` is calculated over these bytes.
    public let tbsCertificateBytes: ArraySlice<UInt8>

    /// The signature attached to this certificate.
    ///
    /// This signature is computed over ``tbsCertificateBytes``.
    public let signature: Signature

    /// The signature algorithm used to produce ``signature-swift.property``.
    public let signatureAlgorithm: SignatureAlgorithm

    /// The bytes of the ``Signature``.
    ///
    /// These are preserved to ensure that we reserialize exactly what we deserialized, regardless
    /// of any canonicalisation we might do.
    @usableFromInline
    internal let signatureBytes: ArraySlice<UInt8>

    /// The bytes of the ``signatureAlgorithm-swift.property``.
    ///
    /// These are preserved to ensure that we reserialize exactly what we deserialized, regardless of
    /// any canonicalisation we might do.
    @usableFromInline
    internal let signatureAlgorithmBytes: ArraySlice<UInt8>

    @inlinable
    init(
        tbsCertificate: TBSCertificate,
        signatureAlgorithm: AlgorithmIdentifier,
        signature: ISO_8824.BitString,
        tbsCertificateBytes: ArraySlice<UInt8>,
        signatureAlgorithmBytes: ArraySlice<UInt8>,
        signatureBytes: ArraySlice<UInt8>
    ) throws(ISO_8824.Error) {
        self.tbsCertificate = tbsCertificate
        self.signatureAlgorithm = SignatureAlgorithm(algorithmIdentifier: signatureAlgorithm)
        // Decode-boundary bridge (N5 Option A): the DER.ImplicitlyTaggable conformance
        // pins throws(ISO_8824.Error), but Signature construction validates the algorithm
        // and throws Certificate.Error. Map it to the ASN.1 error, preserving the detail.
        // The typed Certificate.Error remains on the direct Signature(_:) API and at verify time.
        do {
            self.signature = try Signature(signatureAlgorithm: self.signatureAlgorithm, signatureBytes: signature)
        } catch {
            throw ISO_8824.Error.invalidASN1Object(reason: "\(error)")
        }
        self.tbsCertificateBytes = tbsCertificateBytes
        self.signatureAlgorithmBytes = signatureAlgorithmBytes
        self.signatureBytes = signatureBytes
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate: Hashable {
    @inlinable
    public static func == (lhs: Certificate, rhs: Certificate) -> Bool {
        return lhs.tbsCertificateBytes == rhs.tbsCertificateBytes
            && lhs.signatureBytes == rhs.signatureBytes
            && lhs.signatureAlgorithmBytes == rhs.signatureAlgorithmBytes
    }

    @inlinable
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.tbsCertificateBytes)
        hasher.combine(self.signatureBytes)
        hasher.combine(self.signatureAlgorithmBytes)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate: CustomStringConvertible {
    public var description: String {
        """
        Certificate(\
        version: \(String(reflecting: self.version)), \
        serialNumber: \(String(reflecting: self.serialNumber)), \
        issuer: \(String(reflecting: self.issuer)), \
        subject: \(String(reflecting: self.subject)), \
        notValidBefore: \(String(reflecting: self.notValidBefore)), \
        notValidAfter: \(String(reflecting: self.notValidAfter)), \
        publicKey: \(String(reflecting: self.publicKey)), \
        signature: \(String(reflecting: self.signature)), \
        extensions: \(String(reflecting: self.extensions))\
        )
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate: ISO_8825.DER.ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @inlinable
    public init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Certificate in
            guard let tbsCertificateNode = nodes.next(),
                let signatureAlgorithmNode = nodes.next(),
                let signatureNode = nodes.next()
            else {
                throw ISO_8824.Error.invalidASN1Object(reason: "Invalid certificate object, insufficient ASN.1 nodes")
            }
            let tbsCertificate = try TBSCertificate(derEncoded: tbsCertificateNode)
            let signatureAlgorithm = try AlgorithmIdentifier(derEncoded: signatureAlgorithmNode)
            let signature = try ISO_8824.BitString(derEncoded: signatureNode)
            return try Certificate(
                tbsCertificate: tbsCertificate,
                signatureAlgorithm: signatureAlgorithm,
                signature: signature,
                tbsCertificateBytes: tbsCertificateNode.encodedBytes,
                signatureAlgorithmBytes: signatureAlgorithmNode.encodedBytes,
                signatureBytes: signatureNode.encodedBytes
            )
        }
    }

    @inlinable
    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        coder.appendConstructedNode(identifier: identifier) { coder in
            coder.serializeRawBytes(self.tbsCertificateBytes)
            coder.serializeRawBytes(self.signatureAlgorithmBytes)
            coder.serializeRawBytes(self.signatureBytes)
        }
    }
}

extension ISO_8825.DER.Serializer {
    @inlinable
    static func serialized<Element: ISO_8825.DER.Serializable>(element: Element) throws -> [UInt8] {
        var serializer = ISO_8825.DER.Serializer()
        try serializer.serialize(element)
        return serializer.serializedBytes
    }

}

