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

// TBSCertificate  ::=  SEQUENCE  {
//      version         [0]  Version DEFAULT v1,
//      serialNumber         CertificateSerialNumber,
//      signature            AlgorithmIdentifier,
//      issuer               Name,
//      validity             Validity,
//      subject              Name,
//      subjectPublicKeyInfo SubjectPublicKeyInfo,
//      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                           -- If present, version MUST be v2 or v3
//      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                           -- If present, version MUST be v2 or v3
//      extensions      [3]  Extensions OPTIONAL
//                           -- If present, version MUST be v3 --  }
//
// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
//
// CertificateSerialNumber  ::=  INTEGER
//
// UniqueIdentifier  ::=  BIT STRING
//
// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
@usableFromInline
typealias UniqueIdentifier = ISO_8824.BitString

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
@usableFromInline
package struct TBSCertificate: ISO_8825.DER.ImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    package static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var version: Certificate.Version

    @usableFromInline
    var serialNumber: Certificate.SerialNumber

    @usableFromInline
    var signature: Certificate.SignatureAlgorithm

    @usableFromInline
    var issuer: DistinguishedName

    @usableFromInline
    var validity: Validity

    @usableFromInline
    var subject: DistinguishedName

    @usableFromInline
    var publicKey: Certificate.PublicKey

    @usableFromInline
    var issuerUniqueID: UniqueIdentifier?

    @usableFromInline
    var subjectUniqueID: UniqueIdentifier?

    @usableFromInline
    var extensions: Certificate.Extensions

    @inlinable
    internal init(
        version: Certificate.Version,
        serialNumber: Certificate.SerialNumber,
        signature: Certificate.SignatureAlgorithm,
        issuer: DistinguishedName,
        validity: Validity,
        subject: DistinguishedName,
        publicKey: Certificate.PublicKey,
        issuerUniqueID: UniqueIdentifier? = nil,
        subjectUniqueID: UniqueIdentifier? = nil,
        extensions: Certificate.Extensions
    ) {
        self.version = version
        self.serialNumber = serialNumber
        self.signature = signature
        self.issuer = issuer
        self.validity = validity
        self.subject = subject
        self.publicKey = publicKey
        self.issuerUniqueID = issuerUniqueID
        self.subjectUniqueID = subjectUniqueID
        self.extensions = extensions
    }

    @inlinable
    package init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> TBSCertificate in
            let version = try ISO_8825.DER.decodeDefaultExplicitlyTagged(
                &nodes,
                tagNumber: 0,
                tagClass: .contextSpecific,
                defaultValue: Int(0)
            )
            guard (0...2).contains(version) else {
                throw ISO_8824.Error.invalidASN1Object(reason: "Invalid X.509 version \(version)")
            }

            let serialNumber = try ArraySlice<UInt8>(derEncoded: &nodes)
            let signature = try AlgorithmIdentifier(derEncoded: &nodes)
            let issuer = try DistinguishedName.derEncoded(&nodes)
            let validity = try Validity(derEncoded: &nodes)
            let subject = try DistinguishedName.derEncoded(&nodes)
            let subjectPublicKeyInfo = try SubjectPublicKeyInfo(derEncoded: &nodes)
            let issuerUniqueID = try ISO_8825.DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                (node: ISO_8825.Node) throws(ISO_8824.Error) -> UniqueIdentifier in
                try UniqueIdentifier(derEncoded: node)
            }
            let subjectUniqueID = try ISO_8825.DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                (node: ISO_8825.Node) throws(ISO_8824.Error) -> UniqueIdentifier in
                try UniqueIdentifier(derEncoded: node)
            }
            let extensions = try ISO_8825.DER.optionalExplicitlyTagged(&nodes, tagNumber: 3, tagClass: .contextSpecific) {
                (node: ISO_8825.Node) throws(ISO_8824.Error) -> [Certificate.Extension] in
                try ISO_8825.DER.sequence(of: Certificate.Extension.self, identifier: .sequence, rootNode: node)
            }

            // Decode-boundary bridge (N5 Option A): the DER.ImplicitlyTaggable conformance
            // pins throws(ISO_8824.Error), but PublicKey(spki:) and Extensions(_:) validate
            // (unsupported key algorithm, duplicate extension OID) and throw Certificate.Error.
            // Map those to the ASN.1 error, preserving the detail; the typed Certificate.Error
            // remains on the direct PublicKey(spki:)/Extensions(_:) APIs and at verify time.
            // Catch-all (not just Certificate.Error): PublicKey(spki:) also surfaces
            // crypto-backend errors on malformed key bytes. All are decode-boundary
            // failures → map to the ASN.1 error, preserving the detail in the reason.
            let publicKey: Certificate.PublicKey
            do {
                publicKey = try Certificate.PublicKey(spki: subjectPublicKeyInfo)
            } catch {
                throw ISO_8824.Error.invalidASN1Object(reason: "\(error)")
            }
            let parsedExtensions: Certificate.Extensions
            do {
                parsedExtensions = try Certificate.Extensions(extensions ?? [])
            } catch {
                throw ISO_8824.Error.invalidASN1Object(reason: "\(error)")
            }
            return TBSCertificate(
                version: Certificate.Version(rawValue: version),
                serialNumber: Certificate.SerialNumber(bytes: serialNumber),
                signature: Certificate.SignatureAlgorithm(algorithmIdentifier: signature),
                issuer: issuer,
                validity: validity,
                subject: subject,
                publicKey: publicKey,
                issuerUniqueID: issuerUniqueID,
                subjectUniqueID: subjectUniqueID,
                extensions: parsedExtensions
            )
        }
    }

    @inlinable
    package func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
            if self.version != .v1 {
                try coder.serialize(self.version.rawValue, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            try coder.serialize(self.serialNumber.bytes)
            try coder.serialize(AlgorithmIdentifier(self.signature))
            try coder.serialize(self.issuer)
            try coder.serialize(self.validity)
            try coder.serialize(self.subject)
            try coder.serialize(SubjectPublicKeyInfo(self.publicKey))
            if let issuerUniqueID = self.issuerUniqueID {
                try coder.serialize(issuerUniqueID, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
            }
            if let subjectUniqueID = self.subjectUniqueID {
                try coder.serialize(subjectUniqueID, explicitlyTaggedWithTagNumber: 2, tagClass: .contextSpecific)
            }
            if self.extensions.count > 0 {
                try coder.serialize(explicitlyTaggedWithTagNumber: 3, tagClass: .contextSpecific) {
                    (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
                    try coder.serializeSequenceOf(extensions)
                }
            }
        }
    }
}
