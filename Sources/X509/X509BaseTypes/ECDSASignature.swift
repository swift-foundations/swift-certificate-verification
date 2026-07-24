//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
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

/// An ECDSA signature is laid out as follows:
///
/// ECDSASignature ::= SEQUENCE {
///   r INTEGER,
///   s INTEGER
/// }
///
/// We define this type here because an X.509 certificate may have an ECDSA signature
/// in it without reference to what key created it. We need to be able to store it
/// abstractly, and then turn it into the signature type we need on request.
@usableFromInline
struct ECDSASignature: ISO_8825.DER.ImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var r: ArraySlice<UInt8>

    @usableFromInline
    var s: ArraySlice<UInt8>

    @inlinable
    init(r: ArraySlice<UInt8>, s: ArraySlice<UInt8>) {
        self.r = r
        self.s = s
    }

    @inlinable
    init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> ECDSASignature in
            let r = try ArraySlice<UInt8>(derEncoded: &nodes)
            let s = try ArraySlice<UInt8>(derEncoded: &nodes)

            return ECDSASignature(r: r, s: s)
        }
    }

    @inlinable
    func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
            try coder.serialize(self.r)
            try coder.serialize(self.s)
        }
    }

    /// Build the DER `r`/`s` pair from a fixed-width raw ECDSA signature — the `r || s`
    /// concatenation, each half padded to the curve's coordinate width.
    @inlinable
    init(rawSignatureBytes raw: [UInt8]) {
        let half = raw.count / 2
        let r = ArraySlice(normalisingToASN1IntegerForm: raw.prefix(upTo: half))
        let s = ArraySlice(normalisingToASN1IntegerForm: raw.suffix(from: half))

        self = ECDSASignature(r: r, s: s)
    }
}

extension ArraySlice where Element == UInt8 {
    /// Normalizes a sequence of bytes that represent an unsigned big endian raw integer into the
    /// form we'd get from decoding an ASN1 integer.
    ///
    /// This means we strip leading zero bytes.
    @inlinable
    init<Bytes: Collection>(normalisingToASN1IntegerForm bigEndianRawInteger: Bytes) where Bytes.Element == UInt8 {
        let realBytes = bigEndianRawInteger.drop(while: { $0 == 0 })
        self = ArraySlice(realBytes)
    }

    @inlinable
    init(normalisingToASN1IntegerForm bigEndianRawInteger: ArraySlice<UInt8>) {
        self = bigEndianRawInteger.drop(while: { $0 == 0 })
    }

    @inlinable
    init(normalisingToASN1IntegerForm bigEndianRawInteger: [UInt8]) {
        self.init(normalisingToASN1IntegerForm: bigEndianRawInteger[...])
    }
}
