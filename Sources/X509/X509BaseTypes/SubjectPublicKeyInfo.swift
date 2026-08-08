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

@usableFromInline
package struct SubjectPublicKeyInfo: ISO_8825.DER.ImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    package static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var algorithmIdentifier: AlgorithmIdentifier

    @usableFromInline
    var key: ISO_8824.BitString

    @inlinable
    package init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        // The SPKI block looks like this:
        //
        // SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //   algorithm         AlgorithmIdentifier,
        //   subjectPublicKey  BIT STRING
        // }
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> SubjectPublicKeyInfo in
            let algorithmIdentifier = try AlgorithmIdentifier(derEncoded: &nodes)
            let key = try ISO_8824.BitString(derEncoded: &nodes)

            return SubjectPublicKeyInfo(algorithmIdentifier: algorithmIdentifier, key: key)
        }
    }

    @inlinable
    package init(algorithmIdentifier: AlgorithmIdentifier, key: ISO_8824.BitString) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }

    @inlinable
    package init(algorithmIdentifier: AlgorithmIdentifier, key: [UInt8]) {
        self.algorithmIdentifier = algorithmIdentifier
        // paddingBits defaults to 0, which `_validate()` can never reject (see
        // ISO_8824.BitString._validate(): the only failure modes require a nonzero,
        // out-of-range, or byte-content-inconsistent padding count) — safe to force-try
        // rather than widen this initializer's signature with `throws`.
        self.key = try! ISO_8824.BitString(bytes: key[...])
    }

    @inlinable
    package func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
            try coder.serialize(self.algorithmIdentifier)
            try coder.serialize(self.key)
        }
    }
}
