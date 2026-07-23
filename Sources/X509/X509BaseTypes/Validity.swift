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

// Validity ::= SEQUENCE {
// notBefore      Time,
// notAfter       Time  }
@usableFromInline
struct Validity: ISO_8825.DER.ImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var notBefore: Time

    @usableFromInline
    var notAfter: Time

    @inlinable
    internal init(notBefore: Time, notAfter: Time) {
        self.notBefore = notBefore
        self.notAfter = notAfter
    }

    @inlinable
    init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Validity in
            let notBefore = try Time(derEncoded: &nodes)
            let notAfter = try Time(derEncoded: &nodes)
            return Validity(notBefore: notBefore, notAfter: notAfter)
        }
    }

    @inlinable
    func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
            try coder.serialize(self.notBefore)
            try coder.serialize(self.notAfter)
        }
    }
}
