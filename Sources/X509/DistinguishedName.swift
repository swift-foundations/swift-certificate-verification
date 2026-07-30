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

/// A distinguished name is a name that uniquely identifies a specific entity.
///
/// Distinguished names are a remnant of the X.500 directory system. In that system,
/// distinguished names were the primary key, enabling the identification of a specific entity
/// within the directory.
///
/// These use-cases are largely obsolete, but distinguished names continue to be used to identify
/// both the subject of and issuer of a given X.509 certificate. In this context, the distinguished
/// name is a largely opaque identifier that just happens to have a human-readable string representation.
///
/// The structure of a distinguished name reflects its X.500 roots. A distinguished name is conceptually
/// an ordered sequence of ``RelativeDistinguishedName``s. This sequence is conceptually ordered by hierarchy, from least
/// to most specific. Each ``RelativeDistinguishedName`` contains a collection of ``RelativeDistinguishedName/Attribute``s
/// that are intended to be equivalent representations of the same idea. In common usage, each ``RelativeDistinguishedName``
/// contains a single ``RelativeDistinguishedName/Attribute``.
///
/// As an example, the ``DistinguishedName`` that represents the Apple-operated intermediate certificate authority
/// "Apple Public EV Server RSA CA 2 - G1" is:
///
/// ```swift
/// try DistinguishedName([
///     RelativeDistinguishedName([
///         RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, printableString: "US"),
///     ]),
///     RelativeDistinguishedName([
///         RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, printableString: "Apple Inc."),
///     ]),
///     RelativeDistinguishedName([
///         RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, printableString: "Apple Public EV Server ECC CA 1 - G1"),
///     ]),
/// ])
/// ```
///
/// The ``DistinguishedName`` type models this in its full complexity.
///
/// ``DistinguishedName`` is a collection of ``RelativeDistinguishedName``, making it easy to perform generic computations
/// across the ``RelativeDistinguishedName``s that make up a full ``DistinguishedName``.
///
/// To make working with ``DistinguishedName`` easier, users have a number of convenience APIs for creating the most common
/// kinds of ``DistinguishedName``. In addition to the example above (using ``init(_:)-3no37``), users can also create distinguished
/// names that follow the "one ``RelativeDistinguishedName/Attribute`` per ``RelativeDistinguishedName``" pattern by passing
/// a sequence of ``RelativeDistinguishedName/Attribute`` directly, which will be wrapped into ``RelativeDistinguishedName``
/// objects. For example, the above ``DistinguishedName`` can also be represented by:
///
/// ```swift
/// try DistinguishedName([
///     RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, printableString: "US"),
///     RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, printableString: "Apple Inc."),
///     RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, printableString: "Apple Public EV Server ECC CA 1 - G1"),
/// ])
/// ```
///
/// This produces an identical ``DistinguishedName`` to the prior example.
public struct DistinguishedName {
    @usableFromInline
    var rdns: [RelativeDistinguishedName]

    /// Construct a ``DistinguishedName`` from a sequence of ``RelativeDistinguishedName``.
    ///
    /// - Parameter rdns: The elements of this ``DistinguishedName``.
    @inlinable
    public init<RDNSequence: Sequence>(_ rdns: RDNSequence) where RDNSequence.Element == RelativeDistinguishedName {
        self.rdns = Array(rdns)
    }

    /// Construct a ``DistinguishedName`` from a sequence of ``RelativeDistinguishedName/Attribute``.
    ///
    /// This helper initializer will wrap each ``RelativeDistinguishedName/Attribute`` in a ``RelativeDistinguishedName``
    /// transparently.
    ///
    /// - Parameter attributes: The sequence of ``RelativeDistinguishedName/Attribute``s that make up the ``DistinguishedName``.
    @inlinable
    public init<AttributeSequence: Sequence>(_ attributes: AttributeSequence) throws
    where AttributeSequence.Element == RelativeDistinguishedName.Attribute {
        self.rdns = attributes.map { RelativeDistinguishedName($0) }
    }

    /// Construct a new empty ``DistinguishedName``.
    @inlinable
    public init() {
        self.rdns = []
    }
}

extension DistinguishedName: Hashable {}

extension DistinguishedName: Sendable {}

extension DistinguishedName: RandomAccessCollection, MutableCollection, RangeReplaceableCollection {
    @inlinable
    public var startIndex: Int {
        self.rdns.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self.rdns.endIndex
    }

    @inlinable
    public subscript(position: Int) -> RelativeDistinguishedName {
        get {
            self.rdns[position]
        }
        set {
            self.rdns[position] = newValue
        }
    }

    @inlinable
    public mutating func replaceSubrange<NewElements>(_ subrange: Range<Int>, with newElements: NewElements)
    where NewElements: Collection, RelativeDistinguishedName == NewElements.Element {
        self.rdns.replaceSubrange(subrange, with: newElements)
    }
}

extension DistinguishedName: CustomStringConvertible {
    @inlinable
    public var description: String {
        self.reversed().lazy.map { String(describing: $0) }.joined(separator: ",")
    }
}

extension DistinguishedName: CustomDebugStringConvertible {
    public var debugDescription: String {
        String(reflecting: String(describing: self))
    }
}

extension DistinguishedName: ISO_8825.DER.Serializable {
    @inlinable
    public func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: .sequence) { (rootCoder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
            for element in self.rdns {
                try element.serialize(into: &rootCoder)
            }
        }
    }
}

extension DistinguishedName: ISO_8825.DER.Parseable {
    @inlinable
    public init(derEncoded rootNode: ISO_8825.Node) throws(ISO_8824.Error) {
        self.rdns = try ISO_8825.DER.sequence(of: RelativeDistinguishedName.self, identifier: .sequence, rootNode: rootNode)
    }

    @inlinable
    package static func derEncoded(
        _ sequenceNodeIterator: inout ISO_8825.Node.Collection.Iterator
    ) throws(ISO_8824.Error) -> DistinguishedName {
        // This is a workaround for the fact that, even though the conformance to ISO_8825.DER.ImplicitlyTaggable is
        // deprecated, Swift still prefers calling init(derEncoded:withIdentifier:) instead of this one.
        let dnFactory: (inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> DistinguishedName =
            DistinguishedName.init(derEncoded:)
        return try dnFactory(&sequenceNodeIterator)
    }
}

@available(*, deprecated, message: "Distinguished names may not be implicitly tagged")
extension DistinguishedName: ISO_8825.DER.ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @inlinable
    public init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self.rdns = try ISO_8825.DER.sequence(of: RelativeDistinguishedName.self, identifier: identifier, rootNode: rootNode)
    }

    @inlinable
    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (rootCoder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
            for element in self.rdns {
                try element.serialize(into: &rootCoder)
            }
        }
    }
}
