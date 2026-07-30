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

extension RelativeDistinguishedName {
    /// A single attribute of a ``RelativeDistinguishedName``.
    ///
    /// A ``RelativeDistinguishedName`` is made up of one or more attributes that represent the same
    /// node in the hierarchical ``DistinguishedName`` representation. In almost all cases there is
    /// only one ``Attribute`` in a given ``RelativeDistinguishedName``.
    ///
    /// These attributes are a key-value type, with the type of the node being identified by
    /// ``type`` and the value being stored in ``value``. In the vast majority of cases the ``value``
    /// of the node will be an `ISO_8824.PrintableString` or `ISO_8824.UTF8String`, but the value can only
    /// be derived by inspection.
    public struct Attribute {
        public struct Value: Hashable, Sendable {
            @usableFromInline
            enum Storage: Hashable, Sendable {
                /// ``ISO_8824.PrintableString``
                case printable(String)
                /// ``ISO_8824.UTF8String``
                case utf8(String)
                /// ``ISO_8824.IA5String``
                case ia5(String)
                /// `.any` can never contain bytes which are equal to the DER representation of `.printable`, `.utf8` or `.ia5`.
                /// This invariant must not be violated or otherwise the synthesised `Hashable` would be wrong.
                case any(ISO_8825.`Any`)
            }

            @usableFromInline
            var storage: Storage

            @inlinable
            init(storage: Storage) {
                self.storage = storage
            }
        }
        /// The type of this attribute.
        ///
        /// Common types can be found in `ISO_8824.ObjectIdentifier.RDNAttributeType`.
        public var type: ISO_8824.ObjectIdentifier

        /// The value of this attribute.
        public var value: Attribute.Value

        /// Create a new attribute from a given type and value.
        ///
        /// - Parameter type: The type of the attribute.
        /// - Parameter value: The value of the attribute.
        @inlinable
        public init(type: ISO_8824.ObjectIdentifier, value: Attribute.Value) {
            self.type = type
            self.value = value
        }
    }
}

extension ISO_8825.`Any` {
    @inlinable
    init(_ storage: RelativeDistinguishedName.Attribute.Value.Storage) {
        switch storage {
        case .printable(let printableString):
            // force try is safe because we verify in the initialiser that it is valid
            self = try! .init(erasing: ISO_8824.PrintableString(printableString))
        case .utf8(let utf8String):
            // force try is safe because we verify in the initialiser that it is valid
            self = try! .init(erasing: ISO_8824.UTF8String(utf8String))
        case .ia5(let ia5String):
            // force try is safe because we verify in the initialiser that it is valid
            self = try! .init(erasing: ISO_8824.IA5String(ia5String))
        case .any(let any):
            self = any
        }
    }
}

extension ISO_8825.`Any` {
    @inlinable
    public init(_ value: RelativeDistinguishedName.Attribute.Value) {
        self = ISO_8825.`Any`(value.storage)
    }
}

extension RelativeDistinguishedName.Attribute.Value {
    /// A helper constructor to construct a ``RelativeDistinguishedName/Attribute/Value`` with an `ISO_8824.UTF8String`.
    /// - Parameter utf8String: The value of the attribute.
    @inlinable
    public init(utf8String: String) {
        self.storage = .utf8(utf8String)
    }

    /// A helper constructor to construct a ``RelativeDistinguishedName/Attribute/Value`` with an `ISO_8824.PrintableString`.
    /// - Parameter printableString: The value of the attribute.
    @inlinable
    public init(printableString: String) throws {
        // verify that it is indeed a printable string
        _ = try ISO_8824.PrintableString(printableString)
        self.storage = .printable(printableString)
    }

    /// A helper constructor to construct a ``RelativeDistinguishedName/Attribute/Value`` with an `ISO_8824.IA5String`.
    @inlinable
    public init(ia5String: String) throws {
        // verify that it is indeed a ISO_8824.IA5String
        _ = try ISO_8824.IA5String(ia5String)
        self.storage = .ia5(ia5String)
    }

    @inlinable
    public init(asn1Any: ISO_8825.`Any`) {
        do {
            self.storage = try .init(asn1Any: asn1Any)
        } catch {
            self.storage = .any(asn1Any)
        }
    }
}

extension RelativeDistinguishedName.Attribute.Value.Storage: ISO_8825.DER.Parseable, ISO_8825.DER.Serializable {
    @inlinable
    init(derEncoded node: ISO_8825.Node) throws(ISO_8824.Error) {
        do {
            switch node.identifier {
            case ISO_8824.UTF8String.defaultIdentifier:
                self = .utf8(String(try ISO_8824.UTF8String(derEncoded: node)))
            case ISO_8824.PrintableString.defaultIdentifier:
                self = .printable(String(try ISO_8824.PrintableString(derEncoded: node)))
            case ISO_8824.IA5String.defaultIdentifier:
                self = .ia5(String(try ISO_8824.IA5String(derEncoded: node)))
            default:
                self = .any(ISO_8825.`Any`(derEncoded: node))
            }
        } catch {
            self = .any(ISO_8825.`Any`(derEncoded: node))
        }
    }

    @inlinable
    func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .printable(let printableString):
            // force try is safe because we verify in the initialiser that it is valid
            let printableString = try! ISO_8824.PrintableString(printableString)
            try printableString.serialize(into: &coder)
        case .utf8(let utf8String):
            let string = ISO_8824.UTF8String(utf8String)
            try string.serialize(into: &coder)
        case .ia5(let ia5String):
            // force try is safe because we verify in the initialiser that it is valid
            let string = try! ISO_8824.IA5String(ia5String)
            try string.serialize(into: &coder)
        case .any(let any):
            try any.serialize(into: &coder)
        }
    }
}

extension RelativeDistinguishedName.Attribute.Value: CustomStringConvertible {
    @inlinable
    public var description: String {
        let text: String
        if let string = String(self) {
            text = string
        } else {
            text = String(describing: ISO_8825.`Any`(self))
        }

        // This is a very slow way to do this, but until we have any evidence that
        // this is hot code I'm happy to do it slowly.
        let unescapedBytes = Array(text.utf8)
        let charsToEscape: [UInt8] = [
            UInt8(ascii: "," as Unicode.Scalar), UInt8(ascii: "+" as Unicode.Scalar), UInt8(ascii: "\"" as Unicode.Scalar), UInt8(ascii: "\\" as Unicode.Scalar),
            UInt8(ascii: "<" as Unicode.Scalar), UInt8(ascii: ">" as Unicode.Scalar), UInt8(ascii: ";" as Unicode.Scalar),
        ]

        let leadingBytesToEscape = unescapedBytes.prefix(while: {
            $0 == UInt8(ascii: " " as Unicode.Scalar) || $0 == UInt8(ascii: "#" as Unicode.Scalar)
        })

        // We don't want these ranges to overlap.
        let trailingBytesToEscape = unescapedBytes.dropFirst(leadingBytesToEscape.count).suffix(while: {
            $0 == UInt8(ascii: " " as Unicode.Scalar)
        })
        let middleBytes = unescapedBytes[leadingBytesToEscape.endIndex..<trailingBytesToEscape.startIndex]

        var escapedBytes = leadingBytesToEscape.flatMap { [UInt8(ascii: "\\" as Unicode.Scalar), $0] }
        escapedBytes += middleBytes.flatMap {
            guard charsToEscape.contains($0) else {
                return [$0]
            }
            return [UInt8(ascii: "\\" as Unicode.Scalar), $0]
        }
        escapedBytes += trailingBytesToEscape.flatMap { [UInt8(ascii: "\\" as Unicode.Scalar), $0] }

        let escapedString = String(decoding: escapedBytes, as: UTF8.self)
        return escapedString
    }
}

extension RelativeDistinguishedName.Attribute.Value: CustomDebugStringConvertible {
    public var debugDescription: String {
        String(reflecting: String(describing: self))
    }
}

extension RelativeDistinguishedName.Attribute: Hashable {}

extension RelativeDistinguishedName.Attribute: Sendable {}

extension RelativeDistinguishedName.Attribute: CustomStringConvertible {
    @inlinable
    public var description: String {
        let attributeKey: String
        switch self.type {
        case .RDNAttributeType.commonName:
            attributeKey = "CN"
        case .RDNAttributeType.countryName:
            attributeKey = "C"
        case .RDNAttributeType.localityName:
            attributeKey = "L"
        case .RDNAttributeType.stateOrProvinceName:
            attributeKey = "ST"
        case .RDNAttributeType.organizationName:
            attributeKey = "O"
        case .RDNAttributeType.organizationalUnitName:
            attributeKey = "OU"
        case .RDNAttributeType.streetAddress:
            attributeKey = "STREET"
        case .RDNAttributeType.domainComponent:
            attributeKey = "DC"
        case .RDNAttributeType.emailAddress:
            attributeKey = "E"
        case let type:
            attributeKey = String(describing: type)
        }

        return "\(attributeKey)=\(value)"
    }
}

extension RelativeDistinguishedName.Attribute: ISO_8825.DER.ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @inlinable
    public init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> RelativeDistinguishedName.Attribute in
            let type = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            let value = try Value(storage: .init(derEncoded: &nodes))
            return .init(type: type, value: value)
        }
    }

    @inlinable
    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
            try coder.serialize(self.type)
            try coder.serialize(self.value.storage)
        }
    }
}

extension RelativeDistinguishedName.Attribute {
    /// A helper constructor to construct a ``RelativeDistinguishedName/Attribute`` whose
    /// value is an `ISO_8824.UTF8String`.
    ///
    /// - Parameter type: The type of the attribute.
    /// - Parameter utf8String: The value of the attribute.
    @inlinable
    public init(type: ISO_8824.ObjectIdentifier, utf8String: String) {
        self.type = type
        self.value = .init(utf8String: utf8String)
    }

    /// A helper constructor to construct a ``RelativeDistinguishedName/Attribute`` whose
    /// value is an `ISO_8824.PrintableString`.
    ///
    /// - Parameter type: The type of the attribute.
    /// - Parameter printableString: The value of the attribute.
    @inlinable
    public init(type: ISO_8824.ObjectIdentifier, printableString: String) throws {
        self.type = type
        self.value = try .init(printableString: printableString)
    }

    @inlinable
    public init(type: ISO_8824.ObjectIdentifier, ia5String: String) throws {
        self.type = type
        self.value = try .init(ia5String: ia5String)
    }

    /// Create a new attribute from a given type and value.
    ///
    /// - Parameter type: The type of the attribute.
    /// - Parameter value: The value of the attribute, wrapped in `ISO_8825.`Any``.
    @inlinable
    public init(type: ISO_8824.ObjectIdentifier, value: ISO_8825.`Any`) {
        self.type = type
        self.value = .init(asn1Any: value)
    }
}

extension ISO_8824.ObjectIdentifier {
    /// Common object identifiers used within ``RelativeDistinguishedName/Attribute``s.
    public enum RDNAttributeType: Sendable {
        /// The 'countryName' attribute type contains a two-letter
        /// ISO 3166 country code.
        public static let countryName: ISO_8824.ObjectIdentifier = [2, 5, 4, 6]

        /// The 'commonName' attribute type contains names of an
        /// object.
        public static let commonName: ISO_8824.ObjectIdentifier = [2, 5, 4, 3]

        /// The 'localityName' attribute type contains names of a
        /// locality or place, such as a city, county, or other geographic
        /// region.
        public static let localityName: ISO_8824.ObjectIdentifier = [2, 5, 4, 7]

        /// The 'stateOrProvinceName' attribute type contains the
        /// full names of states or provinces.
        public static let stateOrProvinceName: ISO_8824.ObjectIdentifier = [2, 5, 4, 8]

        /// The 'organizationName' attribute type contains the
        /// names of an organization.
        public static let organizationName: ISO_8824.ObjectIdentifier = [2, 5, 4, 10]

        /// The 'organizationalUnitName' attribute type contains
        /// the names of an organizational unit.
        public static let organizationalUnitName: ISO_8824.ObjectIdentifier = [2, 5, 4, 11]

        /// The 'streetAddress' attribute type contains site
        /// information from a postal address (i.e., the street name, place,
        /// avenue, and the house number).
        public static let streetAddress: ISO_8824.ObjectIdentifier = [2, 5, 4, 9]

        /// The `domainComponent` attribute type contains parts (labels) of a DNS domain name
        public static let domainComponent: ISO_8824.ObjectIdentifier = [0, 9, 2342, 19_200_300, 100, 1, 25]

        /// The `emailAddress` attribute type contains email address defined in PCKS#9 (RFC2985).
        /// Be aware that, modern best practices (e.g., RFC 5280) discourage embedding email addresses in the `Subject DN` instead it should be in  `Subject Alternative Name (SAN)
        public static let emailAddress: ISO_8824.ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 1]
    }
}

extension String {
    /// Extract the textual representation of a given ``RelativeDistinguishedName/Attribute/Value-swift.struct``.
    ///
    /// Returns `nil` if the value is not a printable or UTF8 string.
    public init?(_ value: RelativeDistinguishedName.Attribute.Value) {
        switch value.storage {
        case .printable(let printable):
            self = printable
        case .utf8(let utf8):
            self = utf8
        case .ia5(let ia5):
            self = ia5
        case .any:
            return nil
        }
    }
}

extension RandomAccessCollection {
    @inlinable
    package func suffix(while predicate: (Element) -> Bool) -> SubSequence {
        var index = self.endIndex
        if index == self.startIndex {
            return self[...]
        }

        repeat {
            self.formIndex(before: &index)
            if !predicate(self[index]) {
                self.formIndex(after: &index)
                break
            }
        } while index != self.startIndex

        return self[index..<self.endIndex]
    }
}
