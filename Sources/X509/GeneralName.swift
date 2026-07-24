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

public enum GeneralName: Hashable, Sendable, ISO_8825.DER.Parseable, ISO_8825.DER.Serializable {
    case otherName(OtherName)
    case rfc822Name(String)
    case dnsName(String)
    case x400Address(ISO_8825.`Any`)
    case directoryName(DistinguishedName)
    case ediPartyName(ISO_8825.`Any`)
    case uniformResourceIdentifier(String)
    case ipAddress(ISO_8824.OctetString)
    case registeredID(ISO_8824.ObjectIdentifier)

    @usableFromInline
    static let otherNameTag = ISO_8824.Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
    @usableFromInline
    static let rfc822NameTag = ISO_8824.Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
    @usableFromInline
    static let dnsNameTag = ISO_8824.Identifier(tagWithNumber: 2, tagClass: .contextSpecific)
    @usableFromInline
    static let x400AddressTag = ISO_8824.Identifier(tagWithNumber: 3, tagClass: .contextSpecific)
    @usableFromInline
    static let directoryNameTag = ISO_8824.Identifier(tagWithNumber: 4, tagClass: .contextSpecific)
    @usableFromInline
    static let ediPartyNameTag = ISO_8824.Identifier(tagWithNumber: 5, tagClass: .contextSpecific)
    @usableFromInline
    static let uriTag = ISO_8824.Identifier(tagWithNumber: 6, tagClass: .contextSpecific)
    @usableFromInline
    static let ipAddressTag = ISO_8824.Identifier(tagWithNumber: 7, tagClass: .contextSpecific)
    @usableFromInline
    static let registeredIDTag = ISO_8824.Identifier(tagWithNumber: 8, tagClass: .contextSpecific)

    @inlinable
    public init(derEncoded rootNode: ISO_8825.Node) throws(ISO_8824.Error) {
        switch rootNode.identifier {
        case Self.otherNameTag:
            self = try .otherName(OtherName(derEncoded: rootNode, withIdentifier: Self.otherNameTag))
        case Self.rfc822NameTag:
            let result = try ISO_8824.IA5String(derEncoded: rootNode, withIdentifier: Self.rfc822NameTag)
            self = .rfc822Name(String(result))
        case Self.dnsNameTag:
            let result = try ISO_8824.IA5String(derEncoded: rootNode, withIdentifier: Self.dnsNameTag)
            self = .dnsName(String(result))
        case Self.x400AddressTag:
            self = .x400Address(ISO_8825.`Any`(derEncoded: rootNode))
        case Self.directoryNameTag:
            self = try ISO_8825.DER.explicitlyTagged(
                rootNode,
                tagNumber: Self.directoryNameTag.tagNumber,
                tagClass: Self.directoryNameTag.tagClass
            ) { (node: ISO_8825.Node) throws(ISO_8824.Error) -> GeneralName in
                return try .directoryName(DistinguishedName(derEncoded: node))
            }
        case Self.ediPartyNameTag:
            self = .ediPartyName(ISO_8825.`Any`(derEncoded: rootNode))
        case Self.uriTag:
            let result = try ISO_8824.IA5String(derEncoded: rootNode, withIdentifier: Self.uriTag)
            self = .uniformResourceIdentifier(String(result))
        case Self.ipAddressTag:
            self = try .ipAddress(ISO_8824.OctetString(derEncoded: rootNode, withIdentifier: Self.ipAddressTag))
        case Self.registeredIDTag:
            self = try .registeredID(ISO_8824.ObjectIdentifier(derEncoded: rootNode, withIdentifier: Self.registeredIDTag))
        default:
            throw ISO_8824.Error.unexpectedFieldType(rootNode.identifier)
        }
    }

    @inlinable
    public func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .otherName(let otherName):
            try otherName.serialize(into: &coder, withIdentifier: Self.otherNameTag)
        case .rfc822Name(let name):
            let ia5String = try ISO_8824.IA5String(name)
            try ia5String.serialize(into: &coder, withIdentifier: Self.rfc822NameTag)
        case .dnsName(let name):
            let ia5String = try ISO_8824.IA5String(name)
            try ia5String.serialize(into: &coder, withIdentifier: Self.dnsNameTag)
        case .x400Address(let orAddress):
            try orAddress.serialize(into: &coder)
        case .directoryName(let name):
            try coder.serialize(name, explicitlyTaggedWithIdentifier: Self.directoryNameTag)
        case .ediPartyName(let name):
            try name.serialize(into: &coder)
        case .uniformResourceIdentifier(let name):
            let ia5String = try ISO_8824.IA5String(name)
            try ia5String.serialize(into: &coder, withIdentifier: Self.uriTag)
        case .ipAddress(let ipAddress):
            try ipAddress.serialize(into: &coder, withIdentifier: Self.ipAddressTag)
        case .registeredID(let id):
            try id.serialize(into: &coder, withIdentifier: Self.registeredIDTag)
        }
    }
}

extension GeneralName: CustomStringConvertible {
    @inlinable
    public var description: String {
        switch self {
        case .dnsName(let name):
            return "DNSName(\(String(reflecting: name)))"
        case .directoryName(let directoryName):
            return "DirectoryName(\(String(reflecting: directoryName)))"
        case .ediPartyName(let name):
            return "EDIPartyName(\(String(reflecting: name.derBytes)))"
        case .ipAddress(let address):
            return "IPAddress(\(String(reflecting: Array(address.bytes))))"
        case .otherName(let otherName):
            return "OtherName(\(String(reflecting: otherName)))"
        case .registeredID(let id):
            return "RegisteredID(\(String(reflecting: id)))"
        case .rfc822Name(let name):
            return "RFC822Name(\(String(reflecting: name)))"
        case .uniformResourceIdentifier(let uri):
            return "URI(\(String(reflecting: uri)))"
        case .x400Address(let address):
            return "X400Address(\(String(reflecting: address.derBytes)))"
        }
    }
}

extension ISO_8825.`Any` {
    /// The DER bytes this ANY wraps, recovered by re-serializing it.
    ///
    /// Every other case of ``GeneralName``'s description renders a spec-mirroring RFC 5280
    /// §4.2.1.6 CHOICE label over its payload; `ediPartyName` and `x400Address` used to
    /// render `String(reflecting:)` of the ANY itself, which leaks a *Swift* type name into
    /// a description whose job is to show the *specification* shape. Rendering the bytes
    /// bare matches `ipAddress`, three cases above, which is the same situation: an opaque
    /// octet payload inside a spec-named case.
    ///
    /// It has to be recovered by serializing rather than read directly, because
    /// ``ISO_8825/Any`` deliberately exposes no byte accessor — its documented contract is
    /// that a caller may decode it, create it, or serialize it, and nothing else. That is
    /// why the `ipAddress` precedent could not simply be copied: `ISO_8824.OctetString`
    /// publishes `bytes`, and this type does not. Serializing is the sanctioned route, and
    /// is exactly what ``GeneralName/serialize(into:withIdentifier:)`` already does for
    /// these two cases.
    @usableFromInline
    var derBytes: [UInt8] {
        var serializer = ISO_8825.DER.Serializer()
        // `Any.serialize` writes its stored bytes verbatim and has no failure path; the
        // `throws` belongs to the protocol requirement, not to this type. A description
        // must not trap or propagate, so an empty rendering is the fail-quiet answer for a
        // branch that cannot be reached.
        guard (try? self.serialize(into: &serializer)) != nil else { return [] }
        return Array(serializer.serializedBytes)
    }
}

//GeneralName ::= CHOICE {
//     otherName                       [0]     OtherName,
//     rfc822Name                      [1]     IA5String,
//     dNSName                         [2]     IA5String,
//     x400Address                     [3]     ORAddress,
//     directoryName                   [4]     Name,
//     ediPartyName                    [5]     EDIPartyName,
//     uniformResourceIdentifier       [6]     IA5String,
//     iPAddress                       [7]     OCTET STRING,
//     registeredID                    [8]     OBJECT IDENTIFIER }
//
//OtherName ::= SEQUENCE {
//     type-id    OBJECT IDENTIFIER,
//     value      [0] EXPLICIT ANY DEFINED BY type-id }
//
//EDIPartyName ::= SEQUENCE {
//     nameAssigner            [0]     DirectoryString OPTIONAL,
//     partyName               [1]     DirectoryString }

extension GeneralName {
    public struct OtherName: Hashable, Sendable, ISO_8825.DER.ImplicitlyTaggable {
        @inlinable
        public static var defaultIdentifier: ISO_8824.Identifier {
            .sequence
        }

        public var typeID: ISO_8824.ObjectIdentifier

        public var value: ISO_8825.`Any`?

        @inlinable
        public init(typeID: ISO_8824.ObjectIdentifier, value: ISO_8825.`Any`?) {
            self.typeID = typeID
            self.value = value
        }

        @inlinable
        public init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
            self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> OtherName in
                let typeID = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
                let value = try ISO_8825.DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                    ISO_8825.`Any`(derEncoded: $0)
                }

                return OtherName(typeID: typeID, value: value)
            }
        }

        @inlinable
        public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
            try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
                try coder.serialize(self.typeID)
                if let value = self.value {
                    try coder.serialize(
                        value,
                        explicitlyTaggedWithIdentifier: .init(tagWithNumber: 0, tagClass: .contextSpecific)
                    )
                }
            }
        }
    }
}

extension GeneralName.OtherName: CustomStringConvertible {
    @inlinable
    public var description: String {
        "\(self.typeID): \(String(reflecting: self.value))"
    }
}

@usableFromInline
struct GeneralNames: ISO_8825.DER.ImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var names: [GeneralName]

    @inlinable
    init(_ names: [GeneralName]) {
        self.names = names
    }

    @inlinable
    init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self.names = try ISO_8825.DER.sequence(of: GeneralName.self, identifier: identifier, rootNode: rootNode)
    }

    @inlinable
    func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
            for name in names {
                try coder.serialize(name)
            }
        }
    }
}
