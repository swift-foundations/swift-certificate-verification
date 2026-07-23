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
/// A DirectoryString is defined as:
///
/// ```
/// DirectoryString ::= CHOICE {
///       teletexString       TeletexString   (SIZE (1..MAX)),
///       printableString     PrintableString (SIZE (1..MAX)),
///       universalString     UniversalString (SIZE (1..MAX)),
///       utf8String          UTF8String      (SIZE (1..MAX)),
///       bmpString           BMPString       (SIZE (1..MAX)) }
/// ```
///
/// Note that these upper bounds are measured in _characters_, not bytes.
///
@usableFromInline
enum DirectoryString: ISO_8825.DER.Parseable, ISO_8825.DER.Serializable, Hashable, Sendable {
    case teletexString(ISO_8824.TeletexString)
    case printableString(ISO_8824.PrintableString)
    case universalString(ISO_8824.UniversalString)
    case utf8String(ISO_8824.UTF8String)
    case bmpString(ISO_8824.BMPString)

    @inlinable
    init(derEncoded rootNode: ISO_8825.Node) throws(ISO_8824.Error) {
        switch rootNode.identifier {
        case .teletexString:
            self = .teletexString(try ISO_8824.TeletexString(derEncoded: rootNode))
        case .printableString:
            self = .printableString(try ISO_8824.PrintableString(derEncoded: rootNode))
        case .universalString:
            self = .universalString(try ISO_8824.UniversalString(derEncoded: rootNode))
        case .utf8String:
            self = .utf8String(try ISO_8824.UTF8String(derEncoded: rootNode))
        case .bmpString:
            self = .bmpString(try ISO_8824.BMPString(derEncoded: rootNode))
        default:
            throw ISO_8824.Error.unexpectedFieldType(rootNode.identifier)
        }
    }

    @inlinable
    func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .teletexString(let string):
            try string.serialize(into: &coder)
        case .printableString(let string):
            try string.serialize(into: &coder)
        case .universalString(let string):
            try string.serialize(into: &coder)
        case .utf8String(let string):
            try string.serialize(into: &coder)
        case .bmpString(let string):
            try string.serialize(into: &coder)
        }
    }
}
