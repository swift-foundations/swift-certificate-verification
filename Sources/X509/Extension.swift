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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// A general-purpose representation of a specific X.509 extension.
    ///
    /// X.509 extensions are a general representation, with three properties: an identifier, a critical flag, and the encoded value.
    /// The specific data contained in the encoded value is determined by the value of the identifier stored in ``oid``.
    ///
    /// This value enables ``Certificate/Extensions-swift.struct`` to store the value of all extensions in a certificate, even ones
    /// it does not understand. A number of extensions have built-in support, and can be decoded directly from an ``Extension``
    /// value. These are:
    ///
    /// - ``AuthorityInformationAccess``
    /// - ``AuthorityKeyIdentifier``
    /// - ``BasicConstraints``
    /// - ``ExtendedKeyUsage``
    /// - ``KeyUsage``
    /// - ``NameConstraints``
    /// - ``SubjectAlternativeNames``
    /// - ``SubjectKeyIdentifier``
    ///
    /// Users can write their own types by using a similar approach to these types, when it is necessary to add support for
    /// different X.509 extension.
    public struct Extension {
        /// The identifier for this extension type.
        ///
        /// Common values are stored in `ISO_8824.ObjectIdentifier.X509ExtensionID`.
        public var oid: ISO_8824.ObjectIdentifier

        /// Whether this extension must be processed in order to trust the certificate.
        ///
        /// If the code processing this ``Certificate`` does not understand this extension, the certificate
        /// must not be trusted.
        public var critical: Bool

        /// The encoded bytes of the value of this extension.
        ///
        /// This value should be decoded based on the value of ``oid``.
        public var value: ArraySlice<UInt8>

        /// Construct a new extension from its constituent parts.
        ///
        /// - Parameters:
        ///   - oid: The identifier for this extension type.
        ///   - critical: Whether this extension must be processed in order to trust the certificate.
        ///   - value: The encoded bytes of the value of this extension.
        @inlinable
        public init(oid: ISO_8824.ObjectIdentifier, critical: Bool, value: ArraySlice<UInt8>) {
            self.oid = oid
            self.critical = critical
            self.value = value
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension: CustomStringConvertible {
    public var description: String {
        // Probes: an extension that does not decode as a known type falls through
        // to the opaque rendering; decode failure is not an error here.
        do { return String(reflecting: try AuthorityInformationAccess(self)) } catch {}
        do { return String(reflecting: try SubjectKeyIdentifier(self)) } catch {}
        do { return String(reflecting: try AuthorityKeyIdentifier(self)) } catch {}
        do { return String(reflecting: try ExtendedKeyUsage(self)) } catch {}
        do { return String(reflecting: try BasicConstraints(self)) } catch {}
        do { return String(reflecting: try KeyUsage(self)) } catch {}
        do { return String(reflecting: try NameConstraints(self)) } catch {}
        do { return String(reflecting: try SubjectAlternativeNames(self)) } catch {}
        return """
            Extension(\
            oid: \(String(reflecting: self.oid)), \
            critical: \(String(reflecting: self.critical)), \
            value: \(self.value.count) bytes\
            )
            """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension: ISO_8825.DER.ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @inlinable
    public init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> Certificate.Extension in
            let extensionID = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)
            let critical = try ISO_8825.DER.decodeDefault(&nodes, defaultValue: false)
            let value = try ISO_8824.OctetString(derEncoded: &nodes)

            return Certificate.Extension(oid: extensionID, critical: critical, value: value.bytes)
        }
    }

    @inlinable
    public func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
            try coder.serialize(self.oid)

            if self.critical {
                try coder.serialize(self.critical)
            }

            try coder.serialize(ISO_8824.OctetString(contentBytes: self.value))
        }
    }
}
