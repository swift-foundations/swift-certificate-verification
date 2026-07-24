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
    /// An abstract representation of the cryptographic signature on a certificate.
    ///
    /// Certificates may have a wide range of signature types. This type provides a runtime
    /// abstraction across these types. It ensures that we understand the algorithm used to
    /// sign the certificate, and enables us to provide verification logic, without forcing
    /// users to wrestle with the wide variety of runtime types that may represent a
    /// signature.
    ///
    /// This type is almost entirely opaque. It is validated by the injected
    /// ``Certificate/Verify`` witness, which reconstructs whatever signature type its
    /// backend requires from ``rawRepresentation``. Otherwise, this type has essentially
    /// no behaviours.
    public struct Signature {
        @usableFromInline
        var backing: BackingSignature

        @inlinable
        internal init(backing: BackingSignature) {
            self.backing = backing
        }

        @inlinable
        public init(signatureAlgorithm: SignatureAlgorithm, signatureBytes: ISO_8824.BitString) throws {
            switch signatureAlgorithm {
            case .ecdsaWithSHA256, .ecdsaWithSHA384, .ecdsaWithSHA512:
                let signature = try ECDSASignature(derEncoded: signatureBytes.bytes)
                self.backing = .ecdsa(signature)
            case .ed25519:
                guard signatureBytes.paddingBits == 0 else {
                    throw Certificate.Error.signature(
                        .invalidEncoding(reason: "no padding bits are allowed on Ed25519 signatures")
                    )
                }
                self.backing = .ed25519(Array(signatureBytes.bytes))
            default:
                throw Certificate.Error.algorithm(
                    .unsupportedSignature(AlgorithmIdentifier(signatureAlgorithm).algorithm)
                )
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature: CustomStringConvertible {
    public var description: String {
        switch backing {
        case .ecdsa:
            return "ECDSA"
        case .ed25519:
            return "Ed25519"
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature {
    /// The signature as the model holds it: a decoded DER `r`/`s` pair for ECDSA, and
    /// the raw signature octets for Ed25519.
    ///
    /// `ECDSASignature` is this module's own DER type, not a backend type — holding it
    /// keeps the module free of a cryptographic dependency.
    @usableFromInline
    enum BackingSignature: Hashable, Sendable {
        case ecdsa(ECDSASignature)
        case ed25519([UInt8])

        @inlinable
        static func == (lhs: BackingSignature, rhs: BackingSignature) -> Bool {
            switch (lhs, rhs) {
            case (.ecdsa(let l), .ecdsa(let r)):
                return l == r
            case (.ed25519(let l), .ed25519(let r)):
                return l == r
            default:
                return false
            }
        }

        @inlinable
        func hash(into hasher: inout Hasher) {
            switch self {
            case .ecdsa(let sig):
                hasher.combine(0)
                hasher.combine(sig)
            case .ed25519(let sig):
                hasher.combine(2)
                hasher.combine(sig)
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature {
    /// The raw byte representation of the signature.
    @inlinable
    public var rawRepresentation: [UInt8] {
        switch self.backing {
        case .ecdsa(let sig):
            var serializer = ISO_8825.DER.Serializer()
            try! serializer.serialize(sig)
            return serializer.serializedBytes
        case .ed25519(let bytes):
            return bytes
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ISO_8824.BitString {
    @inlinable
    init(_ signature: Certificate.Signature) {
        self.init(bytes: signature.rawRepresentation[...])
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ISO_8824.OctetString {
    @inlinable
    init(_ signature: Certificate.Signature) {
        switch signature.backing {
        case .ecdsa(let sig):
            var serializer = ISO_8825.DER.Serializer()
            try! serializer.serialize(sig)
            self = ISO_8824.OctetString(contentBytes: serializer.serializedBytes[...])
        case .ed25519(let sig):
            self = ISO_8824.OctetString(contentBytes: sig[...])
        }
    }
}
