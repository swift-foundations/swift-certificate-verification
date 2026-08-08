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
    /// A public key that can be used with a certificate.
    ///
    /// This type is a *model* of a public key: an algorithm plus the key's canonical
    /// bytes. It performs no cryptography and wraps no cryptographic key object, so
    /// this module needs no cryptographic backend to parse, hold, compare, or
    /// re-serialize a certificate's key. Cryptographic use of the key happens through
    /// the injected ``Certificate/Verify`` witness, which reconstructs whatever key
    /// type its backend requires from ``subjectPublicKeyInfoBytes``.
    public struct PublicKey {
        @usableFromInline
        var backing: BackingPublicKey

        @inlinable
        package init(spki: SubjectPublicKeyInfo) throws {
            switch spki.algorithmIdentifier {
            case .p256PublicKey:
                guard spki.key.bytes.count == Certificate.PublicKey.p256X963ByteCount else {
                    throw Certificate.Error.algorithm(.unsupportedPublicKey(spki.algorithmIdentifier.algorithm))
                }
                self.backing = .p256(x963: Array(spki.key.bytes))
            case .p384PublicKey:
                guard spki.key.bytes.count == Certificate.PublicKey.p384X963ByteCount else {
                    throw Certificate.Error.algorithm(.unsupportedPublicKey(spki.algorithmIdentifier.algorithm))
                }
                self.backing = .p384(x963: Array(spki.key.bytes))
            case .p521PublicKey:
                guard spki.key.bytes.count == Certificate.PublicKey.p521X963ByteCount else {
                    throw Certificate.Error.algorithm(.unsupportedPublicKey(spki.algorithmIdentifier.algorithm))
                }
                self.backing = .p521(x963: Array(spki.key.bytes))
            case .ed25519:
                guard spki.key.bytes.count == Certificate.PublicKey.ed25519RawByteCount else {
                    throw Certificate.Error.algorithm(.unsupportedPublicKey(spki.algorithmIdentifier.algorithm))
                }
                self.backing = .ed25519(raw: Array(spki.key.bytes))
            default:
                throw Certificate.Error.algorithm(.unsupportedPublicKey(spki.algorithmIdentifier.algorithm))
            }
        }

        @inlinable
        internal init(backing: BackingPublicKey) {
            self.backing = backing
        }
    }
}

// MARK: Key-length validation

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey {
    // Why lengths are checked here at all:
    //
    // Before this type became algorithm-plus-bytes, constructing a backend key object
    // validated the encoding implicitly, and a malformed key was rejected at parse. The
    // model must not silently lose that. A byte count is arithmetic on an encoding, not
    // cryptography, so re-asserting it costs this module no cryptographic dependency —
    // and it keeps parsing fail-closed, so a malformed key is rejected where the
    // algorithm identifier that gives it meaning is still in hand, rather than travelling
    // deeper and failing later where the failure is far harder to attribute.
    //
    // These are the sizes fixed by the specifications, not tuning parameters. Each is
    // recorded with its source so that a later reader cannot mistake it for a magic
    // number and "simplify" it.

    /// Length of an uncompressed X9.63 P-256 point: the `0x04` uncompressed-form tag
    /// followed by the 32-byte `x` and 32-byte `y` coordinates.
    ///
    /// Source: SEC 1 v2.0 §2.3.3 (Elliptic-Curve-Point-to-Octet-String Conversion),
    /// uncompressed form, with a 32-byte field element for the P-256 curve.
    @usableFromInline
    static let p256X963ByteCount = 1 + 32 + 32  // 65

    /// Length of an uncompressed X9.63 P-384 point: the `0x04` uncompressed-form tag
    /// followed by the 48-byte `x` and 48-byte `y` coordinates.
    ///
    /// Source: SEC 1 v2.0 §2.3.3, uncompressed form, 48-byte field element (P-384).
    @usableFromInline
    static let p384X963ByteCount = 1 + 48 + 48  // 97

    /// Length of an uncompressed X9.63 P-521 point: the `0x04` uncompressed-form tag
    /// followed by the 66-byte `x` and 66-byte `y` coordinates.
    ///
    /// Source: SEC 1 v2.0 §2.3.3, uncompressed form, 66-byte field element (P-521 —
    /// 521 bits rounded up to whole octets).
    @usableFromInline
    static let p521X963ByteCount = 1 + 66 + 66  // 133

    /// Length of an Ed25519 raw public key.
    ///
    /// Source: RFC 8032 §5.1.5 (Ed25519 Key Generation) — the public key is the
    /// 32-octet encoding of the point `A`.
    @usableFromInline
    static let ed25519RawByteCount = 32
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: CustomStringConvertible {
    public var description: String {
        switch self.backing {
        case .p256:
            return "P256.PublicKey"
        case .p384:
            return "P384.PublicKey"
        case .p521:
            return "P521.PublicKey"
        case .ed25519:
            return "Ed25519.PublicKey"
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey {
    /// The algorithm of the key, paired with the key's canonical bytes.
    ///
    /// The payload is the same encoding the certificate carried: the X9.63 uncompressed
    /// point for the NIST curves, and the raw 32-byte point for Ed25519. Holding bytes
    /// rather than a backend key object is what keeps this module free of a
    /// cryptographic dependency; `Hashable` and `Sendable` are then synthesized, because
    /// two keys are equal exactly when their algorithm and bytes are.
    @usableFromInline
    enum BackingPublicKey: Hashable, Sendable {
        case p256(x963: [UInt8])
        case p384(x963: [UInt8])
        case p521(x963: [UInt8])
        case ed25519(raw: [UInt8])
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SubjectPublicKeyInfo {
    @inlinable
    package init(_ publicKey: Certificate.PublicKey) {
        let algorithmIdentifier: AlgorithmIdentifier
        let key: ISO_8824.BitString

        // paddingBits defaults to 0 at every call site below, which `_validate()` can
        // never reject — see the identical note on SubjectPublicKeyInfo's [UInt8] init.
        switch publicKey.backing {
        case .p256(let bytes):
            algorithmIdentifier = .p256PublicKey
            key = try! .init(bytes: bytes[...])
        case .p384(let bytes):
            algorithmIdentifier = .p384PublicKey
            key = try! .init(bytes: bytes[...])
        case .p521(let bytes):
            algorithmIdentifier = .p521PublicKey
            key = try! .init(bytes: bytes[...])
        case .ed25519(let bytes):
            algorithmIdentifier = .ed25519
            key = try! .init(bytes: bytes[...])
        }

        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey {
    /// The byte array of the public key used in the certificate.
    ///
    /// The `subjectPublicKeyInfoBytes` property represents the public key in its canonical form that is determined by the key's algorithm and common representation.
    ///
    /// This is the input a ``Certificate/Verify`` witness reconstructs its backend key
    /// from; pair it with the certificate's algorithm to know how to read it.
    @inlinable
    public var subjectPublicKeyInfoBytes: ArraySlice<UInt8> {
        switch self.backing {
        case .p256(let bytes), .p384(let bytes), .p521(let bytes), .ed25519(let bytes):
            return bytes[...]
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: ISO_8825.DER.ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ISO_8824.Identifier {
        SubjectPublicKeyInfo.defaultIdentifier
    }

    @inlinable
    public init(derEncoded: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        let spki = try SubjectPublicKeyInfo(derEncoded: derEncoded, withIdentifier: identifier)
        // Decode-boundary bridge (N5 Option A): init(spki:) validates the key algorithm
        // and its encoded length, and surfaces Certificate.Error; map to the ASN.1 error.
        do {
            try self.init(spki: spki)
        } catch {
            throw ISO_8824.Error.invalidASN1Object(reason: "\(error)")
        }
    }

    @inlinable
    public func serialize(
        into coder: inout ISO_8825.DER.Serializer,
        withIdentifier identifier: ISO_8824.Identifier
    ) throws(ISO_8824.Error) {
        let spki = SubjectPublicKeyInfo(self)
        try spki.serialize(into: &coder, withIdentifier: identifier)
    }
}
