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
import Crypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

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
    /// This type is almost entirely opaque. It can be validated by way of
    /// ``Certificate/PublicKey-swift.struct/isValidSignature(_:for:)-3cbor``.
    /// Otherwise, this type has essentially no behaviours.
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
                let signature = Data(signatureBytes.bytes)
                self.backing = .ed25519(signature)
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
    @usableFromInline
    enum BackingSignature: Hashable, Sendable {
        case ecdsa(ECDSASignature)
        case ed25519(Data)

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
        case let .ed25519(data):
            return .init(data)
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
            self = ISO_8824.OctetString(contentBytes: ArraySlice(sig))
        }
    }
}

// MARK: Public key operations

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256.Signing.PublicKey {
    @inlinable
    internal func isValidSignature<Bytes: DataProtocol>(
        _ signature: Certificate.Signature,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        guard case .ecdsa(let rawInnerSignature) = signature.backing,
            let innerSignature = P256.Signing.ECDSASignature(rawInnerSignature)
        else {
            // Signature mismatch
            return false
        }

        return self.isValidSignature(innerSignature, for: bytes, signatureAlgorithm: signatureAlgorithm)
    }

    @inlinable
    internal func isValidSignature<SignatureBytes: DataProtocol, Bytes: DataProtocol>(
        _ signature: SignatureBytes,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        // Probe: a signature that is not valid DER is a verification failure, not an error.
        let ecdsaSignature: ECDSASignature
        do {
            ecdsaSignature = try ECDSASignature(derEncoded: Array(signature))
        } catch {
            return false
        }
        guard let innerSignature = P256.Signing.ECDSASignature(ecdsaSignature) else {
            return false
        }

        return self.isValidSignature(innerSignature, for: bytes, signatureAlgorithm: signatureAlgorithm)
    }

    @inlinable
    internal func isValidSignature<Bytes: DataProtocol>(
        _ signature: P256.Signing.ECDSASignature,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        switch signatureAlgorithm {
        case .ecdsaWithSHA256:
            return self.isValidSignature(signature, for: SHA256.hash(data: bytes))
        case .ecdsaWithSHA384:
            return self.isValidSignature(signature, for: SHA384.hash(data: bytes))
        case .ecdsaWithSHA512:
            return self.isValidSignature(signature, for: SHA512.hash(data: bytes))
        default:
            return false
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P384.Signing.PublicKey {
    @inlinable
    internal func isValidSignature<Bytes: DataProtocol>(
        _ signature: Certificate.Signature,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        guard case .ecdsa(let rawInnerSignature) = signature.backing,
            let innerSignature = P384.Signing.ECDSASignature(rawInnerSignature)
        else {
            // Signature mismatch
            return false
        }

        return self.isValidSignature(innerSignature, for: bytes, signatureAlgorithm: signatureAlgorithm)
    }

    @inlinable
    internal func isValidSignature<SignatureBytes: DataProtocol, Bytes: DataProtocol>(
        _ signature: SignatureBytes,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        // Probe: a signature that is not valid DER is a verification failure, not an error.
        let ecdsaSignature: ECDSASignature
        do {
            ecdsaSignature = try ECDSASignature(derEncoded: Array(signature))
        } catch {
            return false
        }
        guard let innerSignature = P384.Signing.ECDSASignature(ecdsaSignature) else {
            return false
        }

        return self.isValidSignature(innerSignature, for: bytes, signatureAlgorithm: signatureAlgorithm)
    }

    @inlinable
    internal func isValidSignature<Bytes: DataProtocol>(
        _ signature: P384.Signing.ECDSASignature,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        switch signatureAlgorithm {
        case .ecdsaWithSHA256:
            return self.isValidSignature(signature, for: SHA256.hash(data: bytes))
        case .ecdsaWithSHA384:
            return self.isValidSignature(signature, for: SHA384.hash(data: bytes))
        case .ecdsaWithSHA512:
            return self.isValidSignature(signature, for: SHA512.hash(data: bytes))
        default:
            return false
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P521.Signing.PublicKey {
    @inlinable
    internal func isValidSignature<Bytes: DataProtocol>(
        _ signature: Certificate.Signature,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        guard case .ecdsa(let rawInnerSignature) = signature.backing,
            let innerSignature = P521.Signing.ECDSASignature(rawInnerSignature)
        else {
            // Signature mismatch
            return false
        }

        return self.isValidSignature(innerSignature, for: bytes, signatureAlgorithm: signatureAlgorithm)
    }

    @inlinable
    internal func isValidSignature<SignatureBytes: DataProtocol, Bytes: DataProtocol>(
        _ signature: SignatureBytes,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        // Probe: a signature that is not valid DER is a verification failure, not an error.
        let ecdsaSignature: ECDSASignature
        do {
            ecdsaSignature = try ECDSASignature(derEncoded: Array(signature))
        } catch {
            return false
        }
        guard let innerSignature = P521.Signing.ECDSASignature(ecdsaSignature) else {
            return false
        }

        return self.isValidSignature(innerSignature, for: bytes, signatureAlgorithm: signatureAlgorithm)
    }

    @inlinable
    internal func isValidSignature<Bytes: DataProtocol>(
        _ signature: P521.Signing.ECDSASignature,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        switch signatureAlgorithm {
        case .ecdsaWithSHA256:
            return self.isValidSignature(signature, for: SHA256.hash(data: bytes))
        case .ecdsaWithSHA384:
            return self.isValidSignature(signature, for: SHA384.hash(data: bytes))
        case .ecdsaWithSHA512:
            return self.isValidSignature(signature, for: SHA512.hash(data: bytes))
        default:
            return false
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519.Signing.PublicKey {
    @inlinable
    internal func isValidSignature<Bytes: DataProtocol>(
        _ signature: Certificate.Signature,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        guard case .ed25519(let rawInnerSignature) = signature.backing else {
            // Signature mismatch
            return false
        }

        return self.isValidSignature(rawInnerSignature, for: bytes, signatureAlgorithm: signatureAlgorithm)
    }

    @inlinable
    internal func isValidSignature<SignatureBytes: DataProtocol, Bytes: DataProtocol>(
        _ signature: SignatureBytes,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        switch signatureAlgorithm {
        case .ed25519:
            return self.isValidSignature(signature, for: bytes)
        default:
            return false
        }
    }
}
