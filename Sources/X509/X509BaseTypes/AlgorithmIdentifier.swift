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
import Standard_Library_Extensions

// TX-N1E: raised from `internal` to `package` — a `package`-access initializer
// (Certificate.init(tbsCertificate:signatureAlgorithm:...)) takes this type as a
// parameter, and a `package` declaration's signature must be built entirely from types at
// least as visible as `package` (an `@usableFromInline` `internal` type satisfies
// same-module `@inlinable` access, but not package-level cross-file API visibility). Same
// class of access-level defect as the TBSCertificate / SubjectPublicKeyInfo fixes; this is
// the third occurrence, all pre-existing and surfaced only once the dependency-side
// (swift-iso-8825/8824) throwing-initializer changes forced other call sites to be
// re-verified.
@usableFromInline
package struct AlgorithmIdentifier: ISO_8825.DER.ImplicitlyTaggable, ISO_8825.BER.ImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    package static var defaultIdentifier: ISO_8824.Identifier {
        .sequence
    }

    @usableFromInline
    var algorithm: ISO_8824.ObjectIdentifier

    @usableFromInline
    var parameters: ISO_8825.`Any`?

    @inlinable
    package init(algorithm: ISO_8824.ObjectIdentifier, parameters: ISO_8825.`Any`?) {
        self.algorithm = algorithm
        self.parameters = parameters
    }

    @inlinable
    package init(derEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        // The AlgorithmIdentifier block looks like this.
        //
        // AlgorithmIdentifier  ::=  SEQUENCE  {
        //   algorithm   OBJECT IDENTIFIER,
        //   parameters  ANY DEFINED BY algorithm OPTIONAL
        // }
        self = try ISO_8825.DER.sequence(rootNode, identifier: identifier) { (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> AlgorithmIdentifier in
            let algorithmOID = try ISO_8824.ObjectIdentifier(derEncoded: &nodes)

            let parameters = nodes.next().map { ISO_8825.`Any`(derEncoded: $0) }

            return .init(algorithm: algorithmOID, parameters: parameters)
        }
    }

    @inlinable
    package init(berEncoded rootNode: ISO_8825.Node, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        self = try .init(derEncoded: rootNode, withIdentifier: identifier)
    }

    @inlinable
    package func serialize(into coder: inout ISO_8825.DER.Serializer, withIdentifier identifier: ISO_8824.Identifier) throws(ISO_8824.Error) {
        try coder.appendConstructedNode(identifier: identifier) { (coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) -> Void in
            try coder.serialize(self.algorithm)
            if let parameters = self.parameters {
                try coder.serialize(parameters)
            }
        }
    }
}

// MARK: Algorithm Identifier Statics
extension AlgorithmIdentifier {
    @usableFromInline
    static let p256PublicKey = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ISO_8824.ObjectIdentifier.NamedCurves.secp256r1)
    )

    @usableFromInline
    static let p384PublicKey = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ISO_8824.ObjectIdentifier.NamedCurves.secp384r1)
    )

    @usableFromInline
    static let p521PublicKey = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ISO_8824.ObjectIdentifier.NamedCurves.secp521r1)
    )

    @usableFromInline
    static let ecdsaWithSHA256 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.ecdsaWithSHA256,
        parameters: nil
    )

    @usableFromInline
    static let ecdsaWithSHA384 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.ecdsaWithSHA384,
        parameters: nil
    )

    @usableFromInline
    static let ecdsaWithSHA512 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.ecdsaWithSHA512,
        parameters: nil
    )

    // MARK: For the RSA signature types, explicit ASN.1 NULL is equivalent to a missing parameters field.
    // We include both here, and the usage sites need to handle the equivalent.
    @usableFromInline
    static let sha1WithRSAEncryption = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha1WithRSAEncryption,
        parameters: try! ISO_8825.`Any`(erasing: ISO_8824.Null())
    )

    @usableFromInline
    static let sha1WithRSAEncryptionUsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha1WithRSAEncryption,
        parameters: nil
    )

    @usableFromInline
    static let sha256WithRSAEncryption = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256WithRSAEncryption,
        parameters: try! ISO_8825.`Any`(erasing: ISO_8824.Null())
    )

    @usableFromInline
    static let sha256WithRSAEncryptionUsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256WithRSAEncryption,
        parameters: nil
    )

    @usableFromInline
    static let sha384WithRSAEncryption = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384WithRSAEncryption,
        parameters: try! ISO_8825.`Any`(erasing: ISO_8824.Null())
    )

    @usableFromInline
    static let sha384WithRSAEncryptionUsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384WithRSAEncryption,
        parameters: nil
    )

    @usableFromInline
    static let sha512WithRSAEncryption = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512WithRSAEncryption,
        parameters: try! ISO_8825.`Any`(erasing: ISO_8824.Null())
    )

    @usableFromInline
    static let sha512WithRSAEncryptionUsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512WithRSAEncryption,
        parameters: nil
    )

    @usableFromInline
    static let rsaKey = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaEncryption,
        parameters: try! ISO_8825.`Any`(erasing: ISO_8824.Null())
    )

    @usableFromInline
    static let sha1UsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha1,
        parameters: nil
    )

    @usableFromInline
    static let sha1 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha1,
        parameters: try! ISO_8825.`Any`(erasing: ISO_8824.Null())
    )

    @usableFromInline
    static let sha256UsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256,
        parameters: nil
    )

    @usableFromInline
    static let sha256 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256,
        parameters: try! ISO_8825.`Any`(erasing: ISO_8824.Null())
    )

    @usableFromInline
    static let sha384UsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384,
        parameters: nil
    )

    @usableFromInline
    static let sha384 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384,
        parameters: try! ISO_8825.`Any`(erasing: ISO_8824.Null())
    )

    @usableFromInline
    static let sha512UsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512,
        parameters: nil
    )

    @usableFromInline
    static let sha512 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512,
        parameters: try! ISO_8825.`Any`(erasing: ISO_8824.Null())
    )

    @usableFromInline
    static let ed25519 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.ed25519,
        parameters: nil
    )
}

extension AlgorithmIdentifier: CustomStringConvertible {
    @usableFromInline
    package var description: String {
        switch self {
        case .p256PublicKey:
            return "p256PublicKey"
        case .p384PublicKey:
            return "p384PublicKey"
        case .p521PublicKey:
            return "p521PublicKey"
        case .ecdsaWithSHA256:
            return "ecdsaWithSHA256"
        case .ecdsaWithSHA384:
            return "ecdsaWithSHA384"
        case .ecdsaWithSHA512:
            return "ecdsaWithSHA512"
        case .sha1WithRSAEncryption, .sha1WithRSAEncryptionUsingNil:
            return "sha1WithRSAEncryption"
        case .sha256WithRSAEncryption, .sha256WithRSAEncryptionUsingNil:
            return "sha256WithRSAEncryption"
        case .sha384WithRSAEncryption, .sha384WithRSAEncryptionUsingNil:
            return "sha384WithRSAEncryption"
        case .sha512WithRSAEncryption, .sha512WithRSAEncryptionUsingNil:
            return "sha512WithRSAEncryption"
        case .sha1, .sha1UsingNil:
            return "sha1"
        case .sha256, .sha256UsingNil:
            return "sha256"
        case .sha384, .sha384UsingNil:
            return "sha384"
        case .sha512, .sha512UsingNil:
            return "sha512"
        case .ed25519:
            return "ed25519"
        default:
            return "AlgorithmIdentifier(\(self.algorithm) - \(String(reflecting: self.parameters)))"
        }
    }
}

// Relevant note: the PKCS1v1.5 versions need to treat having no parameters and a NULL parameters as identical. This is probably general,
// so we may need a custom equatable implementation there.

extension ISO_8824.ObjectIdentifier.AlgorithmIdentifier {
    static let ecdsaWithSHA256: ISO_8824.ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 2]

    static let ecdsaWithSHA384: ISO_8824.ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 3]

    static let ecdsaWithSHA512: ISO_8824.ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 4]

    static let sha1WithRSAEncryption: ISO_8824.ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 5]

    static let sha1: ISO_8824.ObjectIdentifier = [1, 3, 14, 3, 2, 26]

    static let sha256: ISO_8824.ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]

    static let sha384: ISO_8824.ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 2]

    static let sha512: ISO_8824.ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 3]

    static let ed25519: ISO_8824.ObjectIdentifier = [1, 3, 101, 112]
}

extension AlgorithmIdentifier {
    @usableFromInline
    static let ecdsaP256 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ISO_8824.ObjectIdentifier.NamedCurves.secp256r1)
    )
    @usableFromInline
    static let ecdsaP384 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ISO_8824.ObjectIdentifier.NamedCurves.secp384r1)
    )
    @usableFromInline
    static let ecdsaP521 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ISO_8824.ObjectIdentifier.NamedCurves.secp521r1)
    )
}
