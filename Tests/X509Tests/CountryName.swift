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

// ⛔ TEST TARGET ONLY. VERBATIM lift of
//   Sources/X509/DistinguishedNameBuilder/CountryName.swift @ fork-point 24ccdee
// (import adapted: SwiftASN1 → ISO_8824). Owning arc: the future ISSUANCE
// package; `git diff` this copy against that path at 24ccdee to check drift.
// See DNBuilder.swift for the full binding condition.

import ISO_8824
@testable import Certificates

/// Set the Country Name (C) of a ``DistinguishedName``.
///
/// This type is used in ``DistinguishedNameBuilder`` contexts.
public struct CountryName: RelativeDistinguishedNameConvertible, Sendable {
    /// The value of the country name field.
    public var name: String

    /// Construct a new country name
    ///
    /// - Parameter name: The value of the country name
    @inlinable
    public init(_ name: String) {
        self.name = name
    }

    @inlinable
    public func makeRDN() throws -> RelativeDistinguishedName {
        return RelativeDistinguishedName(
            try .init(type: .RDNAttributeType.countryName, printableString: name)
        )
    }
}
