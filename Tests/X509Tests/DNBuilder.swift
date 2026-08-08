// ===----------------------------------------------------------------------===//
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
// ===----------------------------------------------------------------------===//

// ⛔ TEST TARGET ONLY. DO NOT LIFT THIS INTO A MAIN TARGET.
//
// BINDING CONDITION — this file, and its nine sibling element files
// (CommonName, CountryName, DomainComponent, EmailAddress, LocalityName,
// OrganizationName, OrganizationalUnitName, StateOrProvinceName, StreetAddress),
// are a VERBATIM lift of
//     Sources/X509/DistinguishedNameBuilder/*.swift @ fork-point 24ccdee
// with only the module imports adapted to this fork's ASN.1 modules (`import
// SwiftASN1` → `import ISO_8824`); every *declaration body* is unchanged. Their
// permanent home is the future ISSUANCE package — the owning arc. To confirm no
// drift, `git diff` each copy against that path at 24ccdee.
//
// Why parked here, and why it reinstates nothing. Only the builder DSLs were
// deleted from the main target; `DistinguishedName` and
// `RelativeDistinguishedName` SURVIVE there. The `DistinguishedName { … }`
// entry-point init (`init(@DistinguishedNameBuilder …)`) was deleted with the
// issuance surface and is NOT restored here — so this DSL COMPILES but is not
// exercised in the compiled test set. Its exercisers are the excluded
// RFC5280Policy / Verifier suites (TestPKI — component 6, still excluded); this
// family is a prerequisite for component 6, not part of it.
//
// It depends only on surviving *public* main-target types (`DistinguishedName`,
// `RelativeDistinguishedName`, its `Attribute` inits) and the
// `ISO_8824.ObjectIdentifier.RDNAttributeType` accessors. It collides with
// nothing in the main target.

@testable import Certificates

/// Provides a result-builder style DSL for constructing ``DistinguishedName`` values.
///
/// This DSL allows us to construct distinguished names straightforwardly, using their high-level representation instead of
/// the awkward representation provided by sequences of ``RelativeDistinguishedName`` and
/// ``RelativeDistinguishedName/Attribute``. For example, a simple ``DistinguishedName`` can be
/// provided like this:
///
/// ```swift
/// let name = try DistinguishedName {
///     CountryName("US")
///     OrganizationName("Apple Inc.")
///     CommonName("Apple Public EV Server ECC CA 1 - G1")
/// }
/// ```
///
/// Users can extend this syntax for their own extensions by conforming their semantic type to ``RelativeDistinguishedNameConvertible``.
/// This is the only requirement for adding new extensions to this builder syntax.
@resultBuilder
public struct DistinguishedNameBuilder: Sendable {
  @inlinable
  public static func buildExpression<Extension: RelativeDistinguishedNameConvertible>(
    _ expression: Extension
  ) -> Result<DistinguishedName, any Error> {
    Result {
      try DistinguishedName([expression.makeRDN()])
    }
  }

  @inlinable
  public static func buildBlock(
    _ components: Result<DistinguishedName, any Error>...
  ) -> Result<DistinguishedName, any Error> {
    Result {
      DistinguishedName(try components.flatMap { try $0.get() })
    }
  }

  @inlinable
  public static func buildOptional(
    _ component: Result<DistinguishedName, any Error>?
  ) -> Result<DistinguishedName, any Error> {
    component ?? .success(DistinguishedName())
  }

  @inlinable
  public static func buildEither(
    first component: Result<DistinguishedName, any Error>
  ) -> Result<DistinguishedName, any Error> {
    component
  }

  @inlinable
  public static func buildEither(
    second component: Result<DistinguishedName, any Error>
  ) -> Result<DistinguishedName, any Error> {
    component
  }

  @inlinable
  public static func buildArray(
    _ components: [Result<DistinguishedName, any Error>]
  ) -> Result<DistinguishedName, any Error> {
    Result {
      DistinguishedName(try components.flatMap { try $0.get() })
    }
  }

  @inlinable
  public static func buildLimitedAvailability(
    _ component: Result<DistinguishedName, any Error>
  ) -> Result<DistinguishedName, any Error> {
    component
  }
}

public protocol RelativeDistinguishedNameConvertible {
  func makeRDN() throws -> RelativeDistinguishedName
}
