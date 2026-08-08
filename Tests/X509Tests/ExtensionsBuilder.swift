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
// BINDING CONDITION — this file is a VERBATIM lift of
//     Sources/X509/ExtensionsBuilder.swift @ fork-point 24ccdee
// with only the module import adapted to this fork (the original had no import
// because it lived in the main module; every *declaration body* below is
// unchanged). Its permanent home is the future ISSUANCE package — the owning
// arc. To confirm no drift, `git diff` this copy against that path at 24ccdee.
//
// Why it is parked here, and why it reinstates nothing. The
// `Certificate.Extensions { … }` result-builder DSL, the
// `CertificateExtensionConvertible` protocol, and the `Critical<…>` wrapper
// were all deleted from the main target together with the issuance surface, and
// belong to the issuance arc. The excluded RFC5280Policy / Verifier suites
// (TestPKI — component 6, still excluded) construct certificates through this
// DSL, so it must exist in the test target for those suites to eventually
// compile. It is a prerequisite for component 6, not part of it.
//
// It depends only on surviving *public* main-target types
// (`Certificate.Extensions`, `Certificate.Extension`). No main-target extension
// type conforms to `CertificateExtensionConvertible` in this fork — those
// conformances went to the issuance surface — so this file COMPILES but is not
// exercised here. That is intentional: the exercisers are the excluded suites.

@testable import Certificates

/// Provides a result-builder style DSL for constructing ``Certificate/Extensions-swift.struct`` values.
///
/// This DSL allows us to construct extensions straightforwardly, using their high-level representation instead of
/// the erased representation provided by ``Certificate/Extension``. For example, a simple set of
/// extensions can be produced like this:
///
/// ```swift
/// let extensions = Certificate.Extensions {
///     Critical(
///         KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true)
///     )
///
///     ExtendedKeyUsage([.serverAuth, .clientAuth])
///
///     Critical(
///         BasicConstraints.isCertificateAuthority(maxPathLength: 0)
///     )
///
///     AuthorityInformationAccess([.init(method: .ocspServer, location: .uniformResourceIdentifier("http://ocsp.digicert.com"))])
/// }
/// ```
///
/// Users can extend this syntax for their own extensions by conforming their semantic type to ``CertificateExtensionConvertible``.
/// This is the only requirement for adding new extensions to this builder syntax.
///
/// Users are also able to mark specific extensions as critical by using the ``Critical`` helper type.
@resultBuilder
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct ExtensionsBuilder: Sendable {
  @inlinable
  public static func buildExpression<Extension: CertificateExtensionConvertible>(
    _ expression: Extension
  ) -> Result<Certificate.Extensions, any Error> {
    Result {
      try Certificate.Extensions([expression.makeCertificateExtension()])
    }
  }

  @inlinable
  public static func buildExpression(
    _ expression: Certificate.Extensions
  ) -> Result<Certificate.Extensions, any Error> {
    .success(expression)
  }

  @inlinable
  public static func buildExpression() -> Result<Certificate.Extensions, any Error> {
    .success(Certificate.Extensions())
  }

  @inlinable
  public static func buildBlock() -> Result<Certificate.Extensions, any Error> {
    .success(Certificate.Extensions())
  }

  @inlinable
  public static func buildBlock(
    _ components: Result<Certificate.Extensions, any Error>...
  ) -> Result<Certificate.Extensions, any Error> {
    Result {
      try Certificate.Extensions(try components.lazy.flatMap { try $0.get() })
    }
  }

  @inlinable
  public static func buildOptional(
    _ component: Result<Certificate.Extensions, any Error>?
  ) -> Result<Certificate.Extensions, any Error> {
    component ?? .success(Certificate.Extensions())
  }

  @inlinable
  public static func buildEither(
    first component: Result<Certificate.Extensions, any Error>
  ) -> Result<Certificate.Extensions, any Error> {
    component
  }

  @inlinable
  public static func buildEither(
    second component: Result<Certificate.Extensions, any Error>
  ) -> Result<Certificate.Extensions, any Error> {
    component
  }

  @inlinable
  public static func buildArray(
    _ components: [Result<Certificate.Extensions, any Error>]
  ) -> Result<Certificate.Extensions, any Error> {
    Result {
      try Certificate.Extensions(try components.lazy.flatMap { try $0.get() })
    }
  }

  @inlinable
  public static func buildLimitedAvailability(
    _ component: Result<Certificate.Extensions, any Error>
  ) -> Result<Certificate.Extensions, any Error> {
    component
  }
}

/// Conforming types are capable of being erased into ``Certificate/Extension`` values.
///
/// Note that for most extension types, the returned ``Certificate/Extension`` should have its
/// ``Certificate/Extension/critical`` value set to `false`. This allows the ``Critical`` helper
/// type to fulfill its function as expected.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol CertificateExtensionConvertible {
  /// Convert the value into a ``Certificate/Extension``.
  func makeCertificateExtension() throws -> Certificate.Extension
}

/// Marks a given ``CertificateExtensionConvertible`` value as critical.
///
/// This type is used only within the ``ExtensionsBuilder`` DSL to mark extensions as critical.
@frozen
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct Critical<BaseExtension: CertificateExtensionConvertible>:
  CertificateExtensionConvertible
{
  /// The ``CertificateExtensionConvertible`` backing this value.
  public var base: BaseExtension

  /// Wrap a ``CertificateExtensionConvertible`` value and mark it critical.
  @inlinable
  public init(_ base: BaseExtension) {
    self.base = base
  }

  @inlinable
  public func makeCertificateExtension() throws -> Certificate.Extension {
    var ext = try self.base.makeCertificateExtension()
    ext.critical = true
    return ext
  }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Critical: Sendable where BaseExtension: Sendable {}
