// ===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//
import ISO_8824
import ISO_8825
import Time_Primitive

/// A ``VerifierPolicy`` that implements the core chain verifying policies from RFC 5280.
///
/// Almost all verifiers should use this policy as the initial component of their policy set. The policy checks the
/// following things:
///
/// 1. Version. ``Certificate/Version-swift.struct/v1`` ``Certificate``s with ``Certificate/Extensions-swift.struct`` are rejected.
/// 2. Expiry. Expired certificates are rejected.
/// 3. Basic Constraints. Police the constraints contained in the ``BasicConstraints`` extension.
/// 4. Name Constraints. Police the constraints contained in the ``NameConstraints`` extension.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct RFC5280Policy: VerifierPolicy, Sendable {
  public let verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] = [
    .X509ExtensionID.basicConstraints,
    .X509ExtensionID.nameConstraints,

    // The presence of keyUsage here requires some explanation, because this policy doesn't _actually_ compute
    // on it in any way.
    //
    // The unfortunate reality of keyUsage is that, while RFC 5280 requires us to validate it, CAs have historically
    // done a very poor job of actually implementing it. The result is that policing KeyUsage produces minimal value
    // in terms of increased security, but produces a substantial uptick in the number of unbuildable chains. So
    // we _pretend_ to police the key usage, and just...don't.
    .X509ExtensionID.keyUsage,
  ]

  @usableFromInline
  let versionPolicy: VersionPolicy

  @usableFromInline
  let expiryPolicy: ExpiryPolicy

  @usableFromInline
  let basicConstraintsPolicy: BasicConstraintsPolicy

  @usableFromInline
  let nameConstraintsPolicy: NameConstraintsPolicy

  /// Creates an instance that validates expiry against the injected
  /// `validationTime`.
  ///
  /// The verifier never reads a system clock: the instant a chain is
  /// evaluated against is always supplied by the caller.
  ///
  /// - Parameter validationTime: The instant to compare against when
  ///   determining whether the certificates in the chain are within their
  ///   validity interval.
  @inlinable
  public init(validationTime: Instant) {
    self.versionPolicy = VersionPolicy()
    self.expiryPolicy = ExpiryPolicy(validationTime: validationTime)
    self.basicConstraintsPolicy = BasicConstraintsPolicy()
    self.nameConstraintsPolicy = NameConstraintsPolicy()
  }

  @inlinable
  public func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain)
    -> PolicyEvaluationResult
  {
    if case .failsToMeetPolicy(let reason) = self.versionPolicy.chainMeetsPolicyRequirements(
      chain: chain)
    {
      return .failsToMeetPolicy(reason: reason)
    }
    if case .failsToMeetPolicy(let reason) = self.expiryPolicy.chainMeetsPolicyRequirements(
      chain: chain)
    {
      return .failsToMeetPolicy(reason: reason)
    }

    if case .failsToMeetPolicy(let reason) = self.basicConstraintsPolicy
      .chainMeetsPolicyRequirements(chain: chain)
    {
      return .failsToMeetPolicy(reason: reason)
    }

    if case .failsToMeetPolicy(let reason) = self.nameConstraintsPolicy
      .chainMeetsPolicyRequirements(chain: chain)
    {
      return .failsToMeetPolicy(reason: reason)
    }

    return .meetsPolicy
  }
}
