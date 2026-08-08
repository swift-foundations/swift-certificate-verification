// ===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
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

/// A sub-policy of the ``RFC5280Policy`` that polices expiry.
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct ExpiryPolicy: VerifierPolicy, Sendable {
  @usableFromInline
  let verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] = []

  @usableFromInline
  let validationTime: ISO_8824.GeneralizedTime

  /// Creates an instance with an injected validation instant.
  ///
  /// The verifier never reads a system clock: the instant a chain is
  /// evaluated against is always supplied by the caller.
  @inlinable
  init(validationTime: Instant) {
    self.validationTime = ISO_8824.GeneralizedTime(validationTime)
  }

  @inlinable
  func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
    let validationTime = self.validationTime

    // This is an easy check: confirm all the certs are valid.
    //
    // Note that we do this computation on the TBSCertificate Validity struct, not the public Instant fields. This
    // is to avoid expensive repeated transformations into Instant fields.
    for cert in chain {
      let notValidBefore = ISO_8824.GeneralizedTime(cert.tbsCertificate.validity.notBefore)
      let notValidAfter = ISO_8824.GeneralizedTime(cert.tbsCertificate.validity.notAfter)

      if notValidBefore > notValidAfter {
        return .failsToMeetPolicy(
          reason:
            "RFC5280Policy: Certificate \(cert) has invalid expiry, notValidAfter is earlier than notValidBefore"
        )
      }

      if validationTime < notValidBefore {
        return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) is not yet valid")
      }

      if validationTime > notValidAfter {
        return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) has expired")
      }
    }

    return .meetsPolicy
  }
}
