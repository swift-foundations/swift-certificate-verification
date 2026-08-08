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

import ISO_8824

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Error {
  /// An algorithm the certificate model does not support.
  ///
  /// Each case carries the offending algorithm's object identifier as evidence.
  public enum Algorithm: Hashable, Sendable {
    /// The signature algorithm is not supported.
    case unsupportedSignature(ISO_8824.ObjectIdentifier)

    /// The public key algorithm is not supported.
    case unsupportedPublicKey(ISO_8824.ObjectIdentifier)

    /// The digest algorithm is not supported.
    case unsupportedDigest(ISO_8824.ObjectIdentifier)
  }
}
