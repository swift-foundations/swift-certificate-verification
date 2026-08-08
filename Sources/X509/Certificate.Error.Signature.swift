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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Error {
  /// A signature whose encoded form is not acceptable for its algorithm.
  public enum Signature: Hashable, Sendable {
    /// The signature is not valid for the certificate that carries it.
    case invalidForCertificate

    /// The signature's encoding violates the rules of its algorithm.
    case invalidEncoding(reason: String)
  }
}
