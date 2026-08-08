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
import ISO_8825

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Error {
  /// An extension whose OID usage is invalid.
  public enum Extension: Hashable, Sendable {
    /// An extension was unwrapped as a type whose OID it does not carry.
    case incorrectOID(expected: ISO_8824.ObjectIdentifier, found: ISO_8824.ObjectIdentifier)

    /// The same OID is present more than once where uniqueness is required.
    case duplicateOID(ISO_8824.ObjectIdentifier)
  }
}
