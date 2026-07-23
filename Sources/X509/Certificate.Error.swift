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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// A failure condition raised by the certificate model surfaces.
    ///
    /// Verification outcomes are not errors: policy rejection is reported through
    /// ``VerificationResult`` and ``PolicyEvaluationResult``, never thrown.
    public enum Error: Swift.Error, Hashable, Sendable {
        /// An algorithm outside the supported verification surface.
        case algorithm(Algorithm)

        /// A signature whose encoded form is not acceptable.
        case signature(Signature)

        /// An extension whose OID usage is invalid.
        case `extension`(Extension)
    }
}
