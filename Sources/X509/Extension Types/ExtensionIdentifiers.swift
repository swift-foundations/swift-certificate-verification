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

extension ISO_8824.ObjectIdentifier {
    /// OIDs that identify known X509 extensions.
    public enum X509ExtensionID: Sendable {
        /// Identifies the authority key identifier extension, corresponding to
        /// ``AuthorityKeyIdentifier``.
        public static let authorityKeyIdentifier: ISO_8824.ObjectIdentifier = [2, 5, 29, 35]

        /// Identifies the subject key identifier extension, corresponding to
        /// ``SubjectKeyIdentifier``.
        public static let subjectKeyIdentifier: ISO_8824.ObjectIdentifier = [2, 5, 29, 14]

        /// Identifies the key usage extension, corresponding to
        /// ``KeyUsage``.
        public static let keyUsage: ISO_8824.ObjectIdentifier = [2, 5, 29, 15]

        /// Identifies the subject alternative name extension, corresponding to
        /// ``SubjectAlternativeNames``.
        public static let subjectAlternativeName: ISO_8824.ObjectIdentifier = [2, 5, 29, 17]

        /// Identifies the basic constraints extension, corresponding to
        /// ``BasicConstraints``.
        public static let basicConstraints: ISO_8824.ObjectIdentifier = [2, 5, 29, 19]

        /// Identifies the name constraints extension, corresponding to
        /// ``NameConstraints``.
        public static let nameConstraints: ISO_8824.ObjectIdentifier = [2, 5, 29, 30]

        /// Identifies the extended key usage extension, corresponding to
        /// ``ExtendedKeyUsage``.
        public static let extendedKeyUsage: ISO_8824.ObjectIdentifier = [2, 5, 29, 37]

        /// Identifies the authority information access extension, corresponding to
        /// ``AuthorityInformationAccess``.
        public static let authorityInformationAccess: ISO_8824.ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 1, 1]
    }
}
