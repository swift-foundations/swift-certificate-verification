//===----------------------------------------------------------------------===//
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
//===----------------------------------------------------------------------===//

import Testing
import ISO_8824
import ISO_8825
import Certificates

extension ExtendedKeyUsage {
    @Suite struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
        @Suite struct Integration {}
    }
}

extension ExtendedKeyUsage.Test.Unit {
    @Test func `insert usages`() throws {
        var usages = try ExtendedKeyUsage([
            .serverAuth
        ])
        #expect(usages.insert(.clientAuth, at: 1) == (true, 1))
        #expect(
            usages == (try ExtendedKeyUsage([
                .serverAuth,
                .clientAuth,
            ]))
        )
        #expect(usages.insert(.clientAuth, at: 1) == (false, 1))
        #expect(
            usages == (try ExtendedKeyUsage([
                .serverAuth,
                .clientAuth,
            ]))
        )
        #expect(usages.insert(.ocspSigning, at: 1) == (true, 1))
        #expect(
            usages == (try ExtendedKeyUsage([
                .serverAuth,
                .ocspSigning,
                .clientAuth,
            ]))
        )
        #expect(usages.insert(.codeSigning, at: 0) == (true, 0))
        #expect(
            usages == (try ExtendedKeyUsage([
                .codeSigning,
                .serverAuth,
                .ocspSigning,
                .clientAuth,
            ]))
        )
    }

    @Test func `append usages`() throws {
        var usages = ExtendedKeyUsage()

        usages.append(.clientAuth)
        #expect(
            usages == (try ExtendedKeyUsage([
                .clientAuth
            ]))
        )

        usages.append(.clientAuth)
        #expect(
            usages == (try ExtendedKeyUsage([
                .clientAuth
            ]))
        )

        usages.append(.ocspSigning)
        #expect(
            usages == (try ExtendedKeyUsage([
                .clientAuth,
                .ocspSigning,
            ]))
        )
    }

    @Test func `remove usages`() throws {
        var usages = try ExtendedKeyUsage([
            .clientAuth,
            .serverAuth,
            .ocspSigning,
        ])

        #expect(usages.remove(.emailProtection) == nil)
        #expect(
            usages == (try ExtendedKeyUsage([
                .clientAuth,
                .serverAuth,
                .ocspSigning,
            ]))
        )

        #expect(usages.remove(.clientAuth) == .clientAuth)
        #expect(
            usages == (try ExtendedKeyUsage([
                .serverAuth,
                .ocspSigning,
            ]))
        )

        #expect(usages.remove(.clientAuth) == nil)
        #expect(
            usages == (try ExtendedKeyUsage([
                .serverAuth,
                .ocspSigning,
            ]))
        )

        #expect(usages.remove(.ocspSigning) == .ocspSigning)
        #expect(
            usages == (try ExtendedKeyUsage([
                .serverAuth
            ]))
        )

        #expect(usages.remove(.serverAuth) == .serverAuth)
        #expect(usages == ExtendedKeyUsage())

        #expect(usages.remove(.serverAuth) == nil)
        #expect(usages == ExtendedKeyUsage())
    }
}

extension ExtendedKeyUsage.Test.`Edge Case` {
    @Test func `init rejects duplicate usages`() {
        #expect(throws: Certificate.Error.extension(.duplicateOID(ISO_8824.ObjectIdentifier(.serverAuth)))) {
            try ExtendedKeyUsage([
                .serverAuth,
                .serverAuth,
            ])
        }

        #expect(throws: Certificate.Error.extension(.duplicateOID(ISO_8824.ObjectIdentifier(.clientAuth)))) {
            try ExtendedKeyUsage([
                .clientAuth,
                .serverAuth,
                .clientAuth,
            ])
        }
    }

    @Test func `large number of extensions`() throws {
        let usages = try ExtendedKeyUsage(
            (0..<32).map {
                ExtendedKeyUsage.Usage(oid: [1, $0])
            }
        )
        #expect(usages.count == 32)
    }

    @Test func `unreasonable large number of extensions are rejected`() {
        #expect(throws: (any Error).self) {
            try ExtendedKeyUsage(
                (0..<33).map {
                    ExtendedKeyUsage.Usage(oid: [1, $0])
                }
            )
        }

        #expect(throws: (any Error).self) {
            try ExtendedKeyUsage(
                (0..<10_000).map {
                    ExtendedKeyUsage.Usage(oid: [1, $0])
                }
            )
        }
    }
}
