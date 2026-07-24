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
// Covers the test-target-only seconds offset. It is ten lines of carry-and-borrow
// arithmetic that 40 call sites depend on to place certificate validity windows, so a
// defect here would move every one of those windows and surface as policy outcomes nobody
// could attribute.
//
//===----------------------------------------------------------------------===//

import Testing
import Time_Primitive

@Suite struct `Instant Test Seconds` {}

extension `Instant Test Seconds` {
    static let epoch = Instant(secondsSinceUnixEpoch: 1_767_225_600)

    @Test func `whole seconds advance the second and leave the fraction alone`() {
        let result = Self.epoch + 3.0
        #expect(result.secondsSinceUnixEpoch == 1_767_225_603)
        #expect(result.nanosecondFraction == 0)
    }

    @Test func `a fractional offset lands in the nanosecond part`() {
        let result = Self.epoch + 2.5
        #expect(result.secondsSinceUnixEpoch == 1_767_225_602)
        #expect(result.nanosecondFraction == 500_000_000)
    }

    /// Two fractional offsets that together exceed a second must carry.
    @Test func `accumulated fractions carry into the next second`() {
        let result = Self.epoch + 0.6 + 0.6
        #expect(result.secondsSinceUnixEpoch == 1_767_225_601)
        #expect(result.nanosecondFraction == 200_000_000)
    }

    /// A negative offset leaves the nanosecond part below zero before correction, and
    /// `Instant` requires it in `0..<1_000_000_000`. This is the borrow path.
    @Test func `negative offsets borrow rather than produce an invalid instant`() {
        let result = Self.epoch + -0.25
        #expect(result.secondsSinceUnixEpoch == 1_767_225_599)
        #expect(result.nanosecondFraction == 750_000_000)
        #expect(result.nanosecondFraction >= 0)
        #expect(result.nanosecondFraction < 1_000_000_000)
    }

    @Test func `whole negative offsets subtract exactly`() {
        let result = Self.epoch + -3.0
        #expect(result.secondsSinceUnixEpoch == 1_767_225_597)
        #expect(result.nanosecondFraction == 0)
    }

    /// Year- and decade-scale offsets land on the exact second.
    ///
    /// ⚠️ This is **not** a control distinguishing split-before-scale from scale-first. I
    /// wrote it believing it was, and checking refuted that: at these magnitudes the scaled
    /// product is still exactly representable, and where it is not, the error falls in the
    /// nanosecond field a few nanoseconds wide and never moves the second count. Both
    /// implementations pass this. It is kept because year-scale offsets are what validity
    /// windows are built from and their exactness is worth pinning — but it certifies the
    /// result, not the technique.
    @Test func `large offsets stay exact`() {
        let oneYear = 365.0 * 24 * 60 * 60  // 31_536_000
        let result = Self.epoch + oneYear
        #expect(result.secondsSinceUnixEpoch == 1_767_225_600 + 31_536_000)
        #expect(result.nanosecondFraction == 0)

        let decade = 3650.0 * 24 * 60 * 60  // 315_360_000
        #expect((Self.epoch + decade).secondsSinceUnixEpoch == 1_767_225_600 + 315_360_000)
    }

    /// Ordering is what the suites actually rely on: a validation time placed between two
    /// validity bounds must compare between them.
    @Test func `offsets preserve ordering`() {
        #expect(Self.epoch < Self.epoch + 1.0)
        #expect(Self.epoch + 2.0 < Self.epoch + 2.5)
        #expect(Self.epoch + 2.5 < Self.epoch + 3.0)
        #expect(Self.epoch + -1.0 < Self.epoch)
    }
}
