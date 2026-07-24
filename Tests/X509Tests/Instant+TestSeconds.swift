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

import Time_Primitive

// ⛔ TEST TARGET ONLY. DO NOT LIFT THIS INTO A MAIN TARGET, AND DO NOT ADD IT TO
//    swift-time-primitives.
//
// `Instant` offers `+ (Instant, Duration)` and deliberately NO `Double` overload, and
// `2.5` is not a `Duration` literal. **That is the type system working, not lacking.**
// Typed time is the whole point of the type: an untyped seconds offset is precisely the
// API a main target must never have, because `x + 2.5` does not say what 2.5 is, and the
// answer has been seconds, milliseconds and days in different codebases.
//
// This exists for exactly one reason. The policy suites were written against
// `Foundation.Date` and spell their validity offsets `TestPKI.startDate + 2.5`, at 40 call
// sites. The Q4 ruling replaced `Date` with `Instant` throughout the model. Restoring
// those tests by rewriting the arithmetic would mean editing 40 assertions in order to
// preserve them — which is the trade the deferred-tests ledger already recorded against,
// when remapping `ServerIdentityPolicy` was found to "weaken the assertion while appearing
// to preserve the test". Ten lines here keep 40 assertions verbatim.
//
// It is scoped to this file and this target on purpose. If you find yourself wanting it
// somewhere else, the thing you actually want is `Duration` — `.seconds(2.5)` says what
// `2.5` means, and it is available everywhere.
extension Instant {
    /// Offsets an instant by a number of **seconds**, for suites carrying `Date`-era
    /// arithmetic. See the file-level note before using or moving this.
    ///
    /// Whole and fractional parts are separated before scaling rather than after, so the
    /// value scaled to nanoseconds is always below 1 and therefore exact.
    ///
    /// This is defensive rather than load-bearing, and the distinction is worth stating
    /// because it is easy to overclaim. Scaling first — `rhs * 1_000_000_000` — does lose
    /// precision once the product passes `Double`'s exact-integer range (2⁵³), but the
    /// error lands in the nanosecond field and is a few nanoseconds wide; it does not
    /// change the second count for any offset these suites use, and certificate validity is
    /// encoded at second granularity anyway. Splitting costs nothing and keeps the
    /// nanosecond field exact for arbitrary inputs, so it is the better default — but no
    /// test here distinguishes the two forms, and none of them would fail if this were
    /// written the other way.
    static func + (lhs: Instant, rhs: Double) -> Instant {
        let wholeSeconds = rhs.rounded(.towardZero)
        let fraction = rhs - wholeSeconds  // |fraction| < 1, so scaling it is exact enough

        let carriedNanoseconds =
            Int64(lhs.nanosecondFraction) + Int64((fraction * 1_000_000_000).rounded())

        var seconds =
            lhs.secondsSinceUnixEpoch + Int64(wholeSeconds)
            + carriedNanoseconds / 1_000_000_000
        var nanoseconds = carriedNanoseconds % 1_000_000_000

        // A negative offset can leave the nanosecond part below zero; `Instant` requires it
        // in 0..<1_000_000_000, so borrow a second rather than construct an invalid value.
        if nanoseconds < 0 {
            nanoseconds += 1_000_000_000
            seconds -= 1
        }

        return Instant(
            _unchecked: (),
            secondsSinceUnixEpoch: seconds,
            nanosecondFraction: Int32(nanoseconds)
        )
    }
}
