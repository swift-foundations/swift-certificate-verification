//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022-2023 Apple Inc. and the SwiftCertificates project authors
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
import Time_Primitive

// Time ::= CHOICE {
// utcTime        ISO_8824.UTCTime,
// generalTime    ISO_8824.GeneralizedTime }
@usableFromInline
enum Time: ISO_8825.DER.Parseable, ISO_8825.DER.Serializable, Hashable, Sendable {
    case utcTime(ISO_8824.UTCTime)
    case generalTime(ISO_8824.GeneralizedTime)

    @inlinable
    init(derEncoded rootNode: ISO_8825.Node) throws(ISO_8824.Error) {
        switch rootNode.identifier {
        case ISO_8824.GeneralizedTime.defaultIdentifier:
            self = .generalTime(try ISO_8824.GeneralizedTime(derEncoded: rootNode))
        case ISO_8824.UTCTime.defaultIdentifier:
            self = .utcTime(try ISO_8824.UTCTime(derEncoded: rootNode))
        default:
            throw ISO_8824.Error.unexpectedFieldType(rootNode.identifier)
        }
    }

    @inlinable
    func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .utcTime(let utcTime):
            try coder.serialize(utcTime)
        case .generalTime(let generalizedTime):
            try coder.serialize(generalizedTime)
        }
    }

    // RFC 5280 §4.1.2.5 cutover law: dates through 2049 MUST be encoded as
    // ISO_8824.UTCTime; 2050 and later as ISO_8824.GeneralizedTime. This civil-time conversion
    // transfers to the L2 swift-rfc-5280 owner at the no-duplication
    // reconciliation; it lives in-fork until that lane lands.
    @inlinable
    static func makeTime(from instant: Instant) throws -> Time {
        let components = instant.utcDate

        guard ((1950)..<(2050)).contains(components.year) else {
            let generalizedTime = try ISO_8824.GeneralizedTime(components)
            return .generalTime(generalizedTime)
        }
        let utcTime = try ISO_8824.UTCTime(components)
        return .utcTime(utcTime)
    }
}

extension Instant {
    @inlinable
    package init(fromUTCDate date: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)) {
        self.init(secondsSinceUnixEpoch: Int64(timestampFromUTCDate: date))
    }

    @inlinable
    package var utcDate: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int) {
        // Certificate validity has whole-second precision; the nanosecond
        // fraction is deliberately dropped.
        self.secondsSinceUnixEpoch.utcDateFromTimestamp
    }

    @inlinable
    init(_ time: Time) {
        switch time {
        case .generalTime(let generalizedTime):
            self = .init(generalizedTime)
        case .utcTime(let utcTime):
            self = .init(utcTime)
        }
    }

    @inlinable
    package init(_ time: ISO_8824.GeneralizedTime) {
        self = Instant(
            fromUTCDate: (
                year: time.year, month: time.month, day: time.day, hours: time.hours, minutes: time.minutes,
                seconds: time.seconds
            )
        )
    }

    @inlinable
    package init(_ time: ISO_8824.UTCTime) {
        self = Instant(
            fromUTCDate: (
                year: time.year, month: time.month, day: time.day, hours: time.hours, minutes: time.minutes,
                seconds: time.seconds
            )
        )
    }
}

extension ISO_8824.GeneralizedTime {
    @inlinable
    init(_ time: Time) {
        switch time {
        case .generalTime(let t):
            self = t
        case .utcTime(let t):
            // This can never throw, all valid ISO_8824.UTCTimes are valid ISO_8824.GeneralizedTimes
            self = try! ISO_8824.GeneralizedTime(
                year: t.year,
                month: t.month,
                day: t.day,
                hours: t.hours,
                minutes: t.minutes,
                seconds: t.seconds,
                fractionalSeconds: 0
            )
        }
    }

    @inlinable
    package init(_ components: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)) throws {
        try self.init(
            year: components.year,
            month: components.month,
            day: components.day,
            hours: components.hours,
            minutes: components.minutes,
            seconds: components.seconds,
            fractionalSeconds: 0.0
        )
    }

    @inlinable
    package init(_ instant: Instant) {
        // This cannot throw: any valid Instant can be represented.
        try! self.init(instant.utcDate)
    }
}

extension ISO_8824.UTCTime {
    @inlinable
    package init(_ components: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)) throws {
        try self.init(
            year: components.year,
            month: components.month,
            day: components.day,
            hours: components.hours,
            minutes: components.minutes,
            seconds: components.seconds
        )
    }
}
