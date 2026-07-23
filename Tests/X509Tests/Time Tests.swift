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

import Testing
import ISO_8824
import ISO_8825
import Time_Primitive
@testable import Certificates

// gmtime_r/time_t for the reference comparison against the system library.
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

extension Certificates.Time {
    @Suite struct Test {
        @Suite struct Unit {}
        @Suite struct `Edge Case` {}
        @Suite struct Integration {}
    }
}

extension Certificates.Time.Test.Unit {
    @Test func `convert utc time to instant`() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let utctime = try ISO_8824.UTCTime(year: 2022, month: 07, day: 01, hours: 12, minutes: 15, seconds: 55)
        let expected = Instant(secondsSinceUnixEpoch: 1_656_677_755)
        #expect(expected == Instant(.utcTime(utctime)))
    }

    @Test func `convert generalized time to instant`() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let generalizedTime = try ISO_8824.GeneralizedTime(
            year: 2022,
            month: 07,
            day: 01,
            hours: 12,
            minutes: 15,
            seconds: 55,
            fractionalSeconds: 0.0
        )
        let expected = Instant(secondsSinceUnixEpoch: 1_656_677_755)
        #expect(expected == Instant(.generalTime(generalizedTime)))
    }

    @Test func `convert utc time as time to instant`() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let utctime = try ISO_8824.UTCTime(year: 2022, month: 07, day: 01, hours: 12, minutes: 15, seconds: 55)
        let time = Certificates.Time.utcTime(utctime)
        let expected = Instant(secondsSinceUnixEpoch: 1_656_677_755)
        #expect(expected == Instant(time))
    }

    @Test func `convert generalized time as time to instant`() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let generalizedTime = try ISO_8824.GeneralizedTime(
            year: 2022,
            month: 07,
            day: 01,
            hours: 12,
            minutes: 15,
            seconds: 55,
            fractionalSeconds: 0.0
        )
        let time = Certificates.Time.generalTime(generalizedTime)
        let expected = Instant(secondsSinceUnixEpoch: 1_656_677_755)
        #expect(expected == Instant(time))
    }

    @Test func `we handle hours minutes and seconds properly`() throws {
        var timestamp = Int64(0)

        for hours in 0..<24 {
            for minutes in 0..<60 {
                for seconds in 0..<60 {
                    let computed = timestamp.utcDateFromTimestamp

                    #expect(computed.year == 1970)
                    #expect(computed.month == 1)
                    #expect(computed.day == 1)
                    #expect(computed.hours == hours)
                    #expect(computed.minutes == minutes)
                    #expect(computed.seconds == seconds)

                    let reversed = Int64(timestampFromUTCDate: computed)
                    #expect(reversed == timestamp)

                    // Add 1 second and keep going.
                    timestamp += 1
                }
            }
        }
    }
}

extension Certificates.Time.Test.`Edge Case` {
    @Test func `specific inputs for gm time`() throws {
        // These numbers are determined experimentally on macOS.
        let smallestUsableTimeT = Int64(-67_768_040_609_740_800)
        let largestUsableTimeT = Int64(67_768_036_191_676_799)
        let epoch = Int64(0)

        let smallestTime = smallestUsableTimeT.utcDateFromTimestamp
        let largestTime = largestUsableTimeT.utcDateFromTimestamp
        let epochTime = epoch.utcDateFromTimestamp

        #expect(smallestTime.year == -2_147_481_748)
        #expect(smallestTime.month == 1)
        #expect(smallestTime.day == 1)
        #expect(smallestTime.hours == 0)
        #expect(smallestTime.minutes == 0)
        #expect(smallestTime.seconds == 0)

        #expect(largestTime.year == 2_147_485_547)
        #expect(largestTime.month == 12)
        #expect(largestTime.day == 31)
        #expect(largestTime.hours == 23)
        #expect(largestTime.minutes == 59)
        #expect(largestTime.seconds == 59)

        #expect(epochTime.year == 1970)
        #expect(epochTime.month == 1)
        #expect(epochTime.day == 1)
        #expect(epochTime.hours == 0)
        #expect(epochTime.minutes == 0)
        #expect(epochTime.seconds == 0)

        // Test we convert back correctly.
        #expect(smallestUsableTimeT == Int64(timestampFromUTCDate: smallestTime))
        #expect(largestUsableTimeT == Int64(timestampFromUTCDate: largestTime))
        #expect(epoch == Int64(timestampFromUTCDate: epochTime))
    }

    @Test func `handle days and leap years properly`() throws {
        // Start from Sat, 01 Jan 1600 00:00:00 and test every day between then and the year 3000.
        // This tests our year-based computations are probably correct.
        var timestamp = Int64(-11_676_096_000)

        for year in 1600..<3000 {
            let isLeapYear = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)

            for month in 1...12 {
                let days: Int

                switch month {
                case 1, 3, 5, 7, 8, 10, 12:
                    days = 31
                case 4, 6, 9, 11:
                    days = 30
                case 2:
                    days = isLeapYear ? 29 : 28
                default:
                    fatalError()
                }

                for day in 1...days {
                    let computed = timestamp.utcDateFromTimestamp

                    #expect(computed.year == year)
                    #expect(computed.month == month)
                    #expect(computed.day == day)
                    #expect(computed.hours == 0)
                    #expect(computed.minutes == 0)
                    #expect(computed.seconds == 0)

                    let reversed = Int64(timestampFromUTCDate: computed)
                    #expect(reversed == timestamp)

                    // The number of seconds in 1 day.
                    timestamp += 24 * 60 * 60
                }
            }
        }
    }
}

extension Certificates.Time.Test.Integration {
    @Test func `compare random inputs for gm time`() throws {
        // These numbers are determined experimentally on macOS.
        let smallestUsableTimeT = Int64(-67_768_040_609_740_800)
        let largestUsableTimeT = Int64(67_768_036_191_676_799)

        // If we're constrained by the system library time_t size, let's do that.
        let lowerBound = max(smallestUsableTimeT, Int64(time_t.min))
        let upperBound = min(largestUsableTimeT, Int64(time_t.max))

        for _ in 0..<10_000 {
            let random = Int64.random(in: lowerBound...upperBound)
            let mine = random.utcDateFromTimestamp

            var time = time_t(random)
            var theirs = tm()
            #expect(gmtime_r(&time, &theirs) != nil, "Seed: \(random)")

            #expect(mine.year == Int(theirs.tm_year) + 1900, "Seed: \(random)")
            #expect(mine.month == Int(theirs.tm_mon) + 1, "Seed: \(random)")
            #expect(mine.day == Int(theirs.tm_mday), "Seed: \(random)")
            #expect(mine.hours == Int(theirs.tm_hour), "Seed: \(random)")
            #expect(mine.minutes == Int(theirs.tm_min), "Seed: \(random)")
            #expect(mine.seconds == Int(theirs.tm_sec), "Seed: \(random)")

            let returned = Int64(timestampFromUTCDate: mine)
            #expect(returned == random)
        }
    }
}
