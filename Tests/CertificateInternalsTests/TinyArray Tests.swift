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
@testable import Certificate_Internals

private func _assertEqual(
    _ expected: @autoclosure () -> some Sequence<Int>,
    initial: @autoclosure () -> _TinyArray<Int>,
    _ mutate: (inout _TinyArray<Int>) -> Void,
    sourceLocation: SourceLocation = #_sourceLocation
) {
    var actual = initial()
    mutate(&actual)
    #expect(Array(actual) == Array(expected()), sourceLocation: sourceLocation)
    let expected = _TinyArray(expected())
    #expect(actual == expected, sourceLocation: sourceLocation)
    var actualHasher = Hasher()
    actualHasher.combine(actual)
    var expectedHasher = Hasher()
    expectedHasher.combine(expected)
    #expect(
        actualHasher.finalize() == expectedHasher.finalize(),
        "\(actual) does not have the same hash as \(expected)",
        sourceLocation: sourceLocation
    )
}

private func assertEqual(
    _ expected: [Int],
    initial: @autoclosure () -> _TinyArray<Int> = _TinyArray(),
    _ mutate: (inout _TinyArray<Int>) -> Void,
    sourceLocation: SourceLocation = #_sourceLocation
) {
    _assertEqual(expected, initial: initial(), mutate, sourceLocation: sourceLocation)
    // get a sequence that is not an `Array` to hit the slow path as well
    _assertEqual(expected.lazy.map { $0 }, initial: initial(), mutate, sourceLocation: sourceLocation)
}

@Suite struct `TinyArray Tests` {
    @Suite struct Unit {
        @Test func `init`() {
            #expect(Array(_TinyArray([Int]())) == [])
            #expect(Array(_TinyArray<Int>()) == [])
            #expect(_TinyArray<Int>() == _TinyArray<Int>([]))

            #expect(Array(_TinyArray<Int>(CollectionOfOne(1))) == [1])
            #expect(Array(_TinyArray<Int>([1])) == [1])
            #expect(Array(_TinyArray<Int>([1, 2])) == [1, 2])

            #expect(Array(_TinyArray<Int>([1, 2, 3])) == [1, 2, 3])
            #expect(Array(_TinyArray<Int>([1, 2, 3, 4])) == [1, 2, 3, 4])
            #expect(Array(_TinyArray<Int>([1, 2, 3, 4, 5])) == [1, 2, 3, 4, 5])
        }

        @Test func `expressible by array literal`() {
            #expect(Array([] as _TinyArray<Int>) == [])
            #expect(Array([1] as _TinyArray<Int>) == [1])
            #expect(Array([1, 2] as _TinyArray<Int>) == [1, 2])
            #expect(Array([1, 2, 3] as _TinyArray<Int>) == [1, 2, 3])
            #expect(Array([1, 2, 3, 4] as _TinyArray<Int>) == [1, 2, 3, 4])
            #expect(Array([1, 2, 3, 4, 5] as _TinyArray<Int>) == [1, 2, 3, 4, 5])
        }

        @Test func `append`() {
            assertEqual([1]) { array in
                array.append(1)
            }
            assertEqual([1, 2]) { array in
                array.append(1)
                array.append(2)
            }
            assertEqual([1, 2, 3]) { array in
                array.append(1)
                array.append(2)
                array.append(3)
            }
            assertEqual([1, 2, 3, 4]) { array in
                array.append(1)
                array.append(2)
                array.append(3)
                array.append(4)
            }
        }

        @Test func `subscript setter`() {
            assertEqual([2]) { array in
                array.append(1)
                array[0] = 2
            }
            assertEqual([3, 4]) { array in
                array.append(1)
                array.append(2)
                array[1] = 4
                array[0] = 3
            }
            assertEqual([4, 5, 6]) { array in
                array.append(1)
                array.append(2)
                array.append(3)
                array[1] = 5
                array[0] = 4
                array[2] = 6
            }
        }

        @Test func `append contents of`() {
            assertEqual([]) { array in
                array.append(contentsOf: [])
            }
            assertEqual([]) { array in
                array.append(contentsOf: [])
                array.append(contentsOf: [])
            }
            assertEqual([1]) { array in
                array.append(contentsOf: [1])
            }
            assertEqual([1]) { array in
                array.append(contentsOf: [1])
                array.append(contentsOf: [])
            }
            assertEqual([1, 2]) { array in
                array.append(contentsOf: [1, 2])
            }
            assertEqual([1, 2]) { array in
                array.append(contentsOf: [1, 2])
                array.append(contentsOf: [])
            }
            assertEqual([1, 2, 3]) { array in
                array.append(contentsOf: [1, 2, 3])
            }
            assertEqual([1, 2, 3, 4]) { array in
                array.append(contentsOf: [1, 2, 3, 4])
            }
            assertEqual([1, 2, 3, 4, 5]) { array in
                array.append(contentsOf: [1, 2, 3, 4, 5])
            }

            assertEqual([1, 2]) { array in
                array.append(contentsOf: [1])
                array.append(contentsOf: [2])
            }
            assertEqual([1, 2, 3]) { array in
                array.append(contentsOf: [1])
                array.append(contentsOf: [2, 3])
            }
            assertEqual([1, 2, 3]) { array in
                array.append(contentsOf: [1, 2])
                array.append(contentsOf: [3])
            }
            assertEqual([1, 2, 3, 4]) { array in
                array.append(contentsOf: [1, 2])
                array.append(contentsOf: [3, 4])
            }
            assertEqual([1, 2, 3, 4]) { array in
                array.append(contentsOf: [1])
                array.append(contentsOf: [2, 3, 4])
            }
            assertEqual([1, 2, 3, 4]) { array in
                array.append(contentsOf: [1, 2, 3])
                array.append(contentsOf: [4])
            }
            assertEqual([1, 2, 3, 4, 5]) { array in
                array.append(contentsOf: [1, 2, 3, 4])
                array.append(contentsOf: [5])
            }
            assertEqual([1, 2, 3, 4, 5]) { array in
                array.append(contentsOf: [1, 2, 3])
                array.append(contentsOf: [4, 5])
            }
            assertEqual([1, 2, 3, 4, 5]) { array in
                array.append(contentsOf: [1, 2])
                array.append(contentsOf: [3, 4, 5])
            }
            assertEqual([1, 2, 3, 4, 5]) { array in
                array.append(contentsOf: [1])
                array.append(contentsOf: [2, 3, 4, 5])
            }
        }

        @Test func `sort`() {
            assertEqual([], initial: []) { array in
                array.sort(by: { lhs, rhs in
                    Issue.record("should never be called")
                    return lhs < rhs
                })
            }
            assertEqual([1], initial: [1]) { array in
                array.sort(by: { lhs, rhs in
                    Issue.record("should never be called")
                    return lhs < rhs
                })
            }
            assertEqual([2, 1], initial: [1, 2]) { array in
                array.sort(by: >)
            }
            assertEqual([3, 2, 1], initial: [1, 2, 3]) { array in
                array.sort(by: >)
            }
        }
    }

    @Suite struct `Edge Case` {
        @Test func `remove at`() {
            assertEqual([], initial: [1]) { array in
                array.remove(at: 0)
            }
            assertEqual([1], initial: [1, 2]) { array in
                array.remove(at: 1)
            }
            assertEqual([2], initial: [1, 2]) { array in
                array.remove(at: 0)
            }
            assertEqual([], initial: [1, 2]) { array in
                array.remove(at: 1)
                array.remove(at: 0)
            }
            assertEqual([], initial: [1, 2]) { array in
                array.remove(at: 0)
                array.remove(at: 0)
            }
            assertEqual([1, 2], initial: [1, 2, 3]) { array in
                array.remove(at: 2)
            }
            assertEqual([1, 3], initial: [1, 2, 3]) { array in
                array.remove(at: 1)
            }
            assertEqual([2, 3], initial: [1, 2, 3]) { array in
                array.remove(at: 0)
            }
            assertEqual([1], initial: [1, 2, 3]) { array in
                array.remove(at: 1)
                array.remove(at: 1)
            }
            assertEqual([2], initial: [1, 2, 3]) { array in
                array.remove(at: 0)
                array.remove(at: 1)
            }
            assertEqual([3], initial: [1, 2, 3]) { array in
                array.remove(at: 1)
                array.remove(at: 0)
            }
            assertEqual([], initial: [1, 2, 3]) { array in
                array.remove(at: 2)
                array.remove(at: 1)
                array.remove(at: 0)
            }
            assertEqual([], initial: [1, 2, 3]) { array in
                array.remove(at: 0)
                array.remove(at: 0)
                array.remove(at: 0)
            }
        }

        @Test func `remove all`() {
            assertEqual([], initial: []) { array in
                array.removeAll(where: { _ in true })
            }
            assertEqual([], initial: [1]) { array in
                array.removeAll(where: { _ in true })
            }
            assertEqual([], initial: [1, 2]) { array in
                array.removeAll(where: { _ in true })
            }
            assertEqual([], initial: [1, 2, 3]) { array in
                array.removeAll(where: { _ in true })
            }
            assertEqual([], initial: [1, 2, 3, 4]) { array in
                array.removeAll(where: { _ in true })
            }
            assertEqual([], initial: [1, 2, 3, 4, 5]) { array in
                array.removeAll(where: { _ in true })
            }

            assertEqual([1], initial: [1]) { array in
                array.removeAll(where: { _ in false })
            }
            assertEqual([1, 2], initial: [1, 2]) { array in
                array.removeAll(where: { _ in false })
            }
            assertEqual([1, 2, 3], initial: [1, 2, 3]) { array in
                array.removeAll(where: { _ in false })
            }
            assertEqual([1, 2, 3, 4], initial: [1, 2, 3, 4]) { array in
                array.removeAll(where: { _ in false })
            }
            assertEqual([1, 2, 3, 4, 5], initial: [1, 2, 3, 4, 5]) { array in
                array.removeAll(where: { _ in false })
            }

            assertEqual([], initial: [1]) { array in
                array.removeAll(where: { Set([1]).contains($0) })
            }
            assertEqual([2], initial: [1, 2]) { array in
                array.removeAll(where: { Set([1]).contains($0) })
            }
            assertEqual([2, 3], initial: [1, 2, 3]) { array in
                array.removeAll(where: { Set([1]).contains($0) })
            }
            assertEqual([2], initial: [1, 2, 3]) { array in
                array.removeAll(where: { Set([1, 3]).contains($0) })
            }
        }
    }

    @Suite struct Integration {
        @Test func `throwing init from result`() throws {
            #expect(Array(try _TinyArray<Int>(CollectionOfOne(Result<_, Error>.success(1)))) == [1])
            #expect(Array(try _TinyArray([Result<_, Error>.success(1)])) == [1])
            #expect(Array(try _TinyArray([Result<_, Error>.success(1), .success(2)])) == [1, 2])
            #expect(Array(try _TinyArray([Result<_, Error>.success(1), .success(2), .success(3)])) == [1, 2, 3])
            #expect(
                Array(try _TinyArray([Result<_, Error>.success(1), .success(2), .success(3), .success(4)]))
                    == [1, 2, 3, 4]
            )
            #expect(
                Array(try _TinyArray([Result<_, Error>.success(1), .success(2), .success(3), .success(4), .success(5)]))
                    == [1, 2, 3, 4, 5]
            )

            struct MyError: Error {}

            #expect(throws: (any Error).self) {
                Array(try _TinyArray<Int>([Result.failure(MyError())]))
            }
            #expect(throws: (any Error).self) {
                Array(try _TinyArray<Int>([Result.failure(MyError()), Result.failure(MyError())]))
            }
            #expect(throws: (any Error).self) {
                Array(try _TinyArray<Int>([.success(1), Result.failure(MyError())]))
            }
            #expect(throws: (any Error).self) {
                Array(try _TinyArray<Int>([.success(1), Result.failure(MyError()), .success(2)]))
            }
            #expect(throws: (any Error).self) {
                Array(try _TinyArray<Int>([.success(1), .success(2), Result.failure(MyError())]))
            }
            #expect(throws: (any Error).self) {
                Array(try _TinyArray<Int>([.success(1), .success(2), Result.failure(MyError()), .success(4)]))
            }
            #expect(throws: (any Error).self) {
                Array(try _TinyArray<Int>([.success(1), .success(2), .success(3), Result.failure(MyError())]))
            }
            #expect(throws: (any Error).self) {
                Array(
                    try _TinyArray<Int>([.success(1), .success(2), .success(3), .success(4), Result.failure(MyError())])
                )
            }
        }
    }
}
