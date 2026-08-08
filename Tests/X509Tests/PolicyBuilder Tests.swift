// ===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCertificates project authors
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
import Testing
import Time_Primitive

@testable import Certificates

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

private struct Policy: VerifierPolicy {
  var result: PolicyEvaluationResult = .meetsPolicy
  var verifyingCriticalExtensions: [ISO_8824.ObjectIdentifier] = []

  mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async
    -> PolicyEvaluationResult
  {
    result
  }
}

extension PolicyBuilder {
  @Suite struct Test {
    @Suite struct Unit {}
    @Suite struct `Edge Case` {}
    @Suite struct Integration {}
  }
}

extension PolicyBuilder {
  // These suites exercise policy COMPOSITION (the PolicyBuilder DSL and the
  // meets/fails-to-meet plumbing); the policies under test never inspect the
  // certificate, so it is only a vehicle for building a chain. Bound to a frozen
  // DER fixture rather than issued in-test — issuance is an excluded surface in
  // slice 1, and this preserves every assertion in the file unchanged.
  fileprivate static let certificate = try! Fixture.certificate("root-ca")

  fileprivate static let chain = UnverifiedCertificateChain([
    certificate
  ])

  fileprivate static func assertMeetsPolicy(
    @PolicyBuilder makePolicy: () throws -> some VerifierPolicy,
    chain: UnverifiedCertificateChain? = nil,
    sourceLocation: SourceLocation = #_sourceLocation
  ) async rethrows {
    var policy = try makePolicy()
    let result = await policy.chainMeetsPolicyRequirements(chain: chain ?? Self.chain)
    guard case .meetsPolicy = result else {
      Issue.record("\(result)", sourceLocation: sourceLocation)
      return
    }
  }

  fileprivate static func assertFailsToMeetPolicy(
    @PolicyBuilder makePolicy: () throws -> some VerifierPolicy,
    chain: UnverifiedCertificateChain? = nil,
    sourceLocation: SourceLocation = #_sourceLocation
  ) async rethrows {
    var policy = try makePolicy()
    let result = await policy.chainMeetsPolicyRequirements(chain: chain ?? Self.chain)
    guard case .failsToMeetPolicy = result else {
      Issue.record("\(result)", sourceLocation: sourceLocation)
      return
    }
  }
}

extension PolicyBuilder.Test.Unit {
  @Test func `verifying critical extensions with concatenation`() {
    #expect(
      Set(
        AnyPolicy {
          Policy(verifyingCriticalExtensions: [[1, 1]])
        }.verifyingCriticalExtensions
      ) == [
        [1, 1]
      ]
    )

    #expect(
      Set(
        AnyPolicy {
          Policy(verifyingCriticalExtensions: [[1, 1]])
          Policy(verifyingCriticalExtensions: [[1, 2]])
        }.verifyingCriticalExtensions
      ) == [
        [1, 1],
        [1, 2],
      ]
    )

    #expect(
      Set(
        AnyPolicy {
          Policy(verifyingCriticalExtensions: [[1, 1]])
          Policy(verifyingCriticalExtensions: [[1, 2]])
          Policy(verifyingCriticalExtensions: [[1, 3]])
        }.verifyingCriticalExtensions
      ) == [
        [1, 1],
        [1, 2],
        [1, 3],
      ]
    )
  }

  @Test func `verifying critical extensions with if`() {
    let `true` = true
    let `false` = false
    #expect(
      Set(
        AnyPolicy {
          if `true` {
            Policy(verifyingCriticalExtensions: [[1, 1]])
          }
        }.verifyingCriticalExtensions
      ) == [
        [1, 1]
      ]
    )

    #expect(
      Set(
        AnyPolicy {
          if `false` {
            Policy(verifyingCriticalExtensions: [[1, 1]])
          }
        }.verifyingCriticalExtensions
      ) == []
    )
  }

  @Test func `verifying critical extensions with if else`() {
    let `true` = true
    let `false` = false
    #expect(
      Set(
        AnyPolicy {
          if `true` {
            Policy(verifyingCriticalExtensions: [[1, 1]])
          } else {
            Policy(verifyingCriticalExtensions: [[1, 2]])
          }
        }.verifyingCriticalExtensions
      ) == [
        [1, 1]
      ]
    )

    #expect(
      Set(
        AnyPolicy {
          if `false` {
            Policy(verifyingCriticalExtensions: [[1, 1]])
          } else {
            Policy(verifyingCriticalExtensions: [[1, 2]])
          }
        }.verifyingCriticalExtensions
      ) == [
        [1, 2]
      ]
    )
  }

  @Test func `chain meets policy requirements with concatenation`() async {
    await PolicyBuilder.assertMeetsPolicy {
      Policy(result: .meetsPolicy)
    }

    await PolicyBuilder.assertMeetsPolicy {
      Policy(result: .meetsPolicy)
      Policy(result: .meetsPolicy)
    }

    await PolicyBuilder.assertMeetsPolicy {
      Policy(result: .meetsPolicy)
      Policy(result: .meetsPolicy)
      Policy(result: .meetsPolicy)
    }

    await PolicyBuilder.assertFailsToMeetPolicy {
      Policy(result: .failsToMeetPolicy(reason: ""))
    }

    await PolicyBuilder.assertFailsToMeetPolicy {
      Policy(result: .meetsPolicy)
      Policy(result: .failsToMeetPolicy(reason: ""))
    }

    await PolicyBuilder.assertFailsToMeetPolicy {
      Policy(result: .failsToMeetPolicy(reason: ""))
      Policy(result: .meetsPolicy)
    }

    await PolicyBuilder.assertFailsToMeetPolicy {
      Policy(result: .meetsPolicy)
      Policy(result: .meetsPolicy)
      Policy(result: .failsToMeetPolicy(reason: ""))
    }
  }

  @Test func `chain meets policy requirements with if`() async {
    let `true` = true
    let `false` = false
    await PolicyBuilder.assertMeetsPolicy {
      if `true` {
        Policy(result: .meetsPolicy)
      }
    }

    await PolicyBuilder.assertMeetsPolicy {
      if `false` {
        Policy(result: .meetsPolicy)
      }
    }

    await PolicyBuilder.assertFailsToMeetPolicy {
      if `true` {
        Policy(result: .failsToMeetPolicy(reason: ""))
      }
    }

    await PolicyBuilder.assertMeetsPolicy {
      if `false` {
        Policy(result: .failsToMeetPolicy(reason: ""))
      }
    }
  }

  @Test func `chain meets policy requirements with if else`() async {
    let `true` = true
    let `false` = false
    await PolicyBuilder.assertMeetsPolicy {
      if `true` {
        Policy(result: .meetsPolicy)
      } else {
        Policy(result: .meetsPolicy)
      }
    }

    await PolicyBuilder.assertMeetsPolicy {
      if `false` {
        Policy(result: .meetsPolicy)
      } else {
        Policy(result: .meetsPolicy)
      }
    }

    await PolicyBuilder.assertFailsToMeetPolicy {
      if `true` {
        Policy(result: .failsToMeetPolicy(reason: ""))
      } else {
        Policy(result: .meetsPolicy)
      }
    }

    await PolicyBuilder.assertMeetsPolicy {
      if `false` {
        Policy(result: .failsToMeetPolicy(reason: ""))
      } else {
        Policy(result: .meetsPolicy)
      }
    }

    await PolicyBuilder.assertMeetsPolicy {
      if `true` {
        Policy(result: .meetsPolicy)
      } else {
        Policy(result: .failsToMeetPolicy(reason: ""))
      }
    }

    await PolicyBuilder.assertFailsToMeetPolicy {
      if `false` {
        Policy(result: .meetsPolicy)
      } else {
        Policy(result: .failsToMeetPolicy(reason: ""))
      }
    }
  }

  @Test func `any policy type is preserved`() {
    // tested at compile time
    // RFC5280Policy takes the validation instant by injection (Q4 ruling: the
    // verifier never reads a system clock), so this compile-time composition
    // check supplies the corpus's frozen 2026-01-01 instant.
    let _: Verifier<AnyPolicy> = Verifier(rootCertificates: CertificateStore(), verify: .crypto) {
      AnyPolicy {
        RFC5280Policy(validationTime: Instant(secondsSinceUnixEpoch: 1_767_225_600))
      }
    }
  }

  @Test func `all of policies non throwing`() {
    // creating a AllOfPolicies with a non-throwing closure can't throw
    // This is tested at compile time (lack of `try` keyword)
    _ = AllOfPolicies {
      Policy(result: .meetsPolicy)
    }
  }

  @Test func `one of policies non throwing`() {
    // creating a OneOfPolicies with a non-throwing closure can't throw
    // This is tested at compile time (lack of `try` keyword)
    _ = OneOfPolicies {
      Policy(result: .meetsPolicy)
    }
  }
}

extension PolicyBuilder.Test.`Edge Case` {
  @Test func `verifying critical extensions with empty builder`() {
    #expect(
      Set(
        AnyPolicy {

        }.verifyingCriticalExtensions
      ) == []
    )
  }

  @Test func `chain meets policy requirements with empty builder`() async {
    await PolicyBuilder.assertMeetsPolicy {

    }
  }

  @Test func `chain fails policy with one of empty`() async {
    await PolicyBuilder.assertFailsToMeetPolicy {
      OneOfPolicies {}
    }
    let `false` = false
    // This is effectively empty because the branch is never true
    await PolicyBuilder.assertFailsToMeetPolicy {
      OneOfPolicies {
        if `false` {
          Policy(result: .meetsPolicy)
        }
      }
    }

    let policy: Policy? = nil
    // This is effectively empty because the optional is always nil
    await PolicyBuilder.assertFailsToMeetPolicy {
      OneOfPolicies {
        if let policy {
          policy
        }
      }
    }
  }

  @Test func `all of policies throwing`() {
    // Creating a AllOfPolicies which throws an error inside will itself throw
    struct TestError: Error {}
    func throwingPolicyBuilder() throws -> Policy {
      throw TestError()
    }

    #expect(throws: TestError.self) {
      try AllOfPolicies {
        try throwingPolicyBuilder()
      }
    }
  }

  @Test func `one of policies throwing`() {
    // Creating a OneOfPolicies which throws an error inside will itself throw
    struct TestError: Error {}
    func throwingPolicyBuilder() throws -> Policy {
      throw TestError()
    }

    #expect(throws: TestError.self) {
      try OneOfPolicies {
        try throwingPolicyBuilder()
      }
    }
  }
}

extension PolicyBuilder.Test.Integration {
  @Test func `verifying critical extensions with one of`() {
    // When both policies specify the same exts, then the overall policy also has those exts
    #expect(
      Set(
        OneOfPolicies {
          Policy(verifyingCriticalExtensions: [[1, 1]])
          Policy(verifyingCriticalExtensions: [[1, 1]])
        }.verifyingCriticalExtensions
      ) == [
        [1, 1]
      ]
    )
    // When both policies specify the different exts, the overall has the intersection
    #expect(
      Set(
        OneOfPolicies {
          Policy(verifyingCriticalExtensions: [[1, 1], [1, 2]])
          Policy(verifyingCriticalExtensions: [[1, 2], [1, 3]])
        }.verifyingCriticalExtensions
      ) == [
        [1, 2]
      ]
    )
    // Here the sets are disjoint so the overall is empty
    #expect(
      Set(
        OneOfPolicies {
          Policy(verifyingCriticalExtensions: [[1, 1], [1, 2]])
          Policy(verifyingCriticalExtensions: [[1, 3], [1, 4]])
        }.verifyingCriticalExtensions
      ) == []
    )
  }

  @Test func `verifying critical extensions with one of and all of`() {
    // All of means we get all the exts
    #expect(
      Set(
        OneOfPolicies {
          AllOfPolicies {
            Policy(verifyingCriticalExtensions: [[1, 1]])
            Policy(verifyingCriticalExtensions: [[1, 2]])
          }
        }.verifyingCriticalExtensions
      ) == [
        [1, 1], [1, 2],
      ]
    )
    #expect(
      Set(
        OneOfPolicies {
          Policy(verifyingCriticalExtensions: [[1, 1]])
          AllOfPolicies {
            Policy(verifyingCriticalExtensions: [[1, 1]])
            Policy(verifyingCriticalExtensions: [[1, 2]])
          }
        }.verifyingCriticalExtensions
      ) == [
        [1, 1]
      ]
    )
    #expect(
      Set(
        OneOfPolicies {
          Policy(verifyingCriticalExtensions: [[1, 1]])
          AllOfPolicies {
            Policy(verifyingCriticalExtensions: [[1, 2]])
            Policy(verifyingCriticalExtensions: [[1, 3]])
          }
        }.verifyingCriticalExtensions
      ) == []
    )
  }

  @Test func `chain meets policy with one of concatenation both valid`() async {
    await PolicyBuilder.assertMeetsPolicy {
      OneOfPolicies {
        Policy(result: .meetsPolicy)
        Policy(result: .meetsPolicy)
      }
    }
  }

  @Test func `chain meets policy with one of concatenation first valid`() async {
    await PolicyBuilder.assertMeetsPolicy {
      OneOfPolicies {
        Policy(result: .meetsPolicy)
        Policy(result: .failsToMeetPolicy(reason: ""))
      }
    }
  }

  @Test func `chain meets policy with one of concatenation second valid`() async {
    await PolicyBuilder.assertMeetsPolicy {
      OneOfPolicies {
        Policy(result: .failsToMeetPolicy(reason: ""))
        Policy(result: .meetsPolicy)
      }
    }
  }

  @Test func `chain fails to meet policy with one of concatenation both invalid`() async {
    await PolicyBuilder.assertFailsToMeetPolicy {
      OneOfPolicies {
        Policy(result: .failsToMeetPolicy(reason: ""))
        Policy(result: .failsToMeetPolicy(reason: ""))
      }
    }
  }

  @Test func `chain meets policy requirements with one of if else`() async {
    let `true` = true
    let `false` = false
    await PolicyBuilder.assertMeetsPolicy {
      OneOfPolicies {
        Policy(result: .failsToMeetPolicy(reason: ""))
        if `true` {
          Policy(result: .meetsPolicy)
        } else {
          Policy(result: .failsToMeetPolicy(reason: ""))
        }
      }
    }

    await PolicyBuilder.assertMeetsPolicy {
      OneOfPolicies {
        Policy(result: .failsToMeetPolicy(reason: ""))
        if `false` {
          Policy(result: .failsToMeetPolicy(reason: ""))
        } else {
          Policy(result: .meetsPolicy)
        }
      }
    }

    await PolicyBuilder.assertFailsToMeetPolicy {
      OneOfPolicies {
        Policy(result: .failsToMeetPolicy(reason: ""))
        if `true` {
          Policy(result: .failsToMeetPolicy(reason: ""))
        } else {
          Policy(result: .meetsPolicy)
        }
      }
    }
  }

  @Test func `chain meets policy requirements with one of optional`() async {
    let meeting: Policy? = Policy(result: .meetsPolicy)
    let failing: Policy? = Policy(result: .failsToMeetPolicy(reason: ""))
    await PolicyBuilder.assertMeetsPolicy {
      OneOfPolicies {
        if let meeting {
          meeting
        }
      }
    }
    await PolicyBuilder.assertFailsToMeetPolicy {
      OneOfPolicies {
        if let failing {
          failing
        }
      }
    }
  }

  @Test func `chain meets policy with all of`() async {
    await PolicyBuilder.assertMeetsPolicy {
      AllOfPolicies {
        Policy(result: .meetsPolicy)
        Policy(result: .meetsPolicy)
      }
    }
    await PolicyBuilder.assertFailsToMeetPolicy {
      AllOfPolicies {
        Policy(result: .meetsPolicy)
        Policy(result: .failsToMeetPolicy(reason: ""))
      }
    }
  }

  @Test func `chain meets policy with all of and one of`() async {
    await PolicyBuilder.assertMeetsPolicy {
      OneOfPolicies {
        AllOfPolicies {
          Policy(result: .meetsPolicy)
        }
      }
    }
    await PolicyBuilder.assertFailsToMeetPolicy {
      OneOfPolicies {
        AllOfPolicies {
          Policy(result: .failsToMeetPolicy(reason: ""))
        }
      }
    }
    await PolicyBuilder.assertMeetsPolicy {
      OneOfPolicies {
        Policy(result: .meetsPolicy)
        Policy(result: .failsToMeetPolicy(reason: ""))
        AllOfPolicies {
          Policy(result: .meetsPolicy)
          Policy(result: .meetsPolicy)
        }
      }
    }
    await PolicyBuilder.assertFailsToMeetPolicy {
      OneOfPolicies {
        Policy(result: .failsToMeetPolicy(reason: ""))
        AllOfPolicies {
          Policy(result: .meetsPolicy)
          Policy(result: .failsToMeetPolicy(reason: ""))
        }
      }
    }
  }
}
