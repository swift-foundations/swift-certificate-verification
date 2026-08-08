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
import Testing

@testable import Certificates

extension DistinguishedName {
  @Suite struct Test {
    @Suite struct Unit {}
    @Suite struct `Edge Case` {}
    @Suite struct Integration {}
  }
}

extension DistinguishedName {
  fileprivate static func assertRoundTrips<
    ASN1Object: ISO_8825.DER.Parseable & ISO_8825.DER.Serializable & Equatable
  >(
    _ value: ASN1Object
  ) throws {
    var serializer = ISO_8825.DER.Serializer()
    try serializer.serialize(value)
    let parsed = try ASN1Object(derEncoded: serializer.serializedBytes)
    #expect(parsed == value)
  }
}

extension DistinguishedName.Test.Unit {
  @Test func `simple relative distinguished name sorts its elements`() throws {
    let expected = [
      try RelativeDistinguishedName.Attribute(
        type: .NameAttributes.commonName, printableString: "efgh"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
    ]
    let nameA = RelativeDistinguishedName(expected)
    let nameB = RelativeDistinguishedName(expected.reversed())
    #expect(Array(nameA) == expected)
    #expect(Array(nameB) == expected)
  }

  @Test func `simple relative distinguished name sorts its elements when assigned after the fact`()
    throws
  {
    let expected = [
      try RelativeDistinguishedName.Attribute(
        type: .NameAttributes.commonName, printableString: "efgh"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
    ]
    var nameA = RelativeDistinguishedName()
    var nameB = RelativeDistinguishedName()
    nameA.insert(contentsOf: expected)
    nameB.insert(contentsOf: expected.reversed())
    #expect(Array(nameA) == expected)
    #expect(Array(nameB) == expected)
  }

  @Test func `simple relative distinguished name sorts its elements including by length`() throws {
    let expected = [
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
    ]
    let nameA = RelativeDistinguishedName(expected)
    let nameB = RelativeDistinguishedName(expected.reversed())
    #expect(Array(nameA) == expected)
    #expect(Array(nameB) == expected)
  }

  @Test func `simple relative distinguished name remove at`() throws {
    var rdn = RelativeDistinguishedName([
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
    ])

    #expect(
      rdn.remove(at: 1)
        == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde")
    )
    #expect(
      rdn
        == RelativeDistinguishedName([
          RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
          RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ])
    )

    #expect(
      rdn.remove(at: 0)
        == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd")
    )
    #expect(
      rdn
        == RelativeDistinguishedName([
          RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef")
        ])
    )

    #expect(
      rdn.remove(at: 0)
        == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef")
    )
    #expect(rdn == RelativeDistinguishedName())
  }

  @Test func `simple relative distinguished name remove all`() throws {
    var rdn = RelativeDistinguishedName([
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
    ])

    rdn.removeAll(where: {
      $0 == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde")
    })

    #expect(
      rdn
        == RelativeDistinguishedName([
          RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
          RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ])
    )

    rdn.removeAll(where: {
      $0 == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd")
    })
    #expect(
      rdn
        == RelativeDistinguishedName([
          RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef")
        ])
    )

    rdn.removeAll(where: {
      $0 == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef")
    })
    #expect(rdn == RelativeDistinguishedName())
  }

  @Test func `distinguished name representation`() throws {
    let name = try DistinguishedName([
      RelativeDistinguishedName.Attribute(
        type: .RDNAttributeType.domainComponent, ia5String: "com"),
      RelativeDistinguishedName.Attribute(
        type: .RDNAttributeType.domainComponent, ia5String: "apple"),
      RelativeDistinguishedName.Attribute(
        type: .RDNAttributeType.emailAddress, ia5String: "jon.doe@apple.com"),
      RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US"),
      RelativeDistinguishedName.Attribute(
        type: .RDNAttributeType.organizationName, utf8String: "DigiCert Inc"),
      RelativeDistinguishedName.Attribute(
        type: .RDNAttributeType.organizationalUnitName,
        utf8String: "www.digicert.com"
      ),
      RelativeDistinguishedName.Attribute(
        type: .RDNAttributeType.commonName,
        utf8String: "DigiCert Global Root G3"
      ),

    ])

    let s = String(describing: name)
    let expected =
      "CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US,E=jon.doe@apple.com,DC=apple,DC=com"
    #expect(s == expected)
  }

  @Test func `distinguished name representation with nested attributes`() throws {
    let name = try DistinguishedName([
      RelativeDistinguishedName([
        RelativeDistinguishedName.Attribute(
          type: .RDNAttributeType.domainComponent, ia5String: "com")
      ]),
      RelativeDistinguishedName([
        RelativeDistinguishedName.Attribute(
          type: .RDNAttributeType.domainComponent, ia5String: "apple")
      ]),
      RelativeDistinguishedName([
        RelativeDistinguishedName.Attribute(
          type: .RDNAttributeType.emailAddress,
          ia5String: "jon.doe@apple.com"
        )
      ]),
      RelativeDistinguishedName([
        RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US")
      ]),
      RelativeDistinguishedName([
        RelativeDistinguishedName.Attribute(
          type: .RDNAttributeType.stateOrProvinceName, printableString: "CA"),
        RelativeDistinguishedName.Attribute(
          type: .RDNAttributeType.stateOrProvinceName,
          utf8String: "California"
        ),
      ]),
      RelativeDistinguishedName([
        RelativeDistinguishedName.Attribute(
          type: .RDNAttributeType.organizationName,
          utf8String: "DigiCert Inc"
        )
      ]),
      RelativeDistinguishedName([
        RelativeDistinguishedName.Attribute(
          type: .RDNAttributeType.organizationalUnitName,
          utf8String: "www.digicert.com"
        )
      ]),
      RelativeDistinguishedName([
        RelativeDistinguishedName.Attribute(
          type: .RDNAttributeType.commonName,
          utf8String: "DigiCert Global Root G3"
        )
      ]),
    ])

    let s = String(describing: name)
    let expected =
      "CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,ST=CA+ST=California,C=US,E=jon.doe@apple.com,DC=apple,DC=com"
    #expect(s == expected)
  }

  @Test func `rdn attribute value`() {
    func expectEqualValueAndHash<Value>(
      _ expression1: @autoclosure () throws -> Value,
      _ expression2: @autoclosure () throws -> Value,
      _ message: @autoclosure () -> String = "",
      sourceLocation: SourceLocation = #_sourceLocation
    ) where Value: Hashable {
      let lhs: Value
      do {
        lhs = try expression1()
      } catch {
        Issue.record("\(error)", sourceLocation: sourceLocation)
        return
      }
      let rhs: Value
      do {
        rhs = try expression2()
      } catch {
        Issue.record("\(error)", sourceLocation: sourceLocation)
        return
      }
      #expect(lhs == rhs, sourceLocation: sourceLocation)

      var lhsHasher = Hasher()
      lhsHasher.combine(lhs)
      var rhsHasher = Hasher()
      rhsHasher.combine(rhs)

      #expect(
        lhsHasher.finalize() == rhsHasher.finalize(),
        "hashes should be the same for \(lhs) and \(rhs)",
        sourceLocation: sourceLocation
      )
    }

    expectEqualValueAndHash(
      try RelativeDistinguishedName.Attribute.Value(
        asn1Any: ISO_8825.`Any`(
          erasing: ISO_8824.UTF8String("This is a fancy UTF8 String with Emojies 🥳🐥"))
      ),
      RelativeDistinguishedName.Attribute.Value(
        utf8String: "This is a fancy UTF8 String with Emojies 🥳🐥")
    )

    expectEqualValueAndHash(
      try RelativeDistinguishedName.Attribute.Value(
        asn1Any: ISO_8825.`Any`(
          erasing: ISO_8824.PrintableString("This is a simple printable string 123456789 ():="))
      ),
      try RelativeDistinguishedName.Attribute.Value(
        printableString: "This is a simple printable string 123456789 ():="
      )
    )

    expectEqualValueAndHash(
      try RelativeDistinguishedName.Attribute.Value(
        asn1Any: ISO_8825.`Any`(erasing: ISO_8824.UTF8String(String(repeating: "A", count: 129)))
      ),
      RelativeDistinguishedName.Attribute.Value(utf8String: String(repeating: "A", count: 129))
    )

    expectEqualValueAndHash(
      try RelativeDistinguishedName.Attribute.Value(
        asn1Any: ISO_8825.`Any`(
          erasing: ISO_8824.UTF8String(String(repeating: "A", count: Int(UInt16.max) + 1)))
      ),
      RelativeDistinguishedName.Attribute.Value(
        utf8String: String(repeating: "A", count: Int(UInt16.max) + 1))
    )
  }
}

extension DistinguishedName.Test.`Edge Case` {
  @Test func `simple relative distinguished name remove all in one go`() throws {
    var rdn = RelativeDistinguishedName([
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
    ])

    rdn.removeAll(where: { _ in true })

    #expect(rdn == RelativeDistinguishedName())
  }

  @Test func `distinguished name representation with commas and newlines`() throws {
    let name = try DistinguishedName([
      RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US "),
      RelativeDistinguishedName.Attribute(
        type: .RDNAttributeType.organizationName, utf8String: " DigiCert Inc"),
      RelativeDistinguishedName.Attribute(
        type: .RDNAttributeType.organizationalUnitName,
        utf8String: "#www.digicert.com"
      ),
      RelativeDistinguishedName.Attribute(
        type: .RDNAttributeType.commonName, utf8String: ",+\"\\<>;"),
    ])

    let s = String(describing: name)
    #expect(s == "CN=\\,\\+\\\"\\\\\\<\\>\\;,OU=\\#www.digicert.com,O=\\ DigiCert Inc,C=US\\ ")
  }

  @Test func `rdn attribute values can be converted to strings`() throws {
    let examplesAndResults: [(RelativeDistinguishedName.Attribute, String?)] = try [
      (.init(type: .RDNAttributeType.commonName, printableString: "foo"), "foo"),
      (.init(type: .RDNAttributeType.commonName, utf8String: "bar"), "bar"),
      (.init(type: .RDNAttributeType.commonName, ia5String: "foo"), "foo"),
      /// ISO_8824.IA5String with wrong tag
      (
        .init(
          type: .RDNAttributeType.commonName,
          value: ISO_8825.`Any`(derEncoded: [0x19, 0x03, 0x41, 0x42, 0x43])),
        nil
      ),
      /// ISO_8824.IA5String byte that falls outside the range of 7-bit ASCII
      (
        .init(
          type: .RDNAttributeType.commonName,
          value: ISO_8825.`Any`(derEncoded: [0x16, 0x03, 0x41, 0x42, 0x80])),
        nil
      ),
    ]

    for (example, result) in examplesAndResults {
      #expect(String(example.value) == result)
    }
  }

  @Test func `rdn attribute values can be converted to strings in some of the any cases too`()
    throws
  {
    let weirdOID: ISO_8824.ObjectIdentifier = [1, 2, 3, 4, 5]

    let examplesAndResults: [(RelativeDistinguishedName.Attribute, String?)] = try [
      (.init(type: weirdOID, printableString: "foo"), "foo"),
      (.init(type: weirdOID, utf8String: "bar"), "bar"),
      (.init(type: weirdOID, value: ISO_8825.`Any`(erasing: ISO_8824.UTF8String("foo"))), "foo"),
      (
        .init(type: weirdOID, value: ISO_8825.`Any`(erasing: ISO_8824.PrintableString("baz"))),
        "baz"
      ),
      (.init(type: weirdOID, value: ISO_8825.`Any`(erasing: ISO_8824.IA5String("foo"))), "foo"),
      (.init(type: weirdOID, value: ISO_8825.`Any`(erasing: 5)), nil),
      (
        .init(
          type: weirdOID,
          value: ISO_8825.`Any`(erasing: ISO_8824.OctetString(contentBytes: [1, 2, 3, 4]))), nil
      ),
    ]

    for (example, result) in examplesAndResults {
      #expect(String(example.value) == result)
    }
  }

  @Test func `rdn attribute values can be parsed when printable string is invalid`() throws {
    // '&' is not allowed in PrintableString.
    let value = try ISO_8825.`Any`(
      erasing: ISO_8824.UTF8String("Wells Fargo & Company"), withIdentifier: .printableString)

    let attribute = try RelativeDistinguishedName.Attribute(derEncoded: [
      0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x15, 0x57, 0x65, 0x6c, 0x6c, 0x73, 0x20,
      0x46, 0x61, 0x72, 0x67, 0x6f, 0x20, 0x26, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x79,
    ])

    #expect(attribute.type == .RDNAttributeType.organizationName)
    #expect(attribute.value == RelativeDistinguishedName.Attribute.Value(asn1Any: value))
    #expect(String(attribute.value) == nil)
  }
}

extension DistinguishedName.Test.Integration {
  @Test func `simple relative distinguished name round trips`() throws {
    let name = RelativeDistinguishedName([
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
      try RelativeDistinguishedName.Attribute(
        type: .NameAttributes.commonName, printableString: "efgh"),
    ])
    try DistinguishedName.assertRoundTrips(name)
  }

  @Test func `simple relative distinguished name serializes as expected`() throws {
    let name = RelativeDistinguishedName([
      try RelativeDistinguishedName.Attribute(
        type: .NameAttributes.commonName, printableString: "efgh"),
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
    ])

    var serializer = ISO_8825.DER.Serializer()
    try serializer.serialize(name)

    let expectedBytes: [UInt8] = [
      49, 26, 48, 11, 6, 3, 85, 4, 3, 19, 4, 0x65, 0x66, 0x67, 0x68, 48, 11, 6, 3, 85, 4, 41, 12, 4,
      0x61, 0x62,
      0x63, 0x64,
    ]

    #expect(serializer.serializedBytes == expectedBytes)
  }

  @Test func `simple distinguished name round trips`() throws {
    let firstName = RelativeDistinguishedName([
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
      try RelativeDistinguishedName.Attribute(
        type: .NameAttributes.commonName, printableString: "efgh"),
    ])
    let secondName = RelativeDistinguishedName([
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "ijkl"),
      try RelativeDistinguishedName.Attribute(
        type: .NameAttributes.commonName, printableString: "mnop"),
    ])
    let name = DistinguishedName([firstName, secondName])
    try DistinguishedName.assertRoundTrips(name)
  }

  @Test func `simple distinguished name serializes as expected`() throws {
    let firstName = RelativeDistinguishedName([
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
      try RelativeDistinguishedName.Attribute(
        type: .NameAttributes.commonName, printableString: "efgh"),
    ])
    let secondName = RelativeDistinguishedName([
      RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "ijkl"),
      try RelativeDistinguishedName.Attribute(
        type: .NameAttributes.commonName, printableString: "mnop"),
    ])
    let name = DistinguishedName([firstName, secondName])

    var serializer = ISO_8825.DER.Serializer()
    try serializer.serialize(name)

    let expectedBytes: [UInt8] = [
      48, 56, 49, 26, 48, 11, 6, 3, 85, 4, 3, 19, 4, 0x65, 0x66, 0x67, 0x68, 48, 11, 6, 3, 85,
      4, 41, 12, 4, 0x61, 0x62, 0x63, 0x64, 49, 26, 48, 11, 6, 3, 85, 4, 3, 19, 4, 0x6d, 0x6e, 0x6f,
      0x70, 48, 11, 6, 3, 85, 4, 41, 12, 4, 0x69, 0x6a, 0x6b, 0x6c,
    ]

    #expect(serializer.serializedBytes == expectedBytes)
  }

  // `distinguished name builder` and `distinguished name builder flow` were
  // deferred here: they test the DistinguishedNameBuilder result-builder DSL,
  // which is an excluded (issuance-side) surface in slice 1. See the
  // deferred-tests ledger. The 17 remaining cases are DN/RDN essence.
}
