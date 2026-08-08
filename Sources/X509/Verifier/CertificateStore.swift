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

import Certificate_Internals

/// A collection of ``Certificate`` objects for use in a verifier.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct CertificateStore: Sendable, Hashable {

  @usableFromInline
  var backing: Backing

  @inlinable
  public init() {
    self.init([])
  }

  /// Wrap a ``CustomCertificateStore`` in a ``CertificateStore`` so the custom
  /// implementation it can be used interchangeably. For details on why one
  /// may decide to implement a ``CustomCertificateStore``, please see the
  /// documentation on that protocol.
  @inlinable
  public init(custom: some CustomCertificateStore) {
    backing = .custom(AnyCustomCertificateStore(custom))
  }

  /// Initialize a certificate store from a sequence of certificates.
  @inlinable
  public init(_ certificates: some Sequence<Certificate>) {
    backing = .concrete(.init(certificates))
  }

  @inlinable
  public mutating func append(_ certificate: Certificate) {
    self.append(contentsOf: CollectionOfOne(certificate))
  }

  @inlinable
  public mutating func append(contentsOf certificates: some Sequence<Certificate>) {
    backing.append(contentsOf: certificates)
  }

  @inlinable
  public func appending(contentsOf certificates: some Sequence<Certificate>) -> Self {
    var copy = self
    copy.append(contentsOf: certificates)
    return copy
  }

  @inlinable
  public func appending(_ certificate: Certificate) -> Self {
    var copy = self
    copy.append(certificate)
    return self
  }

  func resolve(diagnosticsCallback: ((VerificationDiagnostic) -> Void)?) async -> Resolved {
    switch self.backing {
    case .custom(let inner): .custom(inner)
    case .concrete(let inner):
      .concrete(await ConcreteResolved(inner, diagnosticsCallback: diagnosticsCallback))
    }
  }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateStore {
  @usableFromInline
  struct ConcreteBacking: Sendable, Hashable {
    @usableFromInline
    var additionalTrustRoots: [DistinguishedName: [Certificate]]

    @inlinable
    public init(_ certificates: some Sequence<Certificate>) {
      self.additionalTrustRoots = Dictionary(grouping: certificates, by: \.subject)
    }

    @inlinable
    mutating func append(contentsOf certificates: some Sequence<Certificate>) {
      for certificate in certificates {
        self.additionalTrustRoots[certificate.subject, default: []].append(certificate)
      }
    }
  }

  @usableFromInline
  enum Backing: Sendable, Hashable {
    case custom(AnyCustomCertificateStore)
    case concrete(ConcreteBacking)

    @inlinable
    mutating func append(contentsOf certificates: some Sequence<Certificate>) {
      switch self {
      case .custom(var inner):
        inner.append(contentsOf: certificates)
        self = .custom(inner)

      case .concrete(var inner):
        inner.append(contentsOf: certificates)
        self = .concrete(inner)
      }
    }
  }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateStore {
  @usableFromInline
  enum Resolved: Sendable {
    case custom(AnyCustomCertificateStore)
    case concrete(ConcreteResolved)
  }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateStore.Resolved {
  @inlinable
  subscript(subject: DistinguishedName) -> [Certificate]? {
    get async {
      switch self {
      case .custom(let inner): await inner[subject]
      case .concrete(let inner): inner[subject]
      }
    }
  }

  @inlinable
  func contains(_ certificate: Certificate) async -> Bool {
    switch self {
    case .custom(let inner): await inner.contains(certificate)
    case .concrete(let inner): inner.contains(certificate)
    }
  }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateStore {
  @usableFromInline
  struct ConcreteResolved: Sendable {

    @usableFromInline
    var additionalTrustRoots: [DistinguishedName: [Certificate]]

    init(_ store: ConcreteBacking, diagnosticsCallback: ((VerificationDiagnostic) -> Void)?) async {
      additionalTrustRoots = store.additionalTrustRoots
    }
  }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateStore.ConcreteResolved {
  @inlinable
  subscript(subject: DistinguishedName) -> [Certificate]? {
    get {
      additionalTrustRoots[subject]
    }
  }

  @inlinable
  func contains(_ certificate: Certificate) -> Bool {
    additionalTrustRoots[certificate.subject]?.contains(certificate) == true
  }
}
