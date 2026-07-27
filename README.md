# swift-certificates-n5

![Development Status](https://img.shields.io/badge/status-work--in--progress-orange.svg)

Work-in-progress Institute adaptation of Apple's X.509 certificates library: the
chain-verification essence, with cryptography injected rather than linked.

> Forked from [apple/swift-certificates](https://github.com/apple/swift-certificates)
> at `24ccdee` (1.18.0). The upstream history remains reachable below the fork
> point; every retained source file keeps its upstream Apache-2.0 header, and
> `NOTICE.txt` names the SwiftCertificates project.

**This is not the publication tree.** The canonical `swift-certificates` name is
deliberately vacated while the wider Swift ecosystem resolves
`apple/swift-certificates` under that package identity; publication under a
permanent name is a separate, deliberate step.

---

## What this tree is

The `Certificates` library target carries the X.509 model and chain verifier,
reshaped against Institute conventions:

- **Crypto-free, Foundation-free main target.** Signature verification enters
  through an injected `Certificate.Verify` witness (algorithm + raw bytes);
  the production Crypto-backed witness lives with the test target as the
  prototype of a future crypto adapter package.
- **Institute standards owners replace bundled implementations.** ASN.1 via
  ISO 8824/8825, IP addresses via RFC 791/4291, URI parsing via RFC 3986 —
  in place of vendored ASN.1, `inet_pton`, and `Foundation.URL`.
- **Injected verification time.** `Instant` replaces `Foundation.Date`; the
  verifier never reads a system clock.
- **Typed errors.** `CertificateError` is reshaped into a nested
  `Certificate.Error` taxonomy whose payloads carry evidence.

Excluded surfaces — issuance and private keys, CSR, CMS, OCSP, PEM,
RSA/SecKey/SecureEnclave backends, system trust stores — were deleted at the
fork point and are deferred to dedicated future packages, not silently dropped:
git history preserves all of it, and each deferred test names the surface it
needs.

## Test posture

The suite is converted to swift-testing and gates green on the verifier-essence
tier against a frozen DER fixture corpus. A further tier of upstream test files
remains excluded from the test target (see `Package.swift`) pending rewiring
onto the test-target issuance shim; the exclusions are recorded per case in the
fork's deferral ledger.

## License

Apache 2.0, unchanged from upstream — see `LICENSE.txt` and `NOTICE.txt`.
