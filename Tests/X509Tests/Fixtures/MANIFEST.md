# N5 fixture corpus — generation manifest

Generated ONCE in a scratch context and frozen; the publication tree never
contains issuance code. Regeneration requires re-running this scratch tool.

- Generator: fixture-gen (session scratchpad), swift run via coordinator
- Upstream issuance source: apple/swift-certificates @ 24ccdeeeed4dfaae7955fcac9dbf5489ed4f1a25 (1.18.0)
- Crypto backend: apple/swift-crypto @ exact 4.3.0
- Keys: deterministic P256 raw representations (seeds 0x01 root, 0x02 intermediate, 0x03 leaf, 0x04 stranger); Ed25519 root from fixed 32-byte pattern 0x40...
- Validity instants (Unix): 2020=1577836800, 2025=1735689600, 2026=1767225600, 2035=2051222400, 2045=2366841600
- ECDSA signatures use randomized nonces: byte-identical regeneration is NOT expected; semantic content is deterministic

| file | role | notes |
|---|---|---|
| root-ca.der | anchor | P256 self-signed root, cA, 2025-2045 |
| intermediate-ca.der | intermediate | signed by root, cA, no pathLen |
| leaf-valid.der | leaf PASS | SAN dns:example.com, serverAuth EKU, digitalSignature, 2026-2035 |
| leaf-expired.der | leaf FAIL expiry | expired 2025-01-01 |
| leaf-not-yet-valid.der | leaf FAIL expiry | notBefore 2035-01-01 |
| intermediate-expired.der | intermediate FAIL expiry | expired intermediate for mid-chain validity fixtures |
| leaf-wrong-key-signature.der | leaf FAIL signature | claims intermediate as issuer but signed by an unrelated key |
| leaf-tampered-tbs.der | leaf FAIL signature | valid leaf with one TBS byte flipped post-signing (offset 20) |
| intermediate-not-ca.der | intermediate FAIL constraints | basicConstraints cA=false on the issuing intermediate |
| intermediate-pathlen0.der | intermediate | pathLen 0 |
| second-intermediate.der | intermediate FAIL pathlen | child CA under the pathLen-0 intermediate; leaf-under-it violates path length |
| leaf-under-second-intermediate.der | leaf | leaf issued by second-intermediate (pathlen violation when chained via pathlen0) |
| leaf-unknown-critical.der | leaf FAIL constraints | unrecognized critical extension OID 1.3.6.1.4.1.99999.99 |
| leaf-no-eku.der | leaf policy | EKU absent (policy decides; Institute WebPKI gate treats serverAuth as required) |
| leaf-clientauth-only.der | leaf FAIL policy | EKU clientAuth only — serverAuth required |
| leaf-other-eku.der | leaf FAIL policy | EKU ocspSigning only |
| leaf-keyusage-certsign.der | leaf FAIL policy | keyUsage keyCertSign without digitalSignature on an end-entity |
| leaf-multi-san.der | leaf identity PASS | two DNS SANs |
| leaf-ip-san.der | leaf identity | IPv4 192.0.2.1 + IPv6 2001:db8::1 SANs, no DNS SAN |
| leaf-cn-only.der | leaf identity FAIL | no SAN extension; CN=example.com — CN fallback must be REJECTED |
| leaf-nul-san.der | leaf identity FAIL | embedded NUL in DNS SAN (issued as examZple.com, Z byte-patched to 0x00; signature not valid) |
| leaf-idna-alabel.der | leaf identity | IDNA A-label SAN (buecher.example); matches A-label query only |
| leaf-idna-ulabel.der | leaf identity FAIL | raw U-label bücher.example in SAN (issued as bZZcher.example, ZZ patched to UTF-8 U+00FC; signature not valid) — Institute policy rejects non-A-label presentation |
| leaf-wildcard.der | leaf identity | single-label wildcard: matches a.example.com; must NOT match example.com or a.b.example.com |
| leaf-wildcard-broad.der | leaf identity FAIL | wildcard in registrable-domain position |
| leaf-wildcard-partial.der | leaf identity FAIL | partial-label wildcard |
| ed25519-root-ca.der | anchor | Ed25519 self-signed root |
| leaf-ed25519.der | leaf PASS | P256 leaf key, Ed25519 issuer signature |
