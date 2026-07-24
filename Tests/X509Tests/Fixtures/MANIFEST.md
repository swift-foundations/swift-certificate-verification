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

## Additive expansion — server-identity vectors (2026-07-24, lead-confirmed)

The five vectors below were added **additively**: the original 28 above are untouched
(byte-identical to the first freeze), because ECDSA signing uses randomized nonces
and a wholesale regeneration would rewrite every fixture's bytes for no semantic gain.

**Why these were frozen rather than remapped onto existing fixtures.** The consuming
suite (`ServerIdentityPolicy Tests`, 56 cases) packs many scenarios into a single
certificate, whereas this corpus is one-scenario-per-fixture. Remapping its cases onto
the existing leaves would have required rewriting hostnames and assertions — for
example the suite asserts against `*.WILDCARD.EXAMPLE.com` while the corpus carries
`*.example.com` — which **weakens the assertion while appearing to preserve the test**.
Freezing five fixtures to keep 56 assertions verbatim is the deliberate trade.

Consumption note: the suite installs each of these as *both* the trust anchor and the
leaf and runs only `ServerIdentityPolicy`, so chain construction, expiry and signature
validity are not exercised — only the subject DN and SAN contents are load-bearing.

| file | role | notes |
|---|---|---|
| leaf-weirdo-sans.der | leaf identity (multi-scenario) | CN=httpbin.org; 11 SANs: leftmost/suffix/prefix/infix wildcards, trailing period, IDN A-label, IDN A-label+wildcard, non-leftmost wildcard, double wildcard, wildcard+IDN A-label, and an embedded-NUL SAN (issued as DEL 0x7F, byte-patched to 0x00; signature therefore not valid, which the consuming suite does not exercise). GATE rows: wildcard boundaries, IDNA policy, encoding/NUL rejection |
| leaf-multi-san-hosts.der | leaf identity PASS | CN=localhost; SANs dns:localhost, dns:example.com, ip:192.168.0.1, ip:2001:db8::1. GATE row: SAN DNS/IP |
| leaf-multi-cn.der | leaf identity | subject C=US, CN="Ignore me", ST=Nebraska, CN=localhost — two CommonNames, no SAN extension. GATE row: CN-fallback rejection |
| leaf-no-cn.der | leaf identity | subject C=US, ST=Nebraska — no CommonName and no SAN extension. GATE row: CN-fallback rejection |
| leaf-unicode-cn.der | leaf identity | CN=straße.org — raw U-label in the CommonName, no SAN extension. GATE rows: IDNA policy, CN-fallback |
