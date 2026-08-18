# Application Trust POC Test Matrix

- Status: Phase 0 baseline and implementation map
- Baseline: cpak v2.6.0 (`12e835c`)
- Last updated: 2026-08-18

## 1. How to read this matrix

Each test ID maps a requirement or mandatory invariant from
`application-trust-poc-plan.md` to concrete evidence. `Existing` identifies a
v2.6.0 test or frozen fixture that already proves the baseline. `Planned`
identifies the phase that must add the test. A phase cannot pass while any row
assigned to it lacks direct evidence or an explicit maintainer-approved
exception.

Unit tests may prove parsers and pure decisions. Claims about privilege,
filesystem ownership, OCI referrers, offline operation, and complete lifecycle
behaviour require the real integration path described in the Evidence column.

## 2. Baseline and migration

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-BAS-001 | Canonical state bytes remain stable | `TestLegacySignatureStateFixtureKeepsItsCanonicalBytes` plus `signature-state-v1.canonical` | 0 | Existing |
| AT-BAS-002 | Current Sigstore v0.3 evidence remains decodable and cryptographically bound to state | `TestLegacySigstoreFixtureReverifiesOffline` | 0 | Existing |
| AT-BAS-003 | Trust-policy ABI 1 remains strictly decodable | `TestLegacyTrustPolicyFixtureStillDecodesStrictly` | 0 | Existing |
| AT-BAS-004 | Flat ledger record with legacy `state` and `bundle` remains valid | `TestLegacyAnchorLedgerFixtureStillDecodesStrictly` | 0 | Existing |
| AT-BAS-005 | Legacy and tagged ledger forms decode to equivalent common evidence | Table test over both fixtures through the Phase 1 decoder | 1 | Planned |
| AT-BAS-006 | Mixed legacy and tagged fields are rejected as ambiguous | Decoder negative fixture | 1 | Planned |
| AT-BAS-007 | Unsupported evidence ABI fails closed | Decoder unit test and authority enrolment test | 1 | Planned |
| AT-BAS-008 | Unknown fields and trailing JSON values fail closed | Decoder table test for evidence, ledger, policy, root bundle, and reputation snapshot | 1-4 | Planned |
| AT-BAS-009 | Reading a legacy record does not rewrite it | Ledger read with before/after byte and mtime comparison | 1 | Planned |
| AT-BAS-010 | A valid update rewrites legacy evidence only to the tagged form | Privileged ledger update integration test | 1 | Planned |

## 3. Signature and exact state binding

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-SIG-001 | Existing Sigstore/OIDC positive verification remains green | Existing `pkg/signature` and `pkg/cpak` signature tests | 1 | Existing |
| AT-SIG-002 | OIDC issuer and repository comparison stays exact | Existing `TestMatchesOriginRefusesEveryLookalike` and identity tests | 1 | Existing |
| AT-SIG-003 | Valid detached CMS over canonical state verifies | X.509 verifier unit test with POC chain | 2 | Planned |
| AT-SIG-004 | Changed origin invalidates evidence | One-field mutation table | 2 | Planned |
| AT-SIG-005 | Changed manifest digest invalidates evidence | One-field mutation table | 2 | Planned |
| AT-SIG-006 | Changed resolved image digest invalidates evidence | One-field mutation table | 2 | Planned |
| AT-SIG-007 | Changed lock digest invalidates evidence | One-field mutation table | 2 | Planned |
| AT-SIG-008 | Changed generation invalidates evidence | One-field mutation table | 2 | Planned |
| AT-SIG-009 | A tag or unresolved image reference is never signed or verified | State and signing CLI negative tests | 2-3 | Planned |
| AT-SIG-010 | Altered CMS signature is invalid | Bit-flip corpus case | 2 | Planned |
| AT-SIG-011 | Altered signer certificate is invalid | Certificate substitution corpus case | 2 | Planned |
| AT-SIG-012 | Malformed, truncated, trailing, BER-only, and oversized CMS fail closed | Parser table plus fuzz corpus | 2 | Planned |
| AT-SIG-013 | Unsupported evidence kind or media type is invalid, not unsigned | Discovery and decoder integration tests | 1-2 | Planned |
| AT-SIG-014 | Zero CMS signers is rejected | CMS signer-count test | 2 | Planned |
| AT-SIG-015 | Multiple CMS signers are rejected as ambiguous | CMS signer-count test | 2 | Planned |
| AT-SIG-016 | Duplicate or ambiguous signed attributes are rejected | Handcrafted DER corpus | 2 | Planned |
| AT-SIG-017 | Valid plus invalid candidates accept the valid candidate and report the invalid one | OCI multi-referrer integration test | 2 | Planned |
| AT-SIG-018 | Foreign plus invalid candidates report foreign/invalid and do not become unsigned | OCI multi-referrer integration test | 1-2 | Planned |
| AT-SIG-019 | All invalid candidates produce invalid, not unsigned | OCI multi-referrer integration test | 1-2 | Planned |
| AT-SIG-020 | Manifest permissions remain in the signed state | Existing state digest tests plus lifecycle mutation test | 1, 5 | Existing/Planned |

## 4. Publisher identity and origin authorization

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-ID-001 | OIDC ID is the SHA-256 of the frozen canonical issuer/repository preimage | Golden vector test | 1 | Planned |
| AT-ID-002 | X.509 ID is lowercase-hex SHA-256 over DER SPKI | Golden vector test against Go and OpenSSL-generated certs | 2 | Planned |
| AT-ID-003 | Same-key certificate renewal preserves X.509 publisher ID | Two-leaf fixture test | 2 | Planned |
| AT-ID-004 | New publisher key creates a different ID | Two-key fixture test | 2 | Planned |
| AT-ID-005 | Display-name changes do not change authorization or reputation ID | Identity and policy table test | 2, 4 | Planned |
| AT-ID-006 | Certificate subject and package metadata never authorize an origin | Same-subject/different-key and spoofed-metadata tests | 2 | Planned |
| AT-ID-007 | X.509 signer covers the exact state containing the origin | CMS state-binding test | 2 | Planned |
| AT-ID-008 | Host policy can restrict an X.509 publisher ID to an exact origin | Policy unit and authority integration test | 2, 5 | Planned |
| AT-ID-009 | Publisher and distributor identities are reported separately | CLI structured-output and explain tests | 5 | Planned |
| AT-ID-010 | Unsafe subject characters cannot inject terminal or log output | Sanitization table and CLI snapshot | 2, 5 | Planned |

## 5. X.509 path, usage, algorithms, and time

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-X509-001 | Chain to an admitted public code-signing root succeeds | Reviewed public-root fixture | 2 | Planned |
| AT-X509-002 | Chain to an explicitly imported local root succeeds | Privileged root-store integration test | 2 | Planned |
| AT-X509-003 | Unknown root fails | Verifier negative test | 2 | Planned |
| AT-X509-004 | Missing or wrong intermediate fails | Chain table test | 2 | Planned |
| AT-X509-005 | Leaf without Code Signing EKU fails | Certificate profile fixture | 2 | Planned |
| AT-X509-006 | Leaf without digital-signature key usage fails | Certificate profile fixture | 2 | Planned |
| AT-X509-007 | Leaf with `CA=true` fails | Certificate profile fixture | 2 | Planned |
| AT-X509-008 | Not-yet-valid leaf fails at both sides of the boundary | Injected-clock table test | 2 | Planned |
| AT-X509-009 | Currently valid leaf without timestamp succeeds as `current` | Injected-clock test | 2 | Planned |
| AT-X509-010 | Expired leaf without verified timestamp fails | Injected-clock test | 2 | Planned |
| AT-X509-011 | Valid RFC 3161 token preserves verification after leaf expiry | POC TSA fixture and injected-clock test | 2-3 | Planned |
| AT-X509-012 | Timestamp message-imprint mismatch fails | RFC 3161 negative fixture | 2 | Planned |
| AT-X509-013 | Untrusted, wrong-EKU, expired, or malformed TSA chain fails | RFC 3161 table test | 2 | Planned |
| AT-X509-014 | CMS `signingTime` alone never extends validity | Expired leaf with forged signing-time attribute | 2 | Planned |
| AT-X509-015 | SHA-1, MD5, DSA, RSA-PSS, unknown parameters, and mismatched algorithm identifiers fail as invalid or explicitly unsupported | Algorithm corpus | 2 | Planned |
| AT-X509-016 | Approved RSA and ECDSA profiles succeed | Certificate/signature matrix | 2 | Planned |
| AT-X509-017 | System TLS roots are not consulted | Test with root installed only in an isolated system pool | 2 | Planned |

## 6. Revocation

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-REV-001 | Current issuer-signed CRL without the serial produces `good` | CRL fixture test | 2 | Planned |
| AT-REV-002 | Applicable CRL entry produces `revoked` and blocks | CRL fixture plus policy precedence test | 2, 5 | Planned |
| AT-REV-003 | No applicable CRL produces `unknown` | CRL fixture test | 2 | Planned |
| AT-REV-004 | Expired or not-yet-valid CRL produces `stale` and blocks | Injected-clock test | 2 | Planned |
| AT-REV-005 | Wrong issuer, invalid signature, and unknown critical extension are rejected | CRL negative table | 2 | Planned |
| AT-REV-006 | A current CRL blocks revocation at or before timestamp time and does not retroactively block a later revocation | Timestamp/CRL boundary test | 2 | Planned |
| AT-REV-007 | No implicit OCSP or network request occurs | Network-deny integration test | 2 | Planned |
| AT-REV-008 | Reputation or publisher exception cannot override revocation | Decision-precedence unit and lifecycle test | 4-5 | Planned |

## 7. Root bundle and local-root administration

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-ROOT-001 | Embedded root manifest is ABI 1, strictly decoded, and fingerprint-verified | Generator check and parser unit test | 2 | Planned |
| AT-ROOT-002 | Every source URL, retrieval time, source hash, licence, and attribution is present | Provenance manifest test | 2 | Planned |
| AT-ROOT-003 | Duplicate, non-root, non-self-signed, and fingerprint-mismatched entries fail generation | Generator negative tests | 2 | Planned |
| AT-ROOT-004 | Code-signing and timestamp purposes load into separate pools | Root-loader unit test | 2 | Planned |
| AT-ROOT-005 | Sectigo example root fingerprint matches reviewed CCADB and Sectigo sources | Provenance check plus documented manual review | 2 | Planned |
| AT-ROOT-006 | Administrator sees subject and exact SHA-256 before confirmation | CLI integration snapshot | 2 | Planned |
| AT-ROOT-007 | Non-root caller cannot add or remove a root | Real polkit/socket integration test on Linux | 2 | Planned |
| AT-ROOT-008 | Symlink, traversal, unsafe parent, unsafe ownership, and writable file are rejected | Filesystem attack table | 2 | Planned |
| AT-ROOT-009 | Root update is atomic across interruption | Fault-injected filesystem test | 2 | Planned |
| AT-ROOT-010 | Duplicate import, removal, and re-addition have deterministic outcomes | CLI lifecycle test | 2 | Planned |
| AT-ROOT-011 | Corrupt embedded bundle or future schema fails as cpak error, not untrusted package | Root-loader negative test | 2 | Planned |
| AT-ROOT-012 | Public and local roots remain distinguishable in explanation output | Structured result and CLI test | 2, 5 | Planned |

## 8. POC CA and signing workflow

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-CA-001 | Offline root signs only dedicated intermediates | Certificate chain inspection script and test | 3 | Planned |
| AT-CA-002 | Code-signing intermediate is `CA=true`, `pathLen=0`, and policy constrained | Certificate profile test | 3 | Planned |
| AT-CA-003 | Leaf is `CA=false`, digital signature, Code Signing EKU, bounded subject | Certificate profile test | 3 | Planned |
| AT-CA-004 | TSA certificate and chain have only the timestamping purpose | Certificate profile test | 3 | Planned |
| AT-CA-005 | No reusable private key or passphrase is tracked | Diff secret scan and file inventory | 3, 6 | Planned |
| AT-CA-006 | Signing accepts an encrypted software key through a safe runtime path | `cpak-sign` integration test with ephemeral key | 3 | Planned |
| AT-CA-007 | Signing boundary accepts `crypto.Signer` without evidence-format changes | Interface and fake-signer unit test | 3 | Planned |
| AT-CA-008 | Clean Linux environment can generate, sign, attach, import, verify, and enrol | End-to-end container/VM script | 3, 5 | Planned |
| AT-CA-009 | Same artifact is untrusted before explicit POC-root import | End-to-end negative step | 3 | Planned |
| AT-CA-010 | Root removal causes full re-verification failure without ledger corruption | End-to-end recovery test | 3 | Planned |
| AT-CA-011 | CLI labels POC assurance experimental | CLI snapshot and wording assertion | 3, 5 | Planned |

## 9. Reputation snapshot and provider

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-REP-001 | Valid fresh configured snapshot is accepted | Snapshot verifier unit test | 4 | Planned |
| AT-REP-002 | Tampered or wrongly signed snapshot is rejected | Bit-flip and wrong-key tests | 4 | Planned |
| AT-REP-003 | Unsupported ABI, unknown fields, duplicate keys, duplicate publisher IDs, and oversize fail closed | Parser table and fuzz corpus | 4 | Planned |
| AT-REP-004 | Expired and future-issued snapshot are unavailable | Injected-clock boundary tests | 4 | Planned |
| AT-REP-005 | Equal or lower sequence is rejected as rollback | Privileged store test | 4 | Planned |
| AT-REP-006 | Wrong provider or key ID is rejected | Provider configuration test | 4 | Planned |
| AT-REP-007 | The single active snapshot record, including its sequence, is durably replaced atomically | Fault-injected store test | 4 | Planned |
| AT-REP-008 | Absent publisher is `unknown`; absent provider is `unavailable` | Provider result table | 4 | Planned |
| AT-REP-009 | All five reputation statuses are deterministic | Signed fixture table | 4 | Planned |
| AT-REP-010 | Reason codes and display text are bounded and terminal-safe | Parser and CLI sanitization tests | 4-5 | Planned |
| AT-REP-011 | Display-name changes cannot hijack reputation identity | Publisher-ID lookup test | 4 | Planned |
| AT-REP-012 | Provider performs no network or telemetry operation | Network-deny integration test | 4 | Planned |

## 10. Policy modes and precedence

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-POL-001 | `off` does not consult reputation | Provider spy test | 4 | Planned |
| AT-POL-002 | `audit` records every result without changing prior allow/deny | Decision table | 4 | Planned |
| AT-POL-003 | `warn` warns on unknown, caution, and unavailable but denies blocked | Decision table | 4 | Planned |
| AT-POL-004 | `require-established` allows only established | Decision table | 4 | Planned |
| AT-POL-005 | Exception applies only to its exact publisher, origin, status, and unexpired time and overrides only unknown or caution | Exception boundary table | 4 | Planned |
| AT-POL-006 | Blocked reputation cannot be overridden | Exception boundary table | 4 | Planned |
| AT-POL-007 | Invalid cryptography, untrusted chain, stale evidence, and revocation precede reputation | Full precedence table | 4-5 | Planned |
| AT-POL-008 | Origin, publisher, approval, and release revocation precede reputation | Full precedence table | 4-5 | Planned |
| AT-POL-009 | Administrator remains the final authority | Real authority enrolment tests | 4-5 | Planned |
| AT-POL-010 | ABI 1 policies retain exact existing semantics | Legacy fixture plus existing trust-policy suite | 1, 5 | Existing/Planned |
| AT-POL-011 | ABI 2 is rejected by an ABI 1 decoder instead of partially applied | Compatibility binary/fixture test | 4 | Planned |

## 11. Lifecycle, explainability, and runtime

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-LIFE-001 | Fresh signed install succeeds for Sigstore and POC X.509 | Real OCI end-to-end matrix | 5 | Planned |
| AT-LIFE-002 | Signed update succeeds for the same publisher and next generation | Real OCI end-to-end matrix | 5 | Planned |
| AT-LIFE-003 | Replayed or downgraded generation fails | Existing ledger downgrade tests plus X.509 path | 1, 5 | Existing/Planned |
| AT-LIFE-004 | Publisher key change is visible and policy-controlled | Update integration test | 5 | Planned |
| AT-LIFE-005 | Signed-to-unsigned transition remains visible and follows policy | Existing enrolment tests plus common evidence path | 1, 5 | Existing/Planned |
| AT-LIFE-006 | Invalid attached evidence never falls back to unsigned | Existing tests plus both evidence kinds | 1-2, 5 | Existing/Planned |
| AT-LIFE-007 | Changed package with stale evidence is not enrolled under old state | Update integration test | 5 | Planned |
| AT-LIFE-008 | Reputation is evaluated at install/update, not every launch | Provider call-count lifecycle test | 5 | Planned |
| AT-LIFE-009 | Launch after provider outage uses anchored runtime integrity without PKI/network work | Network-deny launch test | 5 | Planned |
| AT-LIFE-010 | Trust-root or snapshot correction permits clean retry without corrupt state | Recovery scenarios | 5 | Planned |
| AT-LIFE-011 | CLI separates evidence, publisher, root source, reputation, policy, and final action | Structured and human-output golden tests | 5 | Planned |
| AT-LIFE-012 | CLI never describes signed or established software as safe | Forbidden-vocabulary assertion over all outputs | 5-6 | Planned |
| AT-LIFE-013 | Empty, long, malformed, stale, and unavailable data remain readable and safe | CLI matrix and terminal escape tests | 5 | Planned |
| AT-LIFE-014 | Existing unmanaged-host defaults remain backward compatible | Existing install/enrol/launch suite | 1-5 | Existing/Planned |

## 12. Phase and final verification commands

Phase 0 requires at minimum:

```sh
go test ./pkg/signature -run Legacy
go test ./pkg/systemauthority -run Legacy
go test -race ./pkg/signature ./pkg/trustpolicy ./pkg/systemauthority ./pkg/cpak
go vet ./pkg/signature ./pkg/trustpolicy ./pkg/systemauthority ./pkg/cpak
```

On a non-Linux host, tests that import Linux-sensitive dependencies must be
executed in the project's documented Linux environment; cross-compilation is
evidence of compilation only, not runtime behaviour.

The final POC uses the complete verification gate from
`application-trust-poc-plan.md`, including tagged UI tests, schema generation,
Linux builds, fuzzing, real OCI referrers, offline verification, dependency and
license audit, secret inspection, and the scoped security review.
