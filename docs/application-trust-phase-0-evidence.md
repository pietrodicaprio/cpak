# Application Trust POC Phase 0 Evidence

- Status: review-ready, pending the complete Linux race gate
- Baseline: cpak v2.6.0 (`12e835c`)
- Branch: `poc/application-trust-framework`
- Last updated: 2026-08-18

## 1. Scope and outcome

Phase 0 freezes the trust semantics required before implementation changes any
production storage or verification path. It adds no production dependency and
changes no runtime behavior.

The review set is:

- `application-trust-contracts.md`: API, ABI, media-type, identity, trust,
  timestamp, revocation, reputation, and migration decisions;
- `application-trust-test-matrix.md`: requirement-to-evidence map through the
  final POC;
- `testdata/application-trust-v2.6.0`: captured legacy representations;
- the three `legacy_fixture_test.go` files that bind those representations to
  the current implementation.

Development is isolated in `pietrodicaprio/cpak`. No commit, push, issue, pull
request, release, or external project message is part of Phase 0.

## 2. Acceptance ledger

| Phase 0 requirement | Evidence | Status |
| --- | --- | --- |
| Evidence envelope and OCI media types frozen | Contract sections 3 and 4 | Satisfied |
| Normalized publisher IDs frozen | Contract section 5 | Satisfied |
| Legacy ledger decoding and ABI strategy frozen | Contract sections 3, 4.3, and 4.4 | Satisfied |
| CMS implementation evaluated | Section 3 below and contract section 7 | Satisfied |
| Root source and update model frozen | Contract section 10 | Satisfied |
| Timestamp and revocation semantics frozen | Contract sections 8 and 9 | Satisfied |
| Reputation snapshot and policy modes frozen | Contract sections 11 and 12 | Satisfied |
| Every new on-disk or OCI format versioned | Contract sections 4, 10, and 12 | Satisfied |
| Legacy formats captured before storage changes | Frozen fixtures and fixture tests | Satisfied |
| No unapproved production dependency change | No `go.mod` or `go.sum` change | Satisfied |
| Security-semantic decisions resolved | Section 4 below | Satisfied |
| Current fixtures execute against their decode and verification paths | Signature and policy pass natively; the ledger test passes with a Darwin-only compile harness and compiles unchanged for Linux | Satisfied |
| Complete Phase 0 race gate executes on Linux | Requires a Linux runner because the baseline contains Linux-only syscall paths without Darwin build tags | Pending |

## 3. CMS implementation evaluation

The POC selects the versions of `github.com/digitorus/pkcs7` and
`github.com/digitorus/timestamp` already pinned indirectly by the v2.6.0
Sigstore graph. Promotion to direct dependencies is deferred to Phase 2 and
requires an explicit module and licence diff.

| Criterion | Result |
| --- | --- |
| Detached content | Supported by setting detached content explicitly; cpak supplies only the canonical state |
| Signer selection | Library exposes signer access; cpak must require exactly one signer before verification |
| Chain control | `VerifyWithOpts` accepts explicit roots, intermediates, key usages, and time; the convenience `Verify` method is forbidden because it may omit chain validation |
| Timestamp handling | Companion package parses RFC 3161; cpak separately validates the imprint, TSA chain, EKU, time, and revocation |
| Malformed ASN.1 | Library parsing alone is insufficient; a cpak wrapper validates exact outer DER, size, trailing bytes, signer count, attributes, and algorithm parameters, backed by corpus and fuzz tests |
| Algorithm coverage | POC admits RSA PKCS#1 v1.5 and ECDSA with SHA-2; RSA-PSS and ambiguous or unsupported parameters fail closed |
| Maintenance | Both upstream repositories showed activity in 2025 during the Phase 0 review; neither has a stable v1 API |
| Transitive cost | Both packages are already in the baseline module graph; Phase 2 promotion adds no new transitive tree at the reviewed baseline |

Alternatives were not selected because `github/smimesign/ietf-cms` remains
pre-v1 and does not supply the chosen timestamp path, the Mozilla package is
deprecated, and newer packages would add a new graph without eliminating the
cpak-owned security wrapper.

## 4. Security review

### 4.1 Trust boundaries

The review treats OCI evidence, CMS/ASN.1, certificates, CRLs, root-source
reports, local root files, reputation snapshots, policy files, and all display
strings as attacker-controlled until their respective validation succeeds.
The unprivileged CLI is separate from the privileged authority. The authority
reconstructs and reverifies state before enrolment; it does not trust a CLI
success result.

An authenticated root administrator may intentionally replace trust material
or roll back privileged state. Preventing that action is outside the POC threat
model. Unprivileged replacement, path manipulation, ambiguous decoding, and
rollback are in scope.

### 4.2 Resolved findings

| Severity | Finding and misuse path | Resolution | Required negative evidence |
| --- | --- | --- | --- |
| High | Treating every certificate listed by a source report as trusted would let source filtering or status errors silently expand the root set | Reports are candidate inputs only; the embedded bundle is an explicit, fingerprinted, individually reviewed allowlist | Root generator rejects disabled, unreviewed, mismatched, malformed, and duplicate entries |
| High | Using CMS `signingTime` or a library default time could preserve an expired signer using attacker-controlled time | `signingTime` is descriptive only; only a verified RFC 3161 token extends validity; verifier time is injected by cpak | Forged signing time, expiry boundaries, wrong TSA chain/EKU, and imprint mismatch |
| High | A convenience CMS verification call can validate a signature without validating its chain | The wrapper forbids `PKCS7.Verify()` and constructs explicit `x509.VerifyOptions` | Unknown root and system-root-only cases fail |
| High | A snapshot and separate sequence file could diverge during interruption and permit rollback | One privileged active record contains both signed envelope and sequence and is atomically replaced and durably flushed | Equal/lower sequence and fault-injected replacement tests |
| Medium | Sharing code-signing and TSA pools would allow a root imported for one purpose to acquire the other | Embedded purposes and local directories are separate; dual use requires explicit review/import | Cross-purpose root tests fail |
| Medium | Accepting RSA-PSS without verified parameter handling could create algorithm ambiguity | RSA-PSS is explicitly unsupported for the POC | RSA-PSS corpus fails as unsupported |
| Medium | Putting revocation requirements inside reputation policy would conflate independent decisions | ABI 2 has separate X.509 revocation and reputation policy sections | Policy precedence and ABI rejection tests |
| Medium | Evaluating CRL freshness at a historical timestamp would require an archived CRL and could make long-term validation inconsistent | CRLs must be current at injected `now`; only the revocation entry time is compared with the verified timestamp cutoff | Current/stale CRLs and revocation-before/after-timestamp boundary tests |
| Medium | A publisher-only reputation exception could silently apply to unrelated origins or statuses | Exceptions match exact publisher, canonical origin, allowed status, and optional expiry | Cross-publisher, cross-origin, status, and expiry boundary tests |
| Medium | Unbounded JSON integer sequences can lose precision across RFC 8785 implementations | Sequence is restricted to `1..2^53-1` | Zero, negative, fractional, overflow, equal, and lower values fail |

No unresolved critical or high-severity design finding remains. The Phase 2
dependency promotion and implementation require a fresh review of the actual
wrapper, filesystem operations, trust bundle, and negative-test evidence.

## 5. Verification record

Executed from the repository root using the normal Go module and build caches:

| Check | Result |
| --- | --- |
| `go test ./pkg/signature -run Legacy` | Pass; certificate chain, state signature, Rekor inclusion proof, and RFC 3161 timestamp verify offline |
| `go test ./pkg/trustpolicy -run Legacy` | Pass |
| `go test -modfile=<temporary> -overlay=<temporary> ./pkg/systemauthority -run Legacy` | Pass; the temporary harness changes only unrelated Darwin compilation points in `dabadee` and Linux peer credentials |
| `go test -race ./pkg/signature ./pkg/trustpolicy` | Pass |
| `go vet ./pkg/signature ./pkg/trustpolicy` | Pass |
| `GOOS=linux GOARCH=arm64 go test -c -o /tmp/cpak-systemauthority-phase0.test ./pkg/systemauthority` | Pass; compilation evidence only |
| `GOOS=linux GOARCH=arm64 go test -c -o /tmp/cpak-package-phase0.test ./pkg/cpak` | Pass; compilation evidence only |
| `GOOS=linux GOARCH=arm64 go vet ./pkg/systemauthority ./pkg/cpak` | Pass |
| Strict parse of every fixture JSON with `jq empty` | Pass |
| Secret-pattern scan of Phase 0 files and fixture inventory | Pass; no private key is present |
| `git diff --no-index --check` across every untracked Phase 0 file | Pass |

The native macOS command `go test ./pkg/systemauthority -run Legacy` does not
reach the test. The existing `github.com/mirkobrombin/dabadee/v2@v2.0.1`
dependency assigns Darwin's `int32` `stat.Dev` to `uint64`, and the authority
uses Linux `SO_PEERCRED` without a Darwin build split. A temporary module copy
adds only the two explicit integer conversions, while a workspace overlay
stubs only the unused peer-credential function. With those compile-only
obstacles isolated, the unmodified ledger decoder, strict JSON handling,
`validateEnrolment`, and semantic bundle comparison execute and pass. The
repository, module cache, and production dependency graph remain unchanged.

The complete four-package race command does not run on macOS because other
baseline packages also directly compile Linux-only `O_PATH`, mount, and socket
behavior. The equivalent Linux compile and vet checks pass, but a Linux runner
is still required for direct race execution of the complete gate.

## 6. Completion decision

All format, API, migration, dependency, and security-semantic decisions are
reviewable, every new legacy fixture executes on its relevant path, and
implementation no longer needs to invent trust behavior inside a patch. The
remaining completion gate is narrow: execute the test matrix's complete race
command on Linux and record the result. Until that evidence exists, Phase 0 is
review-ready but not certified complete.
