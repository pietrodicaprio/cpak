# Application Trust POC Phase 2 Evidence

- Status: complete
- Baseline: Phase 1 (`3559e4239f1b590ba7270f3a8f6897db2e945f15`)
- Branch: `poc/application-trust-framework`
- Last updated: 2026-08-19

## 1. Scope and outcome

Phase 2 adds the X.509/CMS verification adapter and its dedicated trust-root
boundary without changing the existing Sigstore/OIDC evidence profile. Both
formats use the same tagged evidence envelope, OCI candidate selection,
privileged enrolment record, and authority-side re-verification path.

The implementation is split into reviewable milestones:

| Commit | Boundary |
| --- | --- |
| `4af38a7` | Strict CMS verifier, RFC 3161 validation, CRL evaluation, embedded/public and local trust material, negative and fuzz corpus |
| `907be5b` | X.509 OCI discovery, mixed-candidate behavior, enrolment, and independent authority re-verification |
| `fb88e60` | Root preview/add/remove/status commands and X.509 evidence diagnostics |
| `80b2c77` | Security hardening for TSA algorithms, CRL issuer usage, weak algorithms, malformed timestamps, unsafe subjects, and invalid roots |
| `f46bf2c` | Phase 2 requirement-to-evidence map and pre-Linux certification record |
| `2cc6779` | Linux-discovered correction to the OCI diagnostic assertion |

No pull request, release, tag, or change to the official Containerpak
repository is part of this phase.

## 2. Trust and verification invariants

- CMS is one strict DER `SignedData` value with detached canonical state,
  exactly one signer, exactly one declared digest, and unique signed
  attributes.
- Only SHA-256, SHA-384, or SHA-512 with RSA PKCS#1 v1.5 or ECDSA is accepted.
  SHA-1, MD5, DSA, RSA-PSS, ambiguous parameters, and mismatched identifiers
  fail closed.
- cpak constructs explicit code-signing and timestamping `x509.VerifyOptions`.
  Production verification never calls the chain-optional `PKCS7.Verify()`
  convenience method and never consults the host TLS root pool.
- CMS `signingTime` does not extend certificate life. Only a signature
  timestamp token whose imprint covers the CMS signature and whose dedicated
  TSA certificate chains to the separate timestamp pool can do so.
- CRLs come only from bounded, root-owned offline cache directories. Freshness
  is evaluated at cpak's injected current time; revocation time is compared
  with the verified signing-time cutoff. Revoked and stale evidence blocks;
  absent applicable evidence is reported as `unknown`.
- X.509 publisher identity is SHA-256 over DER SubjectPublicKeyInfo. Certificate
  renewal over the same key preserves identity; key rotation changes it.
- Public and administrator roots are different result states. A root admitted
  for code signing is not admitted for timestamping unless separately listed
  for that purpose.
- The authority records evidence, not a verdict. It reconstructs the tagged
  envelope and runs the common verifier again before every write and read.

## 3. Public-root provenance

The embedded ABI 1 manifest is an explicit two-certificate allowlist, not a
dynamic import of a CA or operating-system root program.

| Root | SHA-256 fingerprint | Purpose |
| --- | --- | --- |
| Sectigo Public Code Signing Root R46 | `7e76260ae69a55d3f060b0fd18b2a8c01443c87b60791030c9fa0b0585101a38` | code signing |
| Sectigo Public Code Signing Root E46 | `8f6371d8cc5aa7ca149667a98b5496398951e4319f7afbcc6a660d673e438d0b` | code signing |

The reviewed CCADB Microsoft Code Signing report was retrieved at
`2026-08-19T07:20:25Z`; the exact downloaded bytes have SHA-256
`7686156ec2528a6dc6ee1a03afef15a9d626420e6ba73e7d4d8e050326c684e1`.
Sectigo's current chain documentation was captured at the same time with
SHA-256
`349d4f2b5b95486085c82343811525586012bfe59f13d3b478cddb45017c7c80`.
The manifest records the exact URLs, retrieval time, digests, CDLA attribution,
and reference-only Sectigo source label. Tests decode the embedded DER and
recompute both root fingerprints.

## 4. Administrator root and CRL boundary

The default security boundary is `/etc/cpak/trust`:

- `code-signing.d`: local publisher roots;
- `timestamping.d`: local TSA roots;
- `revocation/code-signing.d`: cached publisher-chain CRLs;
- `revocation/timestamping.d`: cached TSA-chain CRLs.

Every component from the boundary down must be a real directory with the
configured privileged owner and no group/other write bit. Admitted root and
CRL files must be regular, non-symlink, owner-controlled, bounded files. Root
imports bind the unprivileged preview to an exact lowercase SHA-256, write and
flush a private temporary file, and commit with a no-overwrite hard link.
Fault-injection tests prove that failure before the link leaves no admitted
file and failure after the link leaves a complete parseable root rather than a
partial destination.

The CLI previews the certificate subject, exact fingerprint, and validity
window before confirmation. A non-root invocation passes the confirmed
fingerprint across the existing privileged command boundary; the privileged
side reparses the source and rejects any mismatch.

## 5. Dependency and licence review

`github.com/digitorus/pkcs7` at
`v0.0.0-20230818184609-3a137a874352` is MIT licensed.
`github.com/digitorus/timestamp` at
`v0.0.0-20231217203849-220c5c2851b7` is BSD-2-Clause licensed and is used to
construct independent RFC 3161 test fixtures. Both versions already existed
in the Phase 1 module graph through Sigstore; Phase 2 promotes them from
indirect to direct requirements and changes no `go.sum` entry or transitive
version.

The production timestamp verifier parses the bounded TSTInfo itself after the
strict CMS wrapper. This avoids the companion parser's internal convenience
signature check and ensures that only cpak's explicit TSA roots, EKU, time,
algorithm, and revocation decisions determine acceptance.

## 6. Security review

| Severity | Misuse path | Resolution and evidence |
| --- | --- | --- |
| Critical | A CMS signature verifies without a trusted chain | Explicit roots and EKU are mandatory; unknown, missing, wrong, and system-only chains fail |
| High | An attacker changes one state field while reusing evidence | Canonical origin, manifest, image, lock, and generation mutations all fail |
| High | A certificate or signed attribute is substituted or made ambiguous | Certificate mutation, zero/multiple signer, repeated attribute, digest-count, and algorithm-identifier corpus fails |
| High | Attacker-controlled time preserves an expired publisher | Only verified RFC 3161 time extends validity; imprint, TSA trust/EKU/expiry, and malformed-token cases fail |
| High | Revoked or stale evidence is softened into unknown or reputation | Revoked and stale are explicit blocking results before later policy phases |
| High | The host TLS pool silently expands code-signing trust | Dedicated pools only; a root installed solely through `SSL_CERT_FILE` remains untrusted |
| High | An unprivileged path swap changes the root after confirmation | Fingerprint-bound reparse, component ownership checks, symlink refusal, bounded regular files, and atomic no-overwrite commit |
| Medium | A code-signing root becomes a TSA root implicitly | Separate directories, pools, purposes, and tests |
| Medium | Subject or diagnostic bytes inject terminal control sequences | Display values and diagnostics remove controls and enforce byte bounds |
| Medium | Malformed ASN.1 exhausts resources or reaches inconsistent parsers | One MiB evidence limit, strict outer parse, negative corpus, and bounded fuzzing |

No unresolved critical or high-severity implementation finding remains in the
reviewed Phase 2 scope. Reputation decisions, publisher exceptions, live
escalation frontend interaction, and the complete install/update lifecycle
remain assigned to later phases and cannot weaken these cryptographic results.

## 7. Verification record

Executed from the repository root using the normal Go module and build caches:

| Check | Current result |
| --- | --- |
| `go test ./pkg/signature` | Pass |
| `go test -race ./pkg/signature` | Pass |
| `GOOS=linux GOARCH=amd64 go test -exec /usr/bin/true ./...` | Pass; compile evidence only |
| `GOOS=linux GOARCH=amd64 go vet ./...` | Pass |
| `go test ./pkg/signature -run '^$' -fuzz '^FuzzStrictCMSParser$' -fuzztime=10s` | Pass; 44,359 executions |
| `go test ./pkg/signature -run '^$' -fuzz '^FuzzRootBundleParser$' -fuzztime=10s` | Pass; 7,698 executions |
| `go mod tidy` followed by module diff | Pass; only direct/indirect classification changes, no `go.sum` diff |
| `git diff --check` | Pass |
| GitHub Actions Portability run `32230981575` at `2cc6779` | Pass: native `go test ./...`, `go vet ./...`, and build on Ubuntu 22.04, 24.04, and latest; binary smoke tests on Debian 13, Fedora 42, Arch, openSUSE Tumbleweed, and Ubuntu 26.04 |

Native macOS cannot compile the repository's Linux-only sandbox and peer
credential packages. The cross-target command proves compilation, not runtime
behavior. The native Linux run at
<https://github.com/pietrodicaprio/cpak/actions/runs/32230981575> executes the
CLI, OCI, root-store, signature, and privileged-authority tests on all three
kernel runners. The first run (`32230764768`) exposed an overly literal test
assertion around a correctly quoted OCI media-type diagnostic; commit
`2cc6779` corrected only that assertion. It also observed one transient
baseline Landlock failure on Ubuntu 22.04. The clean rerun passed the same
Landlock test and every Phase 2 test on all runners.

Portability was enabled only for these manual runs and returned to the
`disabled_manually` state afterwards. No release-producing workflow ran.

## 8. Completion decision

The implementation and native Linux evidence satisfy the cryptographic,
trust-store, OCI, migration, authority, fuzz, and portability requirements.
The privileged authority independently reverifies both legacy Sigstore and
tagged X.509 evidence through the common dispatcher. Phase 2 is complete. No
Phase 3 CA or signing workflow is claimed by this phase.
