# Application Trust POC Phase 3 evidence

Status: complete  
Branch: `poc/application-trust-framework`  
Functional head: `9770e8cde2a08511afb9c83e6d62abe90da4a57a`
Date: 2026-08-19

## 1. Scope delivered

Phase 3 adds a disposable private-PKI reference hierarchy and the publisher
workflow needed to produce and attach the X.509/CMS evidence accepted since
Phase 2. It does not add the POC root to cpak's default trust program and does
not claim publisher reputation.

| Commit | Milestone |
| --- | --- |
| `c99f9dc` | `crypto.Signer` CMS production, encrypted PKCS#8 input, generic Sigstore/X.509 attach profiles, canonical-state interoperability, negative tests, and root-removal ledger evidence |
| `90d99dd` | Disposable CA generator, checked-in public sample, empty CRL, CP/CPS, and reproducible Linux runbook |
| `7c98d64` | Clock-safe RFC 3161 fixtures discovered by the first Linux certification run |
| `9770e8c` | Experimental-assurance assertion and scrypt/AES-256-GCM hardening for generated software keys |

## 2. Public and private material boundary

Tracked POC material is limited to:

- the self-signed public root;
- dedicated public Code Signing and timestamping intermediates;
- public publisher and TSA leaves;
- an empty test CRL;
- certificate fingerprints and documentation.

`hack/poc-ca` creates all working private keys in a new caller-selected
directory with mode `0700`. Every key file is encrypted PKCS#8, mode `0600`,
using scrypt (`N=32768`, `r=8`, `p=1`, 16-byte salt) and AES-256-GCM. The
passphrase is accepted only through an owner-only file. `cpak-sign x509-sign`
also accepts a named pipe or inherited descriptor, never a passphrase flag.

The one-off private material used to create the checked-in public sample was
removed after generation. A tracked-file scan found no private-key PEM block,
passphrase, registry credential, or generated executable.

## 3. Trust and identity behavior

- The root signs only the two dedicated intermediates.
- Both intermediates are `CA=true`, `pathLen=0`, with signing and CRL usages.
- Publisher leaves are `CA=false`, `digitalSignature`, Code Signing EKU only.
- TSA leaves are `CA=false`, `digitalSignature`, Time Stamping EKU only.
- The root and every private key remain outside the CMS evidence.
- Publisher identity remains SHA-256 over DER SubjectPublicKeyInfo.
- The exact canonical state produced by `cpak-sign state` is consumed directly
  by `x509-sign`, `attach`, and `cpak verify-signature`.
- `attach --trust-root` is a publication-time verification input only. It does
  not mutate local or system trust.
- The installed machine still requires an explicit, fingerprint-bound
  `trust-root-add` operation through the Phase 2 privileged boundary.
- Removing that root makes later full verification fail while leaving the
  recorded evidence and anchor readable and byte-for-byte unchanged.

## 4. Security review

The review traced passphrase input, key parsing, certificate/chain validation,
CMS production, publication-time trust, OCI attachment, administrator root
admission, authority re-verification, and ledger reads.

No unresolved high- or critical-severity finding remains.

One medium-strength defense issue was found during review: the PKCS#8 library's
default encryption profile used only 10,000 PBKDF2 iterations. The generator
now selects scrypt and AES-256-GCM explicitly. Negative tests also prove that a
group/world-readable key, incorrect passphrase, mismatched certificate key,
untrusted root, malformed certificate input, and unsafe evidence do not reach
publication.

The remaining limitations are deliberate POC boundaries:

- the generator is a local development tool, not an online CA service;
- the passphrase file and generated key directory require operator cleanup;
- no hardware-token backend is implemented, although the signing boundary is
  already `crypto.Signer`;
- the static example CRL is illustrative and expires; a generated demo creates
  current CRL material;
- the real external-registry install/update matrix remains Phase 5. Phase 3
  uses the real OCI protocol against the existing in-process registry and the
  real root, verifier, and authority components independently.

## 5. Acceptance evidence

| Requirement | Evidence | Result |
| --- | --- | --- |
| Root/intermediate/leaf/TSA profiles | `TestGeneratedProfilesSeparateRootIntermediatePublisherAndTSA` plus OpenSSL inspection of `docs/poc-ca` | Pass |
| Root does not sign publisher directly | Chain assertion in the generator profile test | Pass |
| No reusable tracked secret | Tracked-file inventory and private-key/passphrase scan | Pass |
| Encrypted software-key signing | `TestX509SignAcceptsEncryptedSoftwareKeyAndProducesDetachedEvidence` | Pass |
| Replaceable signer backend | `TestSignX509CMSUsesCryptoSignerAndProducesVerifierEvidence` | Pass |
| X.509 OCI attachment | `TestAttachPublishesX509CMSOnlyAfterPublicationTimeTrust` | Pass |
| Explicit opt-in | Same attach test, unknown-root verifier cases, and Phase 2 root-store lifecycle | Pass |
| Removal and ledger preservation | `TestRemovingX509TrustBreaksFullReverificationWithoutChangingTheLedger` | Pass |
| Experimental assurance wording | `TestX509SigningReportDoesNotImplyPublicTrustOrReputation` | Pass |
| Reproducible commands | `docs/application-trust-poc-demo.md` | Documented |

## 6. Verification record

Local checks at functional head or its direct precursors:

| Check | Result |
| --- | --- |
| `go test ./hack/poc-ca ./pkg/signature -count=1` | Pass |
| `GOOS=linux GOARCH=amd64 go test -exec=/usr/bin/true ./...` | Compile pass for every package |
| `GOOS=linux GOARCH=amd64 go vet ./...` | Pass |
| `git diff --check` | Pass |
| Public sample inspection with `openssl x509` and `openssl crl` | Pass |
| Tracked secret-pattern and file inventory | Pass |

GitHub Actions Portability run `32246312721` correctly failed because the fixed
date used by pre-existing RFC 3161 fixtures had crossed their certificate
validity boundary. Commit `2924bee` made the simulated verification time
relative to the execution clock without weakening the rejected cases.

Portability run `32246569421` then passed the full project test and vet command
on Ubuntu 22.04, Ubuntu 24.04, and `ubuntu-latest`; the CGO-free Linux amd64
binary also ran on Debian 13, Fedora 42, Arch Linux, openSUSE Tumbleweed, and
Ubuntu 26.04.

Final pre-rebase hardening run [`32246954003`](https://github.com/pietrodicaprio/cpak/actions/runs/32246954003)
covers the equivalent original functional head `a01fd39`; the rebased series is
certified as a whole by the Phase 4 post-rebase record.

## 7. Completion decision

The private-PKI workflow is reproducible from documented commands without a
developer-owned secret or hardware token. The POC root remains explicit and
opt-in, and removal affects future trust decisions without rewriting history.
Phase 3 is complete; the real install/update lifecycle expansion remains an
explicit Phase 5 deliverable rather than an unreported Phase 3 assumption.
