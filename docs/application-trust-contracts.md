# Application Trust POC Contract Freeze

- Status: accepted Phase 0 design baseline
- Applies to: `poc/application-trust-framework`
- Baseline: cpak v2.6.0 (`12e835c`)
- Last updated: 2026-08-18

## 1. Purpose

This document freezes the formats, APIs, security semantics, and migration
rules needed to implement the Application Trust POC. Implementation may refine
names that are private to a package, but it must not change the wire, storage,
identity, or policy semantics below without updating this decision record and
its compatibility fixtures first.

The contracts separate six questions:

1. whether evidence cryptographically covers an exact artifact state;
2. which publisher identity controls the signing identity;
3. whether that identity may speak for the stated origin;
4. whether host policy approves the publisher, origin, and release;
5. what an independently configured provider reports about publisher
   reputation;
6. whether the installed runtime still matches the enrolled state.

No successful answer substitutes for another. In particular, a valid
signature, a chain to a public root, or an established reputation is never a
claim that software is safe.

## 2. Coordination decision

Development takes place in the personal GitHub fork
`pietrodicaprio/cpak`. The local remote layout is:

- `origin`: `https://github.com/Containerpak/cpak.git`, treated as upstream;
- `fork`: `https://github.com/pietrodicaprio/cpak.git`, available for POC
  branches.

No issue or pull request is opened in the official repository during the POC.
Before an upstream pull request is eventually proposed, the team will either
open the coordination issue requested by `CONTRIBUTING.md` or obtain a
maintainer decision that another coordination record is sufficient. Creating
the fork does not authorize a push, pull request, release, or external project
message.

## 3. Existing formats that remain supported

The following v2.6.0 contracts are immutable compatibility inputs:

| Contract | Frozen value |
| --- | --- |
| Signed-state ABI | `1` |
| Canonical state prefix | `cpak.signature.state.v1` |
| Legacy OCI artifact type | `application/vnd.cpak.signature.v1+json` |
| Legacy Sigstore layer media type | `application/vnd.dev.sigstore.bundle.v0.3+json` |
| Generation annotation | `dev.cpak.signature.generation` |
| Trust-policy ABI | `1` |
| Sigstore evidence limit at registry boundary | 1 MiB |
| Sigstore evidence limit at authority boundary | 256 KiB |
| Anchor-ledger directory ABI | `/var/lib/cpak/integrity/v1` |

The compatibility fixtures under
`testdata/application-trust-v2.6.0` are the source of truth for the exact
legacy representations.

## 4. Signature evidence contract

### 4.1 In-memory contract

The common verifier boundary is represented by the following concepts. The
implementation may place these types in a new package, but their fields and
semantics are frozen.

```go
type EvidenceKind string

const (
    EvidenceSigstoreBundle EvidenceKind = "sigstore-bundle-v1"
    EvidenceX509CMS        EvidenceKind = "x509-cms-v1"
)

type SignatureEvidence struct {
    ABI       int
    Kind      EvidenceKind
    State     signature.State
    MediaType string
    Payload   []byte
}

type Verifier interface {
    Kind() EvidenceKind
    Verify(evidence SignatureEvidence, trust TrustMaterial, now time.Time) (VerificationResult, error)
}
```

`SignatureEvidence.ABI` is `1`. An unsupported ABI, kind, or media type is a
typed invalid result and is never treated as unsigned.

The verifier receives the exact state reconstructed from the installation.
The payload does not get to choose which state is verified. The `now` value is
injected once by the install or update authority so boundary-time tests are
deterministic.

### 4.2 OCI representation

Sigstore keeps its existing OCI representation unchanged. New X.509 evidence
uses:

| Field | Value |
| --- | --- |
| OCI artifact type | `application/vnd.cpak.signature.x509.v1` |
| Evidence layer media type | `application/pkcs7-signature` |
| Layer count | exactly one evidence layer |
| Layer encoding | DER CMS `ContentInfo` containing detached `SignedData` |
| Subject | the resolved OCI image manifest digest |
| Generation annotation | `dev.cpak.signature.generation` |

Both artifact types are queried independently. A registry is allowed to ignore
the artifact-type filter, so cpak rechecks the returned descriptor and layer
media types locally. An object that claims either cpak signature artifact type
but violates its shape is invalid evidence, not an unrelated referrer and not
an unsigned package.

The generation annotation remains a discovery hint. The cryptographic check
is always over the canonical state containing that generation.

### 4.3 On-disk tagged representation

New ledger records encode a signed state as:

```json
{
  "abi": 1,
  "kind": "x509-cms-v1",
  "state": {
    "abi": 1,
    "origin": "github.com/example/application",
    "manifest_sha256": "...",
    "image_digest": "sha256:...",
    "lock_sha256": "...",
    "generation": 12
  },
  "media_type": "application/pkcs7-signature",
  "payload": "base64 DER bytes"
}
```

The same structure carries Sigstore evidence using kind
`sigstore-bundle-v1`, its existing media type, and the bundle JSON bytes in
`payload`.

The enclosing anchor record stays flat and stays under the integrity-v1
directory. The change is limited to the nested `signature` object. Unknown
fields, duplicate JSON keys, multiple JSON values, unsupported ABIs, empty
payloads, and payloads over the authority limit fail closed.

### 4.4 Legacy ledger decoding

A nested signature object with `state` and `bundle`, and without `abi`,
`kind`, `media_type`, or `payload`, is the legacy form. It decodes exactly as:

```text
ABI        = 1
Kind       = sigstore-bundle-v1
MediaType  = application/vnd.dev.sigstore.bundle.v0.3+json
Payload    = legacy bundle bytes
State      = legacy state
```

Legacy and tagged forms are mutually exclusive. A mixture is ambiguous and is
rejected. Readers accept both forms; writers emit only the tagged form after
Phase 1. A legacy record is not rewritten merely because it was read. It is
rewritten only through an otherwise valid install or update enrolment.

The privileged authority always reverifies the decoded evidence before a new
record is written. Launch-time ledger reads validate record shape and runtime
integrity but do not perform full PKI or reputation work.

## 5. Publisher identity contract

### 5.1 Normalized shape

```go
type PublisherIdentity struct {
    Kind        string
    ID          string
    DisplayName string
    Issuer      string
    Repository  string
    Assurance   string
    Claims      map[string]string
}
```

`ID`, `Kind`, and typed claims are authorization inputs. `DisplayName` is
verified descriptive text and is never an authorization key. Every string
shown in a terminal or log is length-bounded and stripped of control
characters at the presentation boundary.

### 5.2 Sigstore/OIDC identity

The POC supports the existing GitHub Actions issuer only. The identity
preimage is the following UTF-8 byte sequence, including the final newline:

```text
cpak.publisher.oidc.v1
issuer=https://token.actions.githubusercontent.com
repository=github.com/owner/repository
```

The repository is the exact, ASCII-lowercase, three-segment canonical origin
already accepted by `signature.State`. It comes only from Fulcio's source
repository extension. The subject and workflow path do not replace it.

The normalized ID is:

```text
oidc-v1-sha256:<64 lowercase hexadecimal SHA-256 characters>
```

The kind is `sigstore-oidc-v1`; issuer and repository remain typed fields for
origin authorization and migration of existing policies.

### 5.3 X.509 identity

The X.509 identity preimage is the DER `SubjectPublicKeyInfo` bytes returned by
`x509.MarshalPKIXPublicKey` for the verified leaf certificate. The normalized
ID is:

```text
x509-spki-sha256:<64 lowercase hexadecimal SHA-256 characters>
```

The kind is `x509-spki-v1`. Renewing a certificate over the same public key
preserves the identity. Re-keying creates a new identity. Cross-key continuity
statements are outside the POC.

The display name is taken from the verified subject profile, preferring the
organisation name and then common name. Empty, ambiguous, or unsafe display
text does not invalidate an otherwise valid identity; it is shown as the
stable publisher ID instead.

### 5.4 Publisher and distributor

The publisher identity is derived only from verified signature evidence. The
origin and registry are distributor coordinates. X.509 origin authorization
means that the verified signer covered the exact canonical state containing
the origin; host policy may additionally restrict that publisher ID to named
origins. A certificate subject, display name, registry hostname, or package
metadata never becomes a publisher ID.

## 6. Verification result contract

Verification produces facts, not the final host decision:

```go
type VerificationResult struct {
    EvidenceKind       EvidenceKind
    StateDigest        string
    Cryptographic      string
    Chain              string
    SigningTime        string
    Revocation         string
    Publisher          *PublisherIdentity
    RootSource         string
    OriginAuthorization string
    ReasonCode         string
    Diagnostic         string
}
```

Frozen status vocabularies are:

- cryptographic: `verified`, `invalid`, `unsupported`;
- chain: `not-applicable`, `trusted-public`, `trusted-local`, `untrusted`,
  `invalid`;
- signing time: `current`, `timestamped`, `missing`, `expired`,
  `not-yet-valid`, `invalid`;
- revocation: `good`, `revoked`, `unknown`, `stale`;
- origin authorization: `authorized`, `foreign`, `unsupported`.

Reason codes are lowercase ASCII kebab-case, no more than 64 bytes. Diagnostic
text is bounded to 512 UTF-8 bytes after control-character sanitization.

An error return is reserved for an inability of cpak itself to perform the
check, such as a corrupt embedded trust bundle. Invalid or hostile evidence is
represented by a result with a stable reason code.

## 7. CMS profile and library decision

### 7.1 Accepted CMS profile

The X.509 evidence is strict DER CMS `SignedData` as defined by RFC 5652:

- outer content type is `signedData`;
- encapsulated content is absent;
- detached content is the exact canonical `cpak.signature.state.v1` bytes;
- exactly one `SignerInfo` is accepted;
- the signer certificate and required intermediates are included;
- self-signed roots in the payload are ignored as trust anchors;
- the signed attributes include `contentType` and `messageDigest` exactly once;
- duplicate or ambiguous signed attributes are invalid;
- SHA-256, SHA-384, and SHA-512 are accepted digest families;
- RSA PKCS#1 v1.5 and ECDSA are accepted only where Go's X.509 implementation
  maps the parameters without ambiguity;
- RSA-PSS is unsupported in the POC and is rejected until the selected CMS
  implementation can parse and enforce its parameters without ambiguity;
- SHA-1, MD5, DSA, unknown parameters, and algorithm-identifier mismatches are
  rejected;
- the leaf must have `CA=false`, digital-signature key usage, and Code Signing
  EKU;
- all parsing occurs after the registry and authority size limits are applied.

### 7.2 Selected implementation

The selected POC candidates are:

- `github.com/digitorus/pkcs7` for CMS parsing, detached signing, signer
  extraction, and signature verification;
- `github.com/digitorus/timestamp` for RFC 3161 parsing and message-imprint
  handling.

Both are already present in the v2.6.0 module graph through Sigstore
dependencies, so promoting the pinned versions to direct POC dependencies does
not add a new transitive dependency tree. The licenses are MIT and BSD-2-Clause
respectively. The repositories were active in 2025, but neither package has a
stable v1 API.

The selection is conditional on a cpak-owned strict wrapper and tests. The
wrapper must not call `PKCS7.Verify()` because it intentionally skips chain
validation when no roots are supplied. It must not treat the unauthenticated
CMS `signingTime` attribute as trusted time. It must:

1. enforce the global DER size bound before parsing;
2. validate the exact outer DER encoding before invoking the underlying
   parser, then reject trailing bytes and non-canonical or ambiguous ASN.1;
3. require exactly one signer through an explicit count check;
4. set detached content to the canonical state supplied by cpak;
5. build explicit `x509.VerifyOptions` with cpak code-signing roots,
   intermediates, Code Signing EKU, and an explicit time;
6. verify the CMS signature and attributes;
7. separately verify an RFC 3161 timestamp, when present;
8. separately evaluate CRLs and report revocation status;
9. expose only cpak's bounded result and reason-code vocabulary;
10. be covered by a malformed ASN.1 corpus and bounded fuzzing.

`github.com/github/smimesign/ietf-cms` was not selected because the reusable
library remains pre-v1 and does not provide the chosen RFC 3161 path.
`go.mozilla.org/pkcs7` is explicitly deprecated in favour of forks.
Newer CMS implementations have less deployment history and would introduce a
new dependency graph without removing the need for cpak-owned timestamp,
revocation, size, and ambiguity controls.

The personal fork authorizes trying and promoting dependencies for the POC.
No dependency change is part of Phase 0 itself; the exact version and license
diff must still be reviewed when Phase 2 modifies `go.mod`.

## 8. Timestamp policy

An unauthenticated or authenticated CMS `signingTime` attribute is descriptive
only. It never extends certificate validity.

A timestamp that extends validity must be an RFC 3161 `TimeStampToken` carried
in the signer's unsigned `id-aa-signatureTimeStampToken` attribute
(`1.2.840.113549.1.9.16.2.14`). The verifier requires:

- exactly one accepted token;
- a message imprint over the CMS signer's signature value;
- an allowed digest algorithm;
- a TSA certificate with Time Stamping EKU;
- a valid TSA chain to roots admitted for the timestamping purpose;
- token time inside the code-signing leaf's validity period;
- token time inside every TSA certificate validity period;
- valid token signature and signed attributes;
- revocation evaluation for the publisher chain at the token time.

When the publisher leaf is currently valid, absence of a timestamp produces
`current`, not a failure. When the leaf is expired, only a fully verified token
produces `timestamped`; otherwise the evidence is invalid with `expired` or
`invalid` signing-time status. A future leaf is always invalid.

## 9. Offline revocation policy

The POC consumes CRLs only. It does not perform an implicit OCSP or network
request.

For every non-root certificate in the publisher chain, the verifier selects an
issuer-matching CRL, verifies its signature and authority, and checks
`thisUpdate <= now < nextUpdate`. CRL freshness is always evaluated at cpak's
injected current time, not at an attacker-supplied or historical CMS time. It
then compares the entry's revocation time with the applicable cutoff: `now`
for a currently valid signature, or the verified RFC 3161 generation time for
a timestamped expired signature. A revocation at or before that cutoff blocks;
a later revocation does not retroactively invalidate the timestamped signature
in this POC. Indirect CRLs, delta CRLs, unknown critical CRL extensions, and
CRLs without a usable `nextUpdate` are unsupported.

Statuses mean:

- `good`: every required certificate has current, valid CRL evidence and no
  applicable revocation entry;
- `revoked`: an applicable valid CRL revokes a required certificate at or
  before the applicable cutoff;
- `unknown`: at least one required issuer has no applicable CRL evidence;
- `stale`: matching CRL evidence exists but is outside its validity window.

`revoked` and `stale` block enrolment. `unknown` is reported and allowed by the
POC default for public roots, because the POC root bundle is distributable but
does not include a continuously refreshed public revocation service. Hosts may
configure managed policy to require `good`. The POC CA demonstration always
provides a current CRL so its expected result is `good`.

## 10. Code-signing root bundle

### 10.1 Source and licence

The initial code-signing candidate source is the CCADB report named “PEM of
Root Certificates in Microsoft's Root Store with Code Signing EKU”. The
initial timestamping candidate source is the current Microsoft Included CA
Certificate report published through CCADB, filtered to enabled certificates
whose declared trust purpose includes Time Stamping. CCADB publishes the data
under CDLA-2.0-Permissive and requires attribution. Each release records every
exact source URL, retrieval time, source SHA-256, and CCADB attribution.

Source membership never grants trust automatically. The generated bundle is
an explicit allowlist of individually reviewed fingerprints. A reviewer must
confirm status, purpose, certificate constraints, supported algorithms, and
independent CA chain documentation for every admitted entry. Disabled or
unreviewed entries are excluded even if they appear in a source report.

Microsoft's participant report and root-program documentation are corroborating
sources. A CA's own chain documentation is required before an example chain is
claimed. In particular, Sectigo is included only by an exact root fingerprint
present in the reviewed CCADB snapshot and corroborated by Sectigo's current
code-signing chain documentation.

### 10.2 Bundle format

The embedded manifest media type is
`application/vnd.cpak.code-signing-roots.v1+json` and its schema is:

```json
{
  "abi": 1,
  "sources": [
    {
      "name": "CCADB Microsoft Code Signing Roots",
      "url": "https://...",
      "retrieved_at": "2026-08-18T00:00:00Z",
      "sha256": "...",
      "license": "CDLA-2.0-Permissive"
    }
  ],
  "roots": [
    {
      "sha256": "64 lowercase hex characters",
      "subject": "bounded display text",
      "purposes": ["code-signing"],
      "der": "base64 DER certificate"
    }
  ]
}
```

Root entries are sorted by SHA-256 fingerprint. The generator rejects duplicate
fingerprints, non-self-signed certificates, `CA=false`, missing certificate
signing key usage, unsupported algorithms, source fingerprint mismatches, and
unknown fields. Subject text is diagnostic only.

Timestamp roots are represented in the same versioned manifest with purpose
`timestamping` but are loaded into a separate pool. A root may have both
purposes only when the reviewed source explicitly assigns both. Purpose never
flows from certificate subject text.

### 10.3 Update model and local roots

The public bundle changes only through a cpak release and its provenance diff
is reviewable. Runtime network updates are outside the POC.

Administrator roots are separate files under
`/etc/cpak/trust/code-signing.d` for code signing and
`/etc/cpak/trust/timestamping.d` for timestamping. Each admitted file is a
single DER or PEM self-signed root whose purpose and SHA-256 fingerprint the
authenticated administrator previewed and confirmed. Symlinks, unsafe
ownership or modes, duplicate roots, multi-certificate files, trailing data,
and non-roots are rejected. Public and local roots remain distinguishable in
results. Import into one purpose does not admit the root for the other.

The system TLS root store is never consulted by default.

## 11. Trust-policy migration

Existing ABI 1 policies remain valid and retain exact issuer/repository
matching. The first policy that uses normalized publisher IDs or reputation is
ABI 2. Old readers must reject ABI 2 rather than partially enforce it.

The ABI 2 additions are conceptually:

```go
type ReputationPolicy struct {
    Mode       string                `json:"mode"`
    ProviderID string                `json:"provider_id,omitempty"`
    Exceptions []ReputationException `json:"exceptions,omitempty"`
}

type ReputationException struct {
    PublisherID string   `json:"publisher_id"`
    Origins     []string `json:"origins"`
    Statuses    []string `json:"statuses"`
    ExpiresAt   string   `json:"expires_at,omitempty"`
    ReasonCode  string   `json:"reason_code"`
}

type X509Policy struct {
    Revocation string `json:"revocation"` // allow-unknown or require-good
}

type PolicyV2 struct {
    // ABI 1 fields remain with identical semantics.
    ApprovedPublisherIDs []string         `json:"approved_publisher_ids,omitempty"`
    X509                 X509Policy       `json:"x509"`
    Reputation           ReputationPolicy `json:"reputation"`
}
```

`X509Policy.Revocation` is exactly `allow-unknown` or `require-good`.
ABI 2 requires the X.509 section even when no X.509 publisher is currently
approved, so the revocation posture is explicit. `allow-unknown` permits only
the `unknown` status; `revoked` and `stale` always block.

A reputation exception requires one normalized publisher ID, one or more exact
canonical origins, and one or both statuses `unknown` and `caution`. All three
dimensions must match. An expiry, when present, is a UTC RFC 3339 whole-second
instant and the exception is inactive at or after that instant. An omitted
expiry is an explicit permanent administrator decision. Entries with an empty
scope, any other status, unsafe reason code, duplicate origin, or duplicate
semantic scope are invalid.

An ABI 1 OIDC selector may be evaluated directly against the typed issuer and
repository in a normalized identity. It is not silently rewritten on disk.
Writers use ABI 2 only when an ABI 2 field is present; otherwise they preserve
ABI 1 output for compatibility.

## 12. Reputation snapshot contract

### 12.0 Provider authority and privileged state

A provider authority document is strict JSON containing ABI 1, one provider
ID, one `ed25519-sha256:<hex>` key ID, and the matching raw Ed25519 public key.
It is separate from the snapshot, code-signing roots, timestamping roots, and
publisher certificates. Duplicate keys, unknown fields, trailing JSON values,
invalid key lengths, and key-ID mismatches are rejected.

The configured authority and active snapshot are root-owned regular files under
`/var/lib/cpak/reputation/v1`. Readers reject symlinks, unexpected ownership,
or group/world-writable state. Configuring a different authority invalidates
the previous snapshot. Clearing the authority removes both records and does not
change trust roots or integrity anchors.

### 12.1 Snapshot format

The media type is
`application/vnd.cpak.publisher-reputation.snapshot.v1+json`.

```json
{
  "abi": 1,
  "provider_id": "example-provider",
  "key_id": "ed25519-sha256:<hex>",
  "signed": {
    "sequence": 42,
    "issued_at": "2026-08-18T10:00:00Z",
    "expires_at": "2026-08-25T10:00:00Z",
    "entries": [
      {
        "publisher_id": "x509-spki-sha256:<hex>",
        "status": "established",
        "reason_code": "verified-history"
      }
    ]
  },
  "signature": "base64 Ed25519 signature"
}
```

The signature is Ed25519 over the RFC 8785 JSON Canonicalization Scheme bytes
of the `signed` object. Provider keys are configured independently from
publisher CAs and code-signing roots. `key_id` is the SHA-256 of the raw
Ed25519 public key, lowercase hexadecimal.

Provider IDs and reason codes are 1-64 lowercase ASCII characters matching
`^[a-z0-9][a-z0-9._-]*$`. Publisher IDs must match a supported normalized-ID
grammar. Timestamps are UTC RFC 3339 with whole seconds. Entries are unique and
sorted by publisher ID. Unknown fields, duplicate keys, duplicate publisher
IDs, unsupported statuses, more than 100,000 entries, documents over 16 MiB,
and reason codes over the bound are invalid.

The importer verifies schema, provider ID, configured key ID, signature,
issued/expiry bounds, and a sequence in the inclusive range `1..2^53-1` before
atomically replacing the active snapshot. The active privileged record is one
file containing the complete signed envelope and therefore its sequence; it is
written to a safe sibling temporary file, durably flushed, and atomically
renamed. Its parent directory is then durably flushed. Equal or lower sequences
than the active record are rollback attempts. There is no separate sequence
file whose update could diverge from the snapshot. Replacement or rollback by
an authenticated root administrator is outside the unprivileged attacker
model and remains an explicit administrative action.

### 12.2 Reputation result

Statuses are exactly:

- `unknown`;
- `established`;
- `caution`;
- `blocked`;
- `unavailable`.

Every result includes provider ID, publisher ID, issue time, expiry, sequence,
and bounded reason code. An absent publisher entry is `unknown`. A missing,
invalid, expired, or unreadable active provider snapshot is `unavailable`; an
invalid snapshot is also reported as an administrative error and never
replaces the last valid snapshot.

### 12.3 Policy modes

Mode names and consequences are frozen:

| Mode | Established | Unknown | Caution | Blocked | Provider unavailable |
| --- | --- | --- | --- | --- | --- |
| `off` | not consulted | not consulted | not consulted | not consulted | not consulted |
| `audit` | allow and record | allow and record | allow and record | allow and record | allow and record |
| `warn` | allow | allow with warning | allow with warning | deny | allow with warning |
| `require-established` | allow | deny | deny | deny | deny |

A scoped administrator exception may override `unknown` or `caution` in
`require-established`. It may not override `blocked`, invalid cryptography,
untrusted chains, revocation, stale mandatory evidence, origin mismatch,
release revocation, or an administrator publisher/origin denial. Provider
unavailability is not exception-equivalent in the POC.

Reputation is evaluated only after signature, identity, origin authorization,
and administrator policy have succeeded. It is refreshed at install or update,
not at every launch.

### 12.4 Administration and diagnostics

Provider configuration is confirmed against the full provider key ID. Snapshot
import is confirmed against SHA-256 of the complete envelope. Across privilege
escalation, the privileged process rereads the named regular file and requires
the same exact value; `--yes` without `--fingerprint` is invalid.

The historical authenticated result and policy action are stored in the
enrolment record. `cpak audit` and `cpak system explain` report provider, status,
provider reason code, policy action, and policy reason code. These fields are
diagnostic history, not launch inputs. A launch does not read the snapshot,
contact a provider, or reinterpret an existing enrolment after a reputation
update.

In `warn` mode, graphical and interactive-terminal callers may present the
warning. A non-interactive caller receives `confirmation-required`; it may not
infer consent or use `--yes` to turn reputation into an allow decision.

## 13. Decision precedence

The implementation uses the following precedence without adapter-specific
shortcuts:

1. malformed, ambiguous, unsupported, oversized, or state-mismatched evidence
   is invalid;
2. failed cryptographic verification or an untrusted chain is invalid;
3. revoked or stale mandatory revocation evidence is blocked;
4. invalid or missing mandatory signing-time evidence is blocked;
5. origin authorization is evaluated for the verified identity;
6. administrator origin, publisher, approval, and release-revocation policy is
   evaluated;
7. reputation is evaluated according to the configured mode;
8. only the explicitly scoped reputation exceptions described above apply;
9. accepted state and evidence are independently reverified by the privileged
   authority and enrolled;
10. launch validates the anchored runtime identity and integrity without
    network, full PKI, or reputation work.

When multiple evidence objects are present, every applicable candidate is
evaluated. At least one candidate must verify, authorize the origin, and
satisfy policy. Invalid extra evidence is reported but does not suppress a
separate valid candidate. If evidence exists and none passes, the package is
invalid, not unsigned.

## 14. Security limits

The initial implementation must define constants for all external inputs. The
contract bounds are:

| Input | Bound |
| --- | ---: |
| Registry evidence object | 1 MiB |
| Authority evidence payload | 256 KiB |
| Anchor record | 512 KiB |
| Root bundle manifest | 8 MiB |
| One local root file | 64 KiB |
| Reputation snapshot | 16 MiB |
| Reputation entries | 100,000 |
| Diagnostic text | 512 UTF-8 bytes |
| Reason code | 64 ASCII bytes |
| Display name | 200 UTF-8 bytes |

ASN.1 and JSON parsers reject trailing values. JSON authority formats reject
unknown fields and duplicate keys. Private keys, passphrases, PINs, tokens, and
credentials are never ledger fields, CLI arguments, logs, or fixtures.

## 15. References and provenance

- RFC 5280, Internet X.509 PKI Certificate and CRL Profile:
  <https://datatracker.ietf.org/doc/html/rfc5280>
- RFC 5652, Cryptographic Message Syntax:
  <https://datatracker.ietf.org/doc/html/rfc5652>
- RFC 3161, Time-Stamp Protocol:
  <https://datatracker.ietf.org/doc/html/rfc3161>
- RFC 8785, JSON Canonicalization Scheme:
  <https://datatracker.ietf.org/doc/html/rfc8785>
- CCADB code-signing root resources:
  <https://www.ccadb.org/resources>
- CCADB data usage terms:
  <https://www.ccadb.org/rootstores/usage>
- Microsoft Trusted Root Program participants:
  <https://learn.microsoft.com/en-us/security/trusted-root/participants-list>
- CA/Browser Forum Code Signing Baseline Requirements:
  <https://cabforum.org/working-groups/code-signing/requirements/>
- digitorus PKCS#7 implementation:
  <https://github.com/digitorus/pkcs7>
- digitorus RFC 3161 implementation:
  <https://github.com/digitorus/timestamp>
