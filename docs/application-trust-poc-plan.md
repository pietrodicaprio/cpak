# Application Trust POC Implementation Plan

- Status: active; Phases 0 through 3 complete, Phases 4 through 6 pending
- Working branch: `poc/application-trust-framework`
- Pull request policy: no pull request is opened until the complete POC
  satisfies the Definition of Done in this document
- Last updated: 2026-08-19

## 1. Purpose

This plan defines an incremental proof of concept for publisher identity,
X.509 code signing, publisher reputation, policy evaluation, and explainable
trust decisions in cpak.

The trust model and decision contract are independent of cpak and of any
desktop environment. cpak is the primary reference actor; a minimal AppImage
conformance example is the second actor used to prove that the published
contract is portable. Graphical interfaces, interactive terminals, unattended
automation, services, and desktopless hosts are presentation or invocation
contexts around the same decision engine, not separate trust models.

The POC is the cpak-contained reference implementation of the concepts in the
Linux Application Trust Framework discussion paper. It is intended to produce
three publishable outcomes:

1. a working implementation;
2. a reproducible example and threat model;
3. evidence that the proposed trust abstractions can support Sigstore/OIDC,
   public X.509 Code Signing CAs, private PKI, and replaceable reputation
   providers without changing the cpak package format.

The implementation extends the verified-launch, publisher-signature, trust
policy, and administrator-ceiling work already present on the `v2` branch. It
must not replace or bypass those mechanisms.

## 2. Delivery and coordination rules

- All work is performed on `poc/application-trust-framework`.
- Changes are developed incrementally. This is not a rewrite.
- Focused commits may be created per phase, but no pull request is opened until
  every required phase and the final Definition of Done are complete.
- No branch is pushed, issue is created, release is published, or external
  message is sent without explicit authorization.
- `CONTRIBUTING.md` requests an issue before a substantial change. Before code
  implementation begins, obtain explicit authorization to open that issue or a
  maintainer decision that the POC branch is the accepted coordination record.
- Existing unrelated changes must be preserved.
- New production dependencies require explicit approval after a bounded
  technical and security evaluation.
- Code, tests, documentation, commits, and future pull-request content are
  written in English.

## 3. Scope

### 3.1 In scope

- Preserve and generalize the existing Sigstore/OIDC signature path.
- Add detached X.509/CMS code-signature verification over the existing cpak
  signed state.
- Add a dedicated code-signing trust-root store, separate from the operating
  system TLS root store and from publisher policy.
- Support a curated public code-signing root bundle and administrator-installed
  private roots.
- Create and document a Containerpak POC CA hierarchy for development and
  demonstration.
- Add normalized publisher identities that do not depend on one signing
  technology.
- Add a replaceable publisher-reputation provider contract.
- Implement an offline, signed-snapshot reputation provider for the POC.
- Integrate reputation into install/update policy without moving full PKI or
  network work into the launch hot path.
- Expose verification, identity, reputation, policy, and final-decision reasons
  through cpak CLI and audit surfaces.
- Support graphical, interactive-terminal, and non-interactive/headless
  invocation without changing verification or policy semantics.
- Define an implementation-independent decision result and demonstrate it with
  cpak plus a minimal AppImage conformance actor.
- Provide negative tests and a reproducible end-to-end Linux demonstration.
- Publish the limitations and security non-goals of the POC.

### 3.2 Out of scope

- Malware detection or behavioral analysis.
- A production global reputation service or telemetry collection network.
- Automatic trust in all software whose certificate chains to a public CA.
- A new package format.
- Replacement of Sigstore, distribution-native signatures, or OCI integrity.
- Browser, Nautilus, Dolphin, GNOME, or KDE integration.
- A mandatory graphical frontend or desktop-session dependency.
- Kernel enforcement through fs-verity, IMA, or IPE.
- Becoming a publicly audited CA or entering third-party root programs.
- Transparent publisher identity continuity across a private-key rotation.
- Automatic online root-store updates in the first POC.
- A production hardware-token backend in the first POC.

## 4. Existing baseline

The implementation starts from the following verified `v2.6.0` behavior:

- `cpak.signature.state.v1` canonically binds origin, manifest digest, resolved
  OCI image digest, optional lock digest, and publisher generation.
- Sigstore bundles are verified offline against the trust material embedded in
  cpak.
- The Fulcio certificate supplies the OIDC issuer and GitHub repository
  identity.
- GitHub Actions identities authorize an origin only through an exact
  issuer-and-repository match.
- unsigned, invalid, and foreign signatures are distinct outcomes;
- the privileged anchor ledger re-verifies evidence before recording it;
- publisher signature requirements, administrator trust policy, revocation,
  approval countersignatures, and verified-launch enforcement already exist.

The POC must retain these properties and their current behavior for existing
packages, trust policies, signature referrers, and ledger records.

## 5. Trust model and mandatory invariants

### 5.1 Separate authorities

The implementation must keep these questions separate:

1. **Cryptographic verification:** does the evidence authenticate the exact
   cpak state?
2. **Publisher identity:** which identity controls the signing key or OIDC
   identity?
3. **Origin authorization:** why may that identity sign this origin?
4. **Trust policy:** does the host permit that publisher, origin, and release?
5. **Reputation:** what does the configured provider report about the
   publisher?
6. **Runtime integrity:** does the launch still match the state accepted at
   installation or update?

No successful answer may be used as a substitute for another.

### 5.2 Security invariants

- A valid signature never means that software is safe.
- A trusted CA root verifies an issuer; it does not automatically approve or
  establish the reputation of every publisher below it.
- Reputation never converts invalid, mismatched, expired-without-valid-time
  evidence, or revoked evidence into a verified signature.
- A package with attached but invalid evidence is not downgraded to unsigned.
- The signed state remains bound to the resolved digest, never a movable tag.
- Manifest permissions remain inside the signed state.
- OIDC origin authorization continues to require the exact supported issuer
  and source repository.
- X.509 origin authorization comes from the verified signer covering the exact
  canonical state containing the origin; host policy may further restrict the
  publisher to specific origins.
- Publisher and distributor/origin identities remain distinct concepts.
- Display names, certificate subjects, package metadata, and reputation reason
  text are never used as authorization identifiers.
- All administrator-controlled trust, reputation, and policy state is stored
  under a root-owned boundary, validated on read, and written atomically.
- Unknown fields, unsupported ABIs, ambiguous evidence, stale signed snapshots,
  and rollback attempts fail closed at the authority that consumes them.
- Full signature, chain, revocation, timestamp, and reputation work happens at
  installation or update, not at every launch.
- The anchor ledger stores verifiable evidence, not an unprovable cached
  verdict, and the privileged authority verifies the evidence again before
  recording it.
- Private keys, PINs, tokens, and credentials are never committed, logged,
  included in fixtures, or passed in command-line arguments when a safer input
  channel exists.

### 5.3 Environment and presentation independence

- Verification, identity, reputation, policy, and final action are computed by
  a presentation-neutral core.
- The absence of a display server, session D-Bus, desktop portal, Secret
  Service, graphical privilege agent, or TTY must not weaken or bypass policy.
- A graphical dialog and an interactive terminal prompt may present a decision
  or collect an allowed confirmation; they do not create trust facts.
- A non-interactive invocation never blocks waiting for confirmation and never
  silently converts `warn` into `allow`.
- A generic automation flag such as `--yes` acknowledges an operation only. It
  does not override invalid evidence, revocation, administrator denial, or an
  unknown/caution reputation result.
- Any permitted reputation exception is explicit, scoped, privileged,
  auditable, and produces the same decision record in every invocation context.
- Full trust evaluation occurs at install/update or explicit verification.
  Starting a previously enrolled binary validates its anchored state without a
  desktop or a network dependency.
- A changed reputation or policy does not retroactively terminate an already
  running process; its effect on future install, update, enrolment, or launch
  decisions must be explicit.

## 6. Required data contracts

Names are provisional until Phase 0 freezes the API, but the concepts are
required.

### 6.1 Signature evidence

```go
type EvidenceKind string

const (
    EvidenceSigstoreBundle EvidenceKind = "sigstore-bundle-v1"
    EvidenceX509CMS        EvidenceKind = "x509-cms-v1"
)

type SignatureEvidence struct {
    Kind       EvidenceKind
    State      signature.State
    Payload    []byte
    MediaType  string
}
```

The stored representation must be tagged and versioned. It must read existing
ledger records that contain the legacy Sigstore `bundle` field.

### 6.2 Normalized publisher identity

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

Authorization and policy use `ID` and typed claims, never `DisplayName`.

- Sigstore/OIDC ID: a versioned digest of the canonical issuer and repository.
- X.509 ID: `x509-spki-sha256:<digest>` for the POC.
- Renewing a certificate over the same public key preserves the X.509 ID.
- Changing the public key creates a new ID. Key-continuity statements are
  explicitly deferred beyond the POC.

### 6.3 Verification result

The result must separately expose:

- artifact/state digest;
- evidence kind;
- cryptographic status;
- certificate-chain status;
- signing-time/timestamp status;
- revocation status;
- normalized publisher identity;
- origin-authorization status and reason code;
- diagnostics safe for CLI and logs.

It must not contain the final host trust decision.

### 6.4 Reputation result

```go
type ReputationStatus string

const (
    ReputationUnknown     ReputationStatus = "unknown"
    ReputationEstablished ReputationStatus = "established"
    ReputationCaution     ReputationStatus = "caution"
    ReputationBlocked     ReputationStatus = "blocked"
    ReputationUnavailable ReputationStatus = "unavailable"
)
```

Every result also contains provider ID, publisher ID, issued time, expiry,
sequence/version, and a bounded machine-readable reason code. The POC must not
expose an unexplained numeric trust score as policy.

## 7. Functional requirements

### FR-1: Backward-compatible Sigstore/OIDC verification

- Existing Sigstore referrers and ledger records continue to verify.
- Existing GitHub Actions issuer/repository matching remains exact.
- Current commands continue to work without new mandatory flags.

### FR-2: X.509/CMS verification

- Accept detached CMS `SignedData` over the canonical
  `cpak.signature.state.v1` bytes.
- Verify the signer signature, certificate path, Code Signing EKU, key usage,
  algorithm policy, certificate validity, and exact state binding.
- Support a valid RFC 3161 timestamp path so a signature can remain verifiable
  after the leaf certificate expires.
- Reject expired certificates without acceptable signing-time evidence.
- Represent revocation as `good`, `revoked`, `unknown`, or `stale`.
- Support an offline CRL path in the POC. Online OCSP may be added only if its
  availability, caching, privacy, and failure policy are explicit.

### FR-3: Code-signing root store

- Do not use the distribution TLS root pool as the default code-signing trust
  pool.
- Embed a reviewable, versioned public code-signing root bundle in cpak.
- Source the initial public dataset from the CCADB/Microsoft Code Signing root
  list, subject to data-usage review.
- Verify every included root by exact DER fingerprint and record provenance.
- Include Sectigo only through an exact root present in the code-signing
  dataset and corroborated by Sectigo's published chain documentation.
- Load administrator roots from a root-owned directory such as
  `/etc/cpak/trust/code-signing.d`.
- Provide an authenticated CLI path that previews subject and SHA-256
  fingerprint before adding or removing a local root.
- Treat public roots and administrator roots as separate sources in diagnostics.
- Distribute public-root changes through cpak releases for the POC.

### FR-4: Containerpak POC CA

- Create an offline POC root and a dedicated Code Signing intermediate.
- The root does not issue leaf certificates directly.
- The intermediate is constrained to CA use with `pathLen=0` and a documented
  Code Signing policy OID.
- Leaf certificates contain `CA=false`, `digitalSignature`, and Code Signing
  EKU, plus a bounded publisher subject profile.
- Publish only public certificates, chains, fingerprints, CRLs, and policy
  documents.
- Keep all private material outside the repository.
- Clearly label the CA assurance as experimental.
- Make trust in the POC root explicit and opt-in; do not silently add it to a
  production default trust bundle.

### FR-5: X.509 signing workflow

- Extend `cpak-sign` to produce or validate the X.509/CMS evidence attached to
  an OCI image referrer.
- Preserve the existing state-generation and attach workflow.
- The initial POC may use an encrypted software PEM key supplied through a safe
  runtime path.
- Signing-key access must be abstracted behind `crypto.Signer` or an equivalent
  boundary so PKCS#11/HSM support does not change the evidence format.
- A production hardware-token backend is not required for POC completion.

### FR-6: Reputation provider

- Define a provider interface keyed by normalized publisher ID.
- Implement an offline provider backed by a signed reputation snapshot.
- Keep the reputation signing authority separate from code-signing CAs and
  publishers.
- Verify snapshot signature, provider identity, schema version, expiry, and
  monotonic sequence before accepting it.
- Store the last accepted sequence under the privileged system-authority
  boundary to prevent rollback.
- Replace snapshots atomically.
- Report stale, unavailable, unknown, established, caution, and blocked states
  distinctly.
- Do not collect or transmit telemetry in the POC.

### FR-7: Policy integration

- Extend publisher selectors to support normalized publisher IDs while reading
  existing OIDC issuer/repository policies.
- Keep explicit origin approval, publisher approval, release revocation,
  countersignature approval, reputation, and verified-launch enforcement as
  separate policy inputs.
- Evaluate reputation at enrolment during install/update.
- Support policy behavior equivalent to `off`, `audit`, `warn`, and
  `require-established`, with exact names frozen in Phase 0.
- Define provider-unavailable behavior per policy mode.
- Preserve administrator authority as the final decision point.

### FR-8: Explainability and CLI

- Extend `cpak verify-signature`, `cpak audit`, and `cpak system explain` to
  report:
  - evidence kind;
  - cryptographic and chain status;
  - publisher ID and verified display name;
  - trust-root source;
  - timestamp and revocation status;
  - reputation provider, status, freshness, and reason code;
  - policy result;
  - final action and reason.
- Use “Verified publisher” only for identity-backed verified evidence.
- Use “Trusted by policy” only for a policy decision.
- Never describe signed or established software as safe.
- Bound and sanitize all externally supplied diagnostic text.

### FR-9: Headless and unattended operation

- Define invocation context as `graphical`, `interactive-terminal`, or
  `non-interactive`; context affects presentation only, except where a policy
  explicitly requires human confirmation.
- Expose a versioned machine-readable result containing verification status,
  publisher ID, reputation status, policy result, final action, and stable
  reason code.
- Define stable exit-code classes for allowed, denied, invalid, unavailable,
  and confirmation-required results without relying on localized text.
- In non-interactive mode, a decision requiring human confirmation returns
  `confirmation-required` and a non-zero exit code. It must not hang, invoke a
  desktop helper, or assume consent.
- Permit root and reputation administration through direct root execution or
  terminal escalation using exact fingerprints and explicit arguments, so
  configuration-management systems do not require a graphical privilege agent.
- cpak packages containing exported binaries but no desktop entries must use
  the same install, update, enrolment, reputation, and runtime-integrity path as
  graphical applications.
- Headless operation must not attempt to read desktop-only credential stores.
  Required registry or signing credentials use explicit safe non-interactive
  sources and remain subject to the existing secret-handling rules.
- The portable result schema and reason semantics must be consumable by a
  second actor without importing cpak storage, manifests, policy files, or CLI
  presentation code.

## 8. Decision precedence

The final policy engine must follow this order:

1. malformed, ambiguous, or state-mismatched evidence is invalid;
2. failed cryptographic verification or an untrusted chain is invalid;
3. revoked evidence is blocked;
4. unsupported or stale mandatory signing-time evidence is blocked;
5. origin authorization is evaluated for the verified identity;
6. administrator origin, publisher, approval, and release-revocation policy is
   evaluated;
7. reputation is evaluated according to the configured mode;
8. a scoped administrator exception may override unknown or caution reputation
   only when the policy explicitly permits it;
9. invalid cryptography and revoked certificates cannot be overridden through a
   reputation or ordinary publisher exception;
10. accepted state and evidence are enrolled, after which launch checks only
    the anchored runtime identity and integrity.

When multiple evidence objects exist, cpak evaluates all applicable candidates.
At least one candidate must verify, authorize the state, and satisfy policy.
Invalid extra objects are reported but do not allow an attacker to suppress a
separate valid object. If evidence objects are present and none verify, the
package is invalid, not unsigned.

## 9. Implementation phases

### Phase 0: Contract freeze and baseline evidence

#### Objectives

- Turn this plan into concrete APIs, ABIs, media types, and migration rules.
- Record the current behavior that must not regress.
- Decide whether to open the repository-required coordination issue.

#### Deliverables

- Short architecture decision records or a design section covering:
  - evidence envelope and OCI media types;
  - normalized publisher ID derivation;
  - legacy ledger decoding and ABI strategy;
  - CMS library selection;
  - root-bundle source and update model;
  - timestamp and revocation policy;
  - reputation snapshot format and policy modes.
- Golden fixtures for current Sigstore evidence, trust policy, and ledger data.
- A test matrix mapped to the requirements in this document.

#### Acceptance criteria

- Every new on-disk or OCI format is versioned.
- Legacy fixtures are identified before the storage structs change.
- The selected CMS implementation is evaluated for detached-content support,
  signer selection, chain-validation control, timestamp handling, malformed
  ASN.1 behavior, maintenance status, and transitive cost.
- No production dependency is promoted or added without explicit approval.
- Open decisions that affect security semantics are resolved or recorded as a
  blocker; none are silently delegated to implementation defaults.

#### Phase completion gate

Phase 0 is complete when the format/API decisions are reviewable, current
behavior is captured by fixtures, and implementation can proceed without
inventing trust semantics inside a code patch.

### Phase 1: Generalize evidence and publisher identity

#### Objectives

- Introduce verifier and normalized-identity boundaries without changing
  behavior.
- Make Sigstore/OIDC an adapter to the common model.

#### Deliverables

- Tagged signature-evidence model.
- Common verifier contract and normalized verification result.
- Normalized publisher identity and typed origin-authorization result.
- Legacy Sigstore evidence and ledger migration/decoding path.
- Updated unit and integration tests.

#### Acceptance criteria

- All existing Sigstore/OIDC positive and negative tests remain green.
- Existing OCI signature artifact types remain discoverable.
- Existing ledger records decode and re-verify.
- OIDC issuer and source-repository checks remain exact and reject lookalikes,
  prefixes, suffixes, unsupported issuers, missing repositories, and Unicode
  folding tricks.
- No CLI behavior changes except additional structured diagnostics explicitly
  approved in the contract.

#### Phase completion gate

Phase 1 is complete when the entire existing signing/enrolment path uses the
new abstraction and no X.509-specific conditional exists outside the verifier
adapter boundary.

### Phase 2: X.509/CMS verifier and trust-root store

#### Objectives

- Verify commercial or private-PKI Code Signing identities over cpak state.
- Establish a dedicated and distributable code-signing root program boundary.

#### Deliverables

- X.509/CMS verifier.
- Public embedded code-signing root bundle with provenance manifest.
- Root-owned administrator trust directory and import/remove/status CLI.
- Timestamp and offline revocation validation.
- OCI discovery and retrieval for the X.509 signature artifact type.
- Unit, fuzz, migration, and Linux integration tests.

#### Acceptance criteria

- A valid detached CMS signature over the exact canonical state verifies.
- Changing origin, manifest digest, image digest, lock digest, generation, CMS
  signature, signer certificate, or signed attributes causes failure.
- Unknown roots, incomplete chains, wrong EKU, wrong key usage, CA leafs,
  unsupported algorithms, future certificates, expired certificates without a
  valid timestamp, invalid timestamps, and revoked certificates are rejected.
- Certificate renewal over the same SPKI produces the same publisher ID.
- A new key produces a different publisher ID.
- The system TLS root store is not consulted by default.
- A root file writable by an unprivileged account is rejected.
- Public and local roots are distinguishable in `system explain` output.
- A current Sectigo Code Signing root can be represented in the public bundle
  using an exact fingerprint from the reviewed upstream dataset.
- Lack of a current Sectigo subscriber private key does not block the POC test
  suite; the POC CA exercises the same verifier path.

#### Phase completion gate

Phase 2 is complete when the privileged enrolment authority independently
re-verifies both legacy Sigstore and X.509 evidence and records either through
the common tagged format.

### Phase 3: Containerpak POC CA and signing workflow

#### Objectives

- Produce a reproducible private-PKI example without requiring current hardware.
- Demonstrate that cpak can consume a CA outside a commercial root program.

#### Deliverables

- CA profile and generation/issuance tooling kept outside production runtime.
- Public POC root and intermediate certificates, fingerprints, test CRL, and
  concise CP/CPS documentation.
- `cpak-sign` X.509 signing/attach workflow using a software key.
- Test publisher certificate and generated-at-test-time private material.
- Explicit opt-in root import instructions.

#### Acceptance criteria

- Root, intermediate, and leaf profiles satisfy the constraints in FR-4.
- The root key is not used to sign a publisher certificate.
- No reusable private key or passphrase is committed.
- A clean Linux environment can generate ephemeral test material, sign a cpak
  state, attach it, import the POC root, verify the publisher, and enrol the
  application.
- Without explicit root import, the same signature is rejected as untrusted.
- Removing the root causes subsequent full verification to fail without
  corrupting existing ledger data.
- The CLI labels the CA assurance as experimental and does not imply public
  trust or reputation.
- Generation, signing, attachment, root administration, verification, and
  enrolment are reproducible with no display server or session bus.

#### Phase completion gate

Phase 3 is complete when the private-PKI demonstration is reproducible from
documented commands with no secret material from a developer workstation.

### Phase 4: Publisher reputation provider

#### Objectives

- Demonstrate provider-neutral publisher reputation without building a remote
  service or collecting telemetry.
- Make freshness, authority, and failure behavior explicit.

#### Deliverables

- Reputation provider interface.
- Versioned signed-snapshot schema.
- Snapshot signer for development/test use and importer for cpak.
- Privileged snapshot store with anti-rollback state.
- Policy integration and CLI diagnostics.
- Fixtures for all reputation states and failure modes.

#### Acceptance criteria

- A valid, fresh snapshot from the configured provider is accepted.
- Tampered, wrongly signed, unsupported, expired, future-dated, oversized, or
  rollback snapshots are rejected.
- Unknown publisher and absent provider are distinct results.
- `established` suppresses only the reputation warning; it cannot override
  invalid evidence, revocation, or administrator denial.
- `blocked` produces the configured refusal and a stable reason code.
- `audit` records a result without changing the existing allow decision.
- Provider-unavailable behavior matches each configured policy mode.
- The same signed snapshot produces the same reputation and policy result on a
  graphical workstation, an interactive terminal, and a non-interactive host.
- Publisher display-name changes do not change or hijack reputation identity.
- Snapshot reason text is bounded and safe for terminal/log output.
- No network request or telemetry is emitted by the POC provider.

#### Phase completion gate

Phase 4 is complete when the same verified publisher can deterministically move
between unknown, established, caution, and blocked demonstration states solely
through authenticated provider evidence, with policy consequences proven by
tests.

### Phase 5: End-to-end policy, UX, and lifecycle integration

#### Objectives

- Exercise the complete install, update, enrolment, audit, explain, and launch
  lifecycle.
- Make every decision understandable without reading source code.
- Treat binaries without desktop entries, unattended automation, and services
  as first-class lifecycle paths.

#### Deliverables

- Final policy modes and migration behavior.
- Updated `verify-signature`, `audit`, and `system explain` output.
- Install and update integration for both evidence types.
- Re-verification and reputation refresh behavior.
- End-to-end Linux test harness.
- Versioned machine-readable decision output and stable exit-code mapping.
- Separate graphical, interactive-terminal, and non-interactive integration
  fixtures.

#### Acceptance criteria

- Signed install and signed update succeed for Sigstore and POC X.509 evidence.
- Publisher continuity is evaluated across update.
- A changed package with stale evidence is not enrolled under its old trusted
  state.
- A signed-to-unsigned transition remains visible and follows signature policy.
- Invalid attached evidence never becomes unsigned through fallback.
- Reputation is evaluated at install/update, not on every launch.
- A verified launch continues to validate anchored runtime identity without
  network or full PKI work.
- CLI output distinguishes verified publisher, root source, reputation, policy,
  and final action.
- Long publisher names, malformed external reason text, empty data, stale data,
  and provider failures remain readable and safe.
- Existing unmanaged-host defaults remain backward compatible.
- A binary-only package with no `.desktop` file can be installed, updated,
  enrolled, audited, explained, and run with no display or session bus.
- Non-interactive `warn` returns confirmation-required without waiting or
  launching a graphical helper; explicit administrator policy is required to
  obtain a different result.
- `--yes` alone cannot accept unknown/caution reputation or bypass invalid,
  revoked, or administratively denied evidence.
- Root import/removal and reputation snapshot administration work when run
  directly as root and through `sudo` or `doas`, without `pkexec` or `run0`.
- Human-readable output, machine-readable output, exit codes, and audit records
  agree on the final action and stable reason code.
- Provider outage and offline cached evidence follow configured policy without
  consulting a desktop service or performing network work during launch.
- Service restart and command execution enforce the enrolled state; policy or
  reputation changes affect future decisions but do not claim to terminate an
  already running process.

#### Phase completion gate

Phase 5 is complete when the real CLI workflow passes on Linux for graphical,
interactive-terminal, and non-interactive positive, negative, update, offline,
service, and recovery scenarios, and every output surface accurately explains
the same result.

### Phase 6: Publication package and final certification

#### Objectives

- Turn the implementation into a publishable study and reproducible example.
- Verify the complete POC against this plan.

#### Deliverables

- Updated publisher-signing documentation.
- X.509 and reputation operator documentation.
- Threat model and explicit limitations.
- Reproducible demo script or runbook.
- Architecture diagram mapping cpak components to the Linux Application Trust
  Framework abstractions.
- Implementation-independent decision schema, reason-code registry, invocation
  context semantics, and conformance requirements.
- Minimal AppImage conformance example that verifies a signed artifact and
  emits the same portable decision result without depending on cpak internals.
- Evidence report listing commands, results, unsupported environments, and any
  remaining gaps.
- Final branch diff ready for review.

#### Acceptance criteria

- A reader can reproduce the demo on a documented Linux environment.
- Documentation contains no production private key, reusable secret, or unsafe
  copy-paste default.
- Public-CA, POC-CA, publisher-policy, reputation, and runtime-integrity claims
  are described separately.
- The paper and implementation use consistent vocabulary and reason semantics.
- The cpak and AppImage actors produce conforming decision records for shared
  fixtures, including at least valid, unknown-reputation, invalid, and blocked
  cases in a headless environment.
- Every requirement and acceptance criterion has a proven result or an explicit
  documented exception accepted by the maintainers.
- No pull request has been opened before this phase passes.

#### Phase completion gate

Phase 6 is complete only when the overall Definition of Done below is satisfied.
At that point a pull request may be prepared, but it is opened only with
explicit authorization.

## 10. Required test matrix

### 10.1 Signature and state

- valid Sigstore/OIDC evidence;
- valid X.509/CMS evidence;
- altered signature;
- altered canonical state field, one test per field;
- signature over a tag or unresolved digest;
- malformed/truncated/oversized evidence;
- unsupported evidence kind or ABI;
- multiple candidates: valid plus invalid, foreign plus invalid, and all invalid;
- legacy OCI referrer and ledger fixtures.

### 10.2 X.509 identity and chain

- trusted public root;
- trusted local root;
- unknown root;
- missing and wrong intermediate;
- wrong EKU and key usage;
- leaf with `CA=true`;
- expired, not-yet-valid, and boundary-time certificates;
- valid and invalid RFC 3161 timestamp;
- revoked, good, unknown, and stale revocation state;
- unsupported or weak algorithms;
- duplicate/ambiguous signers;
- same-key renewal and new-key rotation;
- unsafe subject/display-name characters.

### 10.3 Trust-root administration

- exact fingerprint confirmation;
- non-root caller;
- symlink and path traversal attempts;
- writable parent or root file;
- atomic update interruption;
- duplicate root;
- removal and re-addition;
- corrupted public bundle;
- unsupported future bundle schema.

### 10.4 Reputation

- established, unknown, caution, blocked, and unavailable;
- valid and invalid snapshot signature;
- expiry, future date, and clock boundary;
- rollback and duplicate sequence;
- wrong provider identity;
- mismatched publisher ID;
- oversized snapshot and reason fields;
- interrupted atomic replacement;
- all policy modes and administrator-exception boundaries.

### 10.5 Lifecycle

- fresh install;
- update with same publisher and valid next generation;
- downgrade/replayed generation;
- publisher key change;
- signed-to-unsigned transition;
- signature or reputation revocation after installation;
- offline install from cached evidence;
- launch after provider outage;
- clean recovery after trust-root or snapshot correction.

### 10.6 Invocation context and desktopless operation

- graphical, interactive-terminal, and non-interactive presentation of the
  same underlying decision;
- binary-only cpak package with no desktop entry;
- no `DISPLAY`, `WAYLAND_DISPLAY`, session D-Bus, portal, or Secret Service;
- no TTY on stdin, stdout, or stderr;
- non-interactive `warn` returns confirmation-required without blocking;
- `--yes` cannot override trust or reputation policy;
- direct-root, `sudo`, and `doas` administration without a graphical agent;
- stable machine-readable schema, reason code, final action, and exit code;
- systemd or equivalent service start/restart using an enrolled binary;
- policy and reputation change while a process is already running;
- cpak and AppImage conformance records over shared headless fixtures.

## 11. Verification gates

The following commands are the minimum final verification set, adjusted only
when the repository adds a stricter canonical command:

```sh
go test -race ./...
go test -tags cpak_ui_builtin ./pkg/desktopui
go test -tags cpak_ui_adwaita ./pkg/desktopui
go vet ./...
go run . gen-schema --output /tmp/manifest-v2.json
diff -u schema/manifest-v2.json /tmp/manifest-v2.json
```

Additional required evidence:

- Linux builds of `cpak`, `cpak-sign`, and the installer artifacts;
- targeted fuzzing or a bounded fuzz corpus for CMS/ASN.1, root-bundle,
  reputation-snapshot, and legacy-record parsers;
- end-to-end execution on Linux using the real OCI referrer path;
- end-to-end execution on a Linux host with no graphical session, both with an
  interactive TTY and with all standard streams detached from a TTY;
- a binary-only cpak fixture and a service start/restart fixture;
- cpak/AppImage conformance comparison over the portable decision schema;
- offline verification after evidence has been retrieved;
- inspection proving that no private key or credential entered the Git diff;
- compatibility tests using records and evidence produced before the POC;
- a dependency and license audit for any library promoted or added;
- a security review of root import, privileged storage, parser boundaries,
  revocation, reputation authority, and policy precedence.

Commands must use normal developer caches. If sandboxing blocks those caches,
the command is rerun with the required authorization rather than relocating
tool caches into the repository or `/tmp`.

## 12. Risks and mitigations

### Root-store overreach

**Risk:** importing a TLS root pool silently authorizes CAs never reviewed for
cpak code signing.
**Mitigation:** dedicated code-signing root bundle, exact fingerprints,
provenance, and separate local roots.

### Valid-signature equals trusted-software confusion

**Risk:** users interpret a verified certificate as a safety verdict.
**Mitigation:** separate result types, policy stages, vocabulary, and tests that
reputation/policy cannot alter verification facts.

### Publisher identity instability

**Risk:** certificate renewal or key rotation resets or hijacks reputation.
**Mitigation:** SPKI-based POC identity, explicit same-key renewal tests, new ID
on re-key, and key continuity documented as future work.

### Revocation availability

**Risk:** network failure turns revocation into either an outage or a silent
allow.
**Mitigation:** explicit status and policy, cached signed CRL evidence, bounded
freshness, and separate consumer/managed failure behavior.

### Reputation authority compromise or rollback

**Risk:** a forged or old snapshot promotes or suppresses publishers.
**Mitigation:** separate provider keys, signed schema, expiry, monotonic
sequence, privileged storage, and rollback tests.

### CMS parser complexity

**Risk:** ambiguous ASN.1, multiple signers, or library defaults produce a
different verified message than cpak expects.
**Mitigation:** detached exact-content verification, single accepted signer
semantics, strict size/algorithm limits, malformed corpus tests, and dependency
review.

### POC CA mistaken for public assurance

**Risk:** users assume the experimental CA performs commercial identity
validation.
**Mitigation:** explicit opt-in trust, experimental assurance label, separate
CP/CPS, and no inclusion in the production default root bundle.

### Interactive-policy bypass on headless hosts

**Risk:** an unattended installer treats a warning as consent, hangs waiting
for an unavailable prompt, or uses `--yes` to cross a trust boundary.
**Mitigation:** explicit invocation context, confirmation-required result,
stable non-zero exit code, separate privileged exceptions, and negative tests
with no display, session bus, or TTY.

### Desktop assumptions in non-graphical packages

**Risk:** a binary-only package or service skips enrolment/enforcement, or a
trust operation fails because it assumes portals, Secret Service, or a
graphical privilege agent.
**Mitigation:** entrypoint-neutral enrolment, direct-root and terminal
administration paths, binary-only/service fixtures, and shared decision-core
tests across every frontend.

## 13. Overall Definition of Done

The Application Trust POC is done only when all of the following are true:

### Implementation

- Phases 0 through 6 have passed their completion gates.
- Both Sigstore/OIDC and X.509/CMS use the same normalized verification,
  identity, policy, and enrolment contracts.
- Existing Sigstore packages, trust policies, referrers, and ledger records
  remain compatible.
- The public and local code-signing root stores work through the privileged
  real path.
- The POC CA and X.509 signing example are reproducible without developer-owned
  secrets or a hardware token.
- Reputation snapshot verification, anti-rollback, policy, and diagnostics are
  implemented through the privileged real path.
- Graphical, terminal, and non-interactive callers consume the same portable
  decision result, and binary-only packages use the same enforcement path as
  packages exporting desktop entries.

### Security

- Every mandatory invariant in Section 5 has a direct automated test or
  documented manual verification.
- Invalid, foreign, revoked, stale, downgraded, ambiguous, and tampered evidence
  cannot be misreported as unsigned, verified, trusted, or established.
- Reputation cannot override cryptographic failure, certificate revocation, or
  administrator denial.
- Missing desktop facilities or a generic `--yes` cannot weaken policy, imply
  consent, or bypass a confirmation-required result.
- Root and reputation administration reject unprivileged or unsafe filesystem
  state.
- No private key, credential, token, PIN, or reusable test secret exists in the
  tracked diff.
- The scoped security review has no unresolved high- or critical-severity
  finding.

### Verification

- All project-defined tests, race tests, tagged UI tests, headless and
  no-TTY tests, vet, generation checks, Linux builds, parser robustness checks,
  and end-to-end scenarios pass.
- Verification evidence identifies what is proven, inferred, or not verified.
- Any environment-dependent public Sectigo signing demonstration is explicitly
  separated from the POC CA evidence and is not required until a usable
  commercial signing credential is available.

### Documentation and publication

- Operator, publisher, trust-root, reputation, threat-model, and demo
  documentation is complete and internally consistent.
- The example can be reproduced from a clean documented Linux environment.
- The portable specification is demonstrated by cpak and the minimal AppImage
  actor over shared fixtures without a desktop environment.
- Claims distinguish identity, integrity, policy, reputation, and safety.
- External sources and redistributed trust data have been reviewed for current
  accuracy, provenance, and usage terms.
- The branch diff contains only intentional POC work and no generated binaries
  or unrelated cleanup.

### Release readiness

- The final diff has been reviewed against this plan.
- The working tree is clean after intentional commits.
- No pull request was opened prematurely.
- Opening the final pull request, publishing the paper, or distributing the
  example happens only after explicit authorization.

## 14. Reference sources

- CA/Browser Forum, Code Signing Baseline Requirements:
  <https://cabforum.org/working-groups/code-signing/requirements/>
- Common CA Database, code-signing root resources:
  <https://www.ccadb.org/resources>
- Microsoft Trusted Root Program requirements:
  <https://learn.microsoft.com/en-us/security/trusted-root/program-requirements>
- Mozilla, risks of using a root store outside its curated purpose:
  <https://blog.mozilla.org/security/2021/05/10/beware-of-applications-misusing-root-stores/>
- Sectigo public code-signing root and intermediate documentation:
  <https://www.sectigo.com/knowledge-base/detail/sectigo-new-rsa-and-ecc-root-intermediate-certificates-2025>
- RFC 5280, Internet X.509 PKI certificate and CRL profile:
  <https://datatracker.ietf.org/doc/html/rfc5280>
- RFC 5652, Cryptographic Message Syntax:
  <https://datatracker.ietf.org/doc/html/rfc5652>
- RFC 3161, Time-Stamp Protocol:
  <https://datatracker.ietf.org/doc/html/rfc3161>
- RFC 3647, Certificate Policy and Certification Practices framework:
  <https://datatracker.ietf.org/doc/rfc3647/>
