# Application Trust POC Phase 4 evidence

Status: complete  
Branch: `poc/application-trust-framework`  
Functional head: `c77a020728f3531c47de845e87235c6a4d7a1470`  
Date: 2026-08-19

## 1. Scope delivered

Phase 4 adds a provider-neutral, offline publisher-reputation input and applies
it only after signature, identity, origin, and administrator policy have
succeeded. It does not create a central service, collect telemetry, or claim
that reputation proves software safety.

| Commit | Milestone |
| --- | --- |
| `35d18a5` | Strict signed-snapshot contract, RFC 8785 canonicalization, Ed25519 verification, exact normalized publisher lookup, freshness, and negative tests |
| `ea2cb97` | Root-owned provider/snapshot store, exact key admission, durable atomic replacement, unsafe-state rejection, and sequence rollback protection |
| `0392293` | ABI 2 policy modes, exact exceptions, headless confirmation semantics, authority precedence, and historical enrolment evidence |
| `f7a4a13` | Provider key generation, snapshot signing, fingerprint-bound administration, status/check commands, and no-display workflow |
| `c77a020` | Audit/explain diagnostics, fuzz seeds, Linux test-adapter fix, contract update, test matrix, and operator runbook |

## 2. Authenticated provider boundary

- Provider authorities are strict ABI 1 documents with one provider ID and one
  Ed25519 public key whose complete key ID is confirmed by the administrator.
- Snapshots are Ed25519 signatures over RFC 8785 canonical bytes of the signed
  object. Provider keys are independent of code-signing and timestamping roots.
- Schema, duplicate keys, unknown fields, trailing values, size, entry count,
  sorted uniqueness, normalized publisher IDs, status, reason codes, time, key,
  provider, signature, and sequence are all validated.
- The root-owned store keeps one complete signed envelope. File and directory
  data are flushed around atomic rename; no separate sequence file can diverge.
- Equal and lower sequences are rejected even after the active snapshot expires.
  A failed verification or interrupted write never replaces the prior record.
- Changing or clearing the provider invalidates its snapshot without touching
  publisher trust roots or integrity anchors.

## 3. Policy and desktopless behavior

ABI 1 semantics remain available unchanged. ABI 2 makes X.509 revocation and
reputation posture explicit and freezes four modes:

- `off` performs no provider lookup;
- `audit` records every result without changing the prior allow decision;
- `warn` allows established, denies blocked, and warns for other results;
- `require-established` denies every non-established result unless an exact
  administrator exception permits unknown or caution.

Exceptions bind the exact normalized publisher ID, canonical origin, status,
and optional expiry. They never override blocked reputation or any earlier
cryptographic, chain, revocation, origin, publisher, approval, or release
decision.

The authenticated status is identical on graphical and desktopless hosts.
Presentation is context-aware: a non-interactive `warn` invocation returns
`confirmation-required` instead of inventing consent. Provider administration,
signing, checking, enrolment, audit, and explain require no display server or
session bus. Launch reads only the already enrolled integrity identity; it does
not contact or re-evaluate a reputation provider.

## 4. Security review

The review traced untrusted JSON, provider-key admission, private-key handling,
snapshot signature input, freshness and rollback state, privileged file
ownership/modes, escalation arguments, policy precedence, administrator
exceptions, enrolment recording, diagnostics, and launch-time consumption.

No unresolved high- or critical-severity finding remains.

Security properties verified during review:

- no reputation result can bypass invalid evidence or an administrator denial;
- display names, prefixes, and lookalikes are not reputation selectors;
- `blocked` is not exception-capable;
- `--yes` is not consent and requires the exact previewed fingerprint;
- the privileged process rereads and rebinds source bytes after escalation;
- provider-controlled data printed as a reason is limited to a safe reason-code
  grammar; no arbitrary provider prose reaches a terminal;
- `pkg/reputation` has no filesystem, network, or telemetry dependency;
- recorded reputation is diagnostic history and never a launch authorization.

The first Linux certification run exposed a nil dereference in a test adapter
when exercising a deliberately empty OIDC identity. Production normalization
already rejected that identity. The adapter now preserves the negative result
without dereferencing it, and the full Linux suite proves the regression.

## 5. Acceptance evidence

| Requirement | Evidence | Result |
| --- | --- | --- |
| Fresh authenticated snapshot | Verifier and privileged-store positive suites | Pass |
| Tamper, wrong authority, malformed or ambiguous input | Strict parser tables, signature negatives, and fuzz seeds | Pass |
| Expired/future snapshot and unavailable provider | Injected-clock and absent-state tables | Pass |
| Anti-rollback and atomic replacement | Expired-active rollback and fault-injected write tests | Pass |
| Deterministic five-state result model | Provider lookup and frozen policy tables | Pass |
| Exact identity, not display name | Normalized publisher selector and exact lookup tests | Pass |
| Policy modes and scoped exceptions | Pure decision table and real authority enrolment tests | Pass |
| Earlier trust decisions precede reputation | Provider spy around signature and administrator refusal paths | Pass |
| Headless semantics | Non-interactive confirmation-required tests and CLI administration lifecycle | Pass |
| Historical diagnostics | Recorded-signature plus audit/explain reason-code tests | Pass |
| Offline/no telemetry | Dependency audit and Linux lifecycle without provider networking | Pass |

The complete row-to-test mapping is maintained in
`application-trust-test-matrix.md`.

## 6. Verification record

Local checks at functional head:

| Check | Result |
| --- | --- |
| `go test ./pkg/reputation -run 'Test|Fuzz.*seed' -count=1` | Pass |
| `GOOS=linux GOARCH=amd64 go test -exec=/usr/bin/true ./...` | Compile pass for every package |
| `GOOS=linux GOARCH=amd64 go vet ./...` | Pass |
| `git diff --check` | Pass |

Portability run `32249945862` failed consistently on the newly exercised empty
identity in the system-authority test adapter. This was treated as a real gate,
fixed in `c77a020`, and not retried unchanged.

Final Portability run
[`32250642559`](https://github.com/pietrodicaprio/cpak/actions/runs/32250642559)
covers functional head `c77a020728f3531c47de845e87235c6a4d7a1470` and passed:

- the full project test, vet, build, and doctor command on Ubuntu 22.04,
  Ubuntu 24.04, and `ubuntu-latest`;
- the CGO-free Linux amd64 build;
- userspace execution on Debian 13, Fedora 42, Arch Linux, openSUSE Tumbleweed,
  and Ubuntu 26.04.

## 7. Completion decision

The same verified publisher can be moved deterministically among unknown,
established, caution, and blocked through authenticated signed snapshots. The
configured policy produces explicit, tested consequences in graphical,
terminal, service, and unattended contexts without launch-time networking.
Phase 4 is complete. Full install/update lifecycle presentation and the second
AppImage actor remain Phase 5 and Phase 6 work respectively.
