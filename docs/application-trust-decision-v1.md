# Application Trust Decision Result v1

Status: frozen for the Phase 5 POC  
JSON Schema: `schema/application-trust-decision-v1.json`

This document defines the portable result produced by an application-trust
actor. It is independent of cpak storage, manifests, policy files, command-line
presentation, and privilege transports. cpak is the first actor. The AppImage
demonstrator consumes the same contract in Phase 6.

## 1. Contract boundary

A result separates facts, policy, presentation consent, and the final action:

1. `verification` describes evidence and cryptographic verification;
2. `publisher` describes the verified publisher identity, or its absence;
3. `trust` describes chain, root, signing-time, and revocation facts;
4. `reputation` describes the authenticated historical provider result;
5. `policy` describes the host policy action and any interactive confirmation;
6. `final` is the only field that decides the command outcome and exit code.

No earlier stage may claim that software is safe. A verified signature proves
only the state and identity described by the selected evidence profile.
Reputation is historical provider data, not a cryptographic or safety fact.

Every stage is present even when it was not evaluated. Absence is represented
by an explicit status and reason code, never by omission or a zero value.

## 2. Top-level fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1`. A consumer rejects any other version. |
| `actor` | Bounded implementation identifier, for example `cpak`. It is diagnostic and never a trust input. |
| `operation` | `verify`, `install`, `update`, `audit`, `explain`, `launch`, or `service-start`. |
| `context` | `graphical`, `interactive-terminal`, or `non-interactive`. |
| `decision_source` | `evaluated` for a new decision or `recorded` for authenticated historical state. |
| `subject` | Origin and, when available, immutable artifact digest and publisher generation. |
| `verification` | Evidence kind, verification status, stable reason, and bounded diagnostic. |
| `publisher` | Identity status, normalized ID, bounded display name, and origin authorization. |
| `trust` | Chain, root source, signing-time, and revocation status. |
| `reputation` | Provider, status, freshness, snapshot time, and stable reason. |
| `policy` | Signature mode, reputation mode, policy action, confirmation state, exception flag, and stable reason. |
| `final` | Final action, exit class, reason code, and exact exit code. |

`subject.origin` is the actor-selected origin. Evidence cannot replace it.
`subject.artifact_digest`, when present, is an immutable digest and not a tag or
mutable registry reference.

## 3. Explicit absence and status values

Verification status is one of `verified`, `unsigned`, `invalid`, `unavailable`,
or `not-evaluated`. Evidence kind is one of `sigstore-bundle-v1`,
`x509-cms-v1`, `none`, or `unknown`.

Publisher status is one of `verified`, `absent`, `invalid`, `unavailable`, or
`not-evaluated`. `publisher.id` is present only for a normalized verified
identity. `publisher.display_name` is optional, bounded presentation text and
never an authorization selector. `publisher.origin_authorization` is one of
`authorized`, `foreign`, `unsupported`, or `not-evaluated`; it is computed
against `subject.origin` and never copied from evidence.

Chain status is one of `trusted-public`, `trusted-local`, `not-applicable`,
`untrusted`, `invalid`, or `not-evaluated`. Signing-time status is one of
`current`, `timestamped`, `missing`, `expired`, `not-yet-valid`, `invalid`,
`not-applicable`, or `not-evaluated`. Revocation status is one of `good`,
`revoked`, `unknown`, `stale`, `not-applicable`, or `not-evaluated`.

Reputation status is one of `established`, `unknown`, `caution`, `blocked`,
`unavailable`, or `not-consulted`. Freshness is one of `fresh`, `stale`,
`unavailable`, or `not-applicable`.

## 4. Confirmation semantics

Policy action is one of `allow`, `warn`, `deny`, or `not-evaluated`.
Confirmation state is one of `not-required`, `required`, `accepted`,
`declined`, or `not-available`.

Invocation context is presentation metadata, not a trust fact. It can affect
only how a `warn` action is completed:

| Policy action | Context | Confirmation | Final action |
| --- | --- | --- | --- |
| `allow` | any | `not-required` | `allow` |
| `deny` | any | `not-required` | `deny` |
| `warn` | graphical or interactive terminal | accepted at the dedicated trust prompt | `warn` |
| `warn` | graphical or interactive terminal | declined | `deny` |
| `warn` | graphical or interactive terminal | no answer obtained | `confirmation-required` |
| `warn` | non-interactive | `not-available` | `confirmation-required` |

The operation acknowledgement represented by cpak's `--yes` flag is not a
trust confirmation and must never produce `accepted`. A caller cannot use
context or confirmation to replace an invalid, revoked, blocked, unavailable,
or administratively denied result. An accepted warning is ephemeral for the
current install or update. It does not create a reputation fact or a persistent
administrator exception.

The official actor adapter owns prompt collection. The portable decision core
receives confirmation as a separate typed input; it never infers confirmation
from a TTY, display, `--yes`, environment variable, timeout, or default value.

For a privileged enrolment, the authority issues an opaque challenge only
after recomputing a `warn` result. The challenge expires after five minutes, is
single-use, and is bound to the exact user, origin, generation, launch root,
signed-state digest, provider snapshot, reputation status, and reason codes.
After an interactive adapter accepts the warning, the authority consumes the
challenge and recomputes every fact and policy before recording. A changed
warning requires a new confirmation; a changed deny remains denied. The
challenge binds a confirmation to a decision but is not itself evidence that a
human saw a prompt, so official adapters and their negative tests remain part
of the confirmation boundary. Challenges are never result, ledger, or log
fields.

## 5. Final actions and stable exit codes

`final.action`, `final.class`, and `final.exit_code` are an indivisible mapping:

| Final action | Exit class | Exit code | Meaning |
| --- | --- | ---: | --- |
| `allow` | `allowed` | 0 | Policy allows the operation without a warning. |
| `warn` | `allowed` | 0 | The dedicated interactive warning was accepted. |
| `deny` | `denied` | 20 | Policy or the user explicitly refused the operation. |
| `invalid` | `invalid` | 21 | Evidence, state, identity, or authenticated data is malformed, ambiguous, unsupported, or cryptographically invalid. |
| `unavailable` | `unavailable` | 22 | A required authority or trust input could not produce a decision. |
| `confirmation-required` | `confirmation-required` | 23 | Policy requires a dedicated confirmation that this invocation cannot provide. |

Provider unavailability does not automatically imply exit code 22. In `off`,
`audit`, or `warn` mode the policy may still produce an allowed or warning
result. Exit code 22 is used only when unavailability is the final action.

An actor returning a portable result returns the exit code carried by `final`.
Localized text, logs, and table formatting never select an exit code.

## 6. Reason codes and external text

Every stage has a stable `reason_code` matching
`^[a-z0-9][a-z0-9._-]{0,63}$`. Codes are semantic API values and are never
localized. A stage that was not evaluated uses `not-evaluated`; a policy that
does not consult reputation uses `not-consulted`.

`verification.diagnostic`, `publisher.display_name`, and `trust.root_source`
are presentation data. Before a result is emitted they must be valid UTF-8,
must contain no C0 or DEL control characters, and must be truncated to their
schema bounds. They never participate in identity, policy, or exit selection.
Private keys, tokens, credentials, passphrases, PINs, and raw evidence payloads
are never result fields.

## 7. Validation and compatibility

Producers validate a result before printing or recording it. Consumers reject:

- unsupported schema versions;
- unknown fields or enum values;
- missing stages;
- a final action/class/exit-code combination outside the frozen table;
- identity values attached to an unverified publisher;
- an allowed install, update, launch, or service start whose verified publisher
  is not authorized for the subject origin;
- an evidence kind of `none` unless verification is `unsigned` or
  `not-evaluated`;
- confirmation accepted in a non-interactive context;
- confirmation used to override a final action other than a warning;
- invalid timestamps, reason codes, digests, control characters, or bounds.

New optional presentation fields require a new schema version because v1
rejects unknown fields. New reason codes do not require a schema version when
they preserve the documented stage and final-action semantics.
