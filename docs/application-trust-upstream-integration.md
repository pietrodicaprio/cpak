# Application Trust upstream baseline integration

- Integration branch: `integration/application-trust-e86fa23`
- POC parent: `d06dc0a`
- Common ancestor: `be29d55`
- Upstream baseline: `38fa798` (`v2.9.7`)
- Semantic merge: `d7f9034`
- Certified code: `a17078f`
- Status: certified in Portability run `33168708481`

This integration brings the 18 upstream commits after `be29d55`, including the
`v2.9.7` package-authority hardening, into the Application Trust POC before
Phase 6. The historical integration branch name is retained for continuity;
the original
`poc/application-trust-framework` branch remains the reference for the earlier
Phase 5 certification.

## Security properties preserved across conflicts

| Conflict surface | Integrated property | Regression evidence |
| --- | --- | --- |
| `cmd/cpak-installer/main.go`, `main_test.go` | The signed installer binds an immutable commit, manifest identity, summarized permissions, and embedded cpak binary. Its operation consent remains separate from graphical publisher-reputation confirmation. Closed terminal input cannot imply consent. | `TestGraphicalInstallSelectsOnlyTheDedicatedTrustFrontend`, `TestPermissionLinesShowTheSignedDetails`, `TestClosedInputCannotApproveATerminalInstall` |
| `cmd/install.go`, `install_prompt_test.go` | A verified signed installer may replace the generic operation prompt, but it never installs a reputation-confirmation callback in a non-interactive context. Only the dedicated terminal or graphical trust prompt may confirm a warning. Manifest validation and signed-installer verification run before installation, and repository origins use upstream canonical normalization. | `TestSignedInstallerConsentDoesNotAcceptPublisherReputation`, `TestVerifySignedInstallerMetadataRejectsPermissionChanges`, `TestVerifySignedInstallerMetadataRequiresPinnedStandalonePackage`, `TestSignedInstallerConsentRejectsAnOrdinaryParentProcess` |
| `cmd/cpak-sign/attach.go`, `attach_test.go`, `cmd/verify_signature.go` | Publication and direct verification use the common evidence dispatcher. Attached evidence must cover the exact state and carry explicit origin authorization; X.509 and Sigstore retain distinct evidence profiles. | `TestAttachVerifiesThroughTheSignaturePackage`, `TestAttachPublishesNothingWhenTheBundleDoesNotVerify`, `TestAttachRefusesAnIdentityThatCannotSpeakForTheOrigin`, `TestVerifySignatureSelectsAnExplicitEvidenceProfile` |
| `pkg/cpak/signature.go`, `signature_test.go` | Registry discovery keeps evidence kind and media type. Publisher verification accepts only `OriginAuthorized`; foreign valid evidence remains distinct from invalid and unsigned evidence. | `TestVerifyPackageStateRefusesAnIdentityThatCannotSpeakForTheOrigin`, `TestMixedEvidenceCandidatesPreserveValidForeignAndInvalidOutcomes`, `TestVerifyPackageStateDiscoversX509EvidenceThroughItsOwnOCIProfile` |
| `pkg/cpak/approval.go` | Approval verifies the exact state and reports the signer identity without borrowing publisher origin authorization. Publisher verification and local approval remain separate decisions. | `TestApprovalsOfReportsWhoCounterSignedTheStateTheInstallationResolved`, `TestApprovalsOfDoesNotReadThePublisherSignatureAsAnApproval`, `TestApprovalsOfRefusesAStateThatNamesAnotherOrigin` |
| `pkg/cpak/enrol.go` | Invalid or foreign attached evidence cannot fall back to unsigned. Reputation warning, refusal, confirmation, rotation, and recorded verification remain part of the enrolment result. | `TestEnrolPublishedApplicationRefusesFallbackWhenTheBundleDoesNotStand`, `TestEnrolPublishedApplicationRefusesASignatureFromAnotherIdentity`, `TestReputationWarningUsesOnlyTheDedicatedEnrolmentConfirmation`, `TestChangedReputationWarningRequiresANewConfirmation` |
| `pkg/cpak/installer.go`, installer tests | Application Trust enrolment callbacks remain part of installation while upstream dependency traversal enforces depth, count, duplicate, and cycle limits. | Full `pkg/cpak` suite and Phase 5 nested-dependency lifecycle |
| `pkg/systemauthority/anchor.go`, `anchor_test.go` | The authority recomputes verification, trust policy, and reputation. Signed enrolment records an exact single-use reputation confirmation only after the authority validates its challenge and action. Legacy integrity-policy schema detection remains combined with verification/reputation validation; the version domains remain independent. | `TestEnrolmentReadsAndSupersedesAPolicyFromBeforeSerialDevices`, `TestEnrolmentRecognizesAPolicyFromBeforeDesktopCapabilities`, `TestForgottenAnchorReadsAPolicyFromBeforeSerialDevices`, `TestRecordedAuthorityVerificationRejectsUnknownRevocationState` |
| `pkg/systemauthority/socket.go`, D-Bus and socket tests | Upstream signed-evidence transport and privileged root re-entry preserve the POC confirmation instead of dropping it. Strict bounded JSON and peer credentials remain enforced; confirmation-required and refusal results keep stable structured codes and data across D-Bus, Unix socket, and re-entry. | `TestSignedConfirmationFallsBackWithoutDroppingTheChallenge`, `TestAuthoritySocketPreservesAReputationWarningAndConfirmation`, `TestAuthoritySocketPreservesAReputationRefusal` |
| `pkg/systemauthority/privsep.go` | Publisher-chosen Sigstore or CMS bytes are parsed only by the unprivileged, network-isolated verifier child. The flat common result crosses the boundary under strict, bounded JSON decoding. | `TestTheChildDoesNotKeepRoot`, `TestTheChildHasNoNetwork`, `TestTheParentRequiresExactlyOneChildAnswer`, `TestSeparatedVerifierRefusesOpaqueCallerTrustMaterial` |

## Upstream security baseline carried by the merge

- Manifest v3 requires digest-pinned code, rejects raw host desktop sockets,
  and uses filtered D-Bus and mediated X11/Bluetooth capabilities.
- Launch fails closed when Landlock or seccomp is unavailable, and the seccomp
  profile blocks additional kernel attack surfaces.
- Archive extraction rejects paths and links outside the destination.
- Nested services are limited to declared nested dependencies.
- Signed installer, self-update metadata, D-Bus message framing, descriptor
  limits, storage migration, and installed-source removal use the upstream
  hardened implementations and regression suites.

The Phase 5 X.509 and Sigstore process fixtures now publish Manifest v3 with
digest-pinned images. The stale-evidence lifecycle changes the repository
manifest to a second immutable image digest while deliberately serving evidence
for the first digest, then proves refusal and recovery with evidence for the
second state.

## Verification ledger

The following checks passed against the semantic integration on macOS cross
compilation and an isolated Ubuntu 24.04 VPS checkout:

```text
GOOS=linux GOARCH=amd64 go test -exec=true ./...
GOOS=linux GOARCH=amd64 go vet ./...
go test ./...
go test -race ./pkg/systemauthority ./pkg/cpak ./cmd
TMPDIR=/home/fab/t ./hack/application-trust-phase5/run-linux.sh
```

The VPS test process used its normal Go caches, `umask 022`, and a short,
owner-only `TMPDIR` because trust-store tests correctly reject group-writable
parents and Unix-domain sockets have a bounded path length.

The Ubuntu 22.04 kernel job initially exposed an upstream test-fixture problem:
the nested service correctly re-executed its real temporary Go test binary, but
the test then hid `/tmp`. Commit `a17078f` binds that binary at
`/run/cpak-test` before hiding `/tmp`, preserving production executable
identity without relying on kernel-specific `/proc/self/exe` behavior.

The completion authority is
[Portability run 33168708481](https://github.com/pietrodicaprio/cpak/actions/runs/33168708481)
at certified code commit `a17078f`. `application-trust-phase5`,
`application-trust-phase5-sigstore`, all three kernel jobs, all five userspace
jobs, and the binary build passed. The Sigstore job obtained fresh GitHub
Actions OIDC, Fulcio, and Rekor evidence for this exact integrated commit.
Phase 6 may start from this baseline.
