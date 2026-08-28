# Application Trust upstream baseline integration

- Integration branch: `integration/application-trust-e86fa23`
- POC parent: `d06dc0a`
- Common ancestor: `be29d55`
- Upstream baseline: `e86fa23`
- Status: local semantic integration verified; fresh Phase 5 CI certification pending

This integration brings the 17 upstream commits after `be29d55` into the
Application Trust POC before Phase 6. The original
`poc/application-trust-framework` branch remains the reference for the earlier
Phase 5 certification.

## Security properties preserved across conflicts

| Conflict surface | Integrated property | Regression evidence |
| --- | --- | --- |
| `cmd/cpak-installer/main.go`, `main_test.go` | The signed installer binds an immutable commit, manifest identity, summarized permissions, and embedded cpak binary. Its operation consent remains separate from graphical publisher-reputation confirmation. Closed terminal input cannot imply consent. | `TestGraphicalInstallSelectsOnlyTheDedicatedTrustFrontend`, `TestPermissionLinesShowTheSignedDetails`, `TestClosedInputCannotApproveATerminalInstall` |
| `cmd/install.go`, `install_prompt_test.go` | A verified signed installer may replace the generic operation prompt, but it never installs a reputation-confirmation callback in a non-interactive context. Only the dedicated terminal or graphical trust prompt may confirm a warning. Manifest validation and signed-installer verification run before installation. | `TestSignedInstallerConsentDoesNotAcceptPublisherReputation`, `TestVerifySignedInstallerMetadataRejectsPermissionChanges`, `TestVerifySignedInstallerMetadataRequiresPinnedStandalonePackage`, `TestSignedInstallerConsentRejectsAnOrdinaryParentProcess` |
| `cmd/cpak-sign/attach.go`, `attach_test.go`, `cmd/verify_signature.go` | Publication and direct verification use the common evidence dispatcher. Attached evidence must cover the exact state and carry explicit origin authorization; X.509 and Sigstore retain distinct evidence profiles. | `TestAttachVerifiesThroughTheSignaturePackage`, `TestAttachPublishesNothingWhenTheBundleDoesNotVerify`, `TestAttachRefusesAnIdentityThatCannotSpeakForTheOrigin`, `TestVerifySignatureSelectsAnExplicitEvidenceProfile` |
| `pkg/cpak/signature.go`, `signature_test.go` | Registry discovery keeps evidence kind and media type. Publisher verification accepts only `OriginAuthorized`; foreign valid evidence remains distinct from invalid and unsigned evidence. | `TestVerifyPackageStateRefusesAnIdentityThatCannotSpeakForTheOrigin`, `TestMixedEvidenceCandidatesPreserveValidForeignAndInvalidOutcomes`, `TestVerifyPackageStateDiscoversX509EvidenceThroughItsOwnOCIProfile` |
| `pkg/cpak/approval.go` | Approval verifies the exact state and reports the signer identity without borrowing publisher origin authorization. Publisher verification and local approval remain separate decisions. | `TestApprovalsOfReportsWhoCounterSignedTheStateTheInstallationResolved`, `TestApprovalsOfDoesNotReadThePublisherSignatureAsAnApproval`, `TestApprovalsOfRefusesAStateThatNamesAnotherOrigin` |
| `pkg/cpak/enrol.go` | Invalid or foreign attached evidence cannot fall back to unsigned. Reputation warning, refusal, confirmation, rotation, and recorded verification remain part of the enrolment result. | `TestEnrolPublishedApplicationRefusesFallbackWhenTheBundleDoesNotStand`, `TestEnrolPublishedApplicationRefusesASignatureFromAnotherIdentity`, `TestReputationWarningUsesOnlyTheDedicatedEnrolmentConfirmation`, `TestChangedReputationWarningRequiresANewConfirmation` |
| `pkg/systemauthority/anchor.go`, `anchor_test.go` | The authority recomputes verification, trust policy, and reputation. Legacy integrity-policy schema detection is combined with verification/reputation validation; the version domains remain independent. | `TestEnrolmentReadsAndSupersedesAPolicyFromBeforeSerialDevices`, `TestEnrolmentRecognizesAPolicyFromBeforeDesktopCapabilities`, `TestForgottenAnchorReadsAPolicyFromBeforeSerialDevices`, `TestRecordedAuthorityVerificationRejectsUnknownRevocationState` |
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

The following checks passed against the uncommitted integration tree copied to
an isolated Ubuntu 24.04 VPS checkout:

```text
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -exec /usr/bin/true ./... -count=1
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

The VPS test process used its normal Go caches, `umask 022`, and a short,
owner-only `TMPDIR` because trust-store tests correctly reject group-writable
parents and Unix-domain sockets have a bounded path length.

Fresh `application-trust-phase5` and
`application-trust-phase5-sigstore` jobs at the integrated commit remain the
completion authority. Phase 6 does not begin until both jobs pass at the same
commit and this document records their run.
