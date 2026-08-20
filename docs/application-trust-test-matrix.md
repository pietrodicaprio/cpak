# Application Trust POC Test Matrix

- Status: Phases 0 through 4 implemented; Phases 5 and 6 planned
- Baseline: cpak v2.6.0 (`12e835c`)
- Last updated: 2026-08-19

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
| AT-BAS-005 | Legacy and tagged ledger forms decode to equivalent common evidence | `TestLegacyAndTaggedEvidenceDecodeEquivalently` and `TestLegacyAnchorLedgerFixtureStillDecodesStrictly` | 1 | Implemented |
| AT-BAS-006 | Mixed legacy and tagged fields are rejected as ambiguous | `TestStoredEvidenceDecoderFailsClosed/mixed_legacy_and_tagged_fields` | 1 | Implemented |
| AT-BAS-007 | Unsupported evidence ABI fails closed | `TestStoredEvidenceDecoderFailsClosed/unsupported_abi` and `TestTheAuthorityRefusesAnUnsupportedEvidenceABI` | 1 | Implemented |
| AT-BAS-008 | Unknown fields and trailing JSON values fail closed | Phase 1 evidence and ledger cases in `TestStoredEvidenceDecoderFailsClosed` and `TestLedgerRejectsDuplicateKeysBeforeJSONCanMergeThem`; later formats remain assigned to Phases 2-4 | 1-4 | Implemented (Phase 1 scope) |
| AT-BAS-009 | Reading a legacy record does not rewrite it | `TestReadingALegacyLedgerRecordDoesNotRewriteIt` compares bytes and mtime | 1 | Implemented |
| AT-BAS-010 | A valid update rewrites legacy evidence only to the tagged form | `TestValidUpdateRewritesLegacySignatureAsTaggedEvidence` | 1 | Implemented |

## 3. Signature and exact state binding

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-SIG-001 | Existing Sigstore/OIDC positive verification remains green | Existing `pkg/signature` and `pkg/cpak` signature tests | 1 | Existing |
| AT-SIG-002 | OIDC issuer and repository comparison stays exact | Existing `TestMatchesOriginRefusesEveryLookalike` plus `TestTypedOIDCAuthorizationRefusesEveryLookalike` on the common path | 1 | Implemented |
| AT-SIG-003 | Valid detached CMS over canonical state verifies | `TestValidDetachedCMSVerifiesAndNormalizesThePublisher` | 2 | Implemented |
| AT-SIG-004 | Changed origin invalidates evidence | `TestCMSIsBoundToEveryCanonicalStateField/origin` | 2 | Implemented |
| AT-SIG-005 | Changed manifest digest invalidates evidence | `TestCMSIsBoundToEveryCanonicalStateField/manifest` | 2 | Implemented |
| AT-SIG-006 | Changed resolved image digest invalidates evidence | `TestCMSIsBoundToEveryCanonicalStateField/image` | 2 | Implemented |
| AT-SIG-007 | Changed lock digest invalidates evidence | `TestCMSIsBoundToEveryCanonicalStateField/lock` | 2 | Implemented |
| AT-SIG-008 | Changed generation invalidates evidence | `TestCMSIsBoundToEveryCanonicalStateField/generation` | 2 | Implemented |
| AT-SIG-009 | A tag or unresolved image reference is never signed or verified | Existing state validation plus `TestFetchPackageSignatureRefusesAReferenceInPlaceOfAResolvedDigest`; signing production remains Phase 3 | 2-3 | Implemented (Phase 2 verifier scope) |
| AT-SIG-010 | Altered CMS signature is invalid | `TestCMSRejectsMalformedAndWeakInputs/bit_flip` | 2 | Implemented |
| AT-SIG-011 | Altered signer certificate is invalid | `TestCMSRejectsCertificateSubstitutionAndBrokenChains` | 2 | Implemented |
| AT-SIG-012 | Malformed, truncated, trailing, BER-only, and oversized CMS fail closed | `TestCMSRejectsMalformedAndWeakInputs` plus `FuzzStrictCMSParser` | 2 | Implemented |
| AT-SIG-013 | Unsupported evidence kind or media type is invalid, not unsigned | `TestStoredEvidenceDecoderFailsClosed`, `TestUnsupportedVerifierIsInvalidEvidenceNotUnsigned`, and `TestFetchPackageSignatureRefusesASignatureArtifactWithTheWrongLayerType` | 1-2 | Implemented (Phase 1 scope) |
| AT-SIG-014 | Zero CMS signers is rejected | `TestCMSRejectsAmbiguousSignersAttributesAndAlgorithms/zero_signers` | 2 | Implemented |
| AT-SIG-015 | Multiple CMS signers are rejected as ambiguous | `TestCMSRejectsAmbiguousSignersAttributesAndAlgorithms/multiple_signers` | 2 | Implemented |
| AT-SIG-016 | Duplicate or ambiguous signed attributes are rejected | `TestCMSRejectsAmbiguousSignersAttributesAndAlgorithms` | 2 | Implemented |
| AT-SIG-017 | Valid plus invalid candidates accept the valid candidate and report the invalid one | `TestMixedEvidenceCandidatesPreserveValidForeignAndInvalidOutcomes/valid_X.509_outranks_invalid_Sigstore` | 2 | Implemented |
| AT-SIG-018 | Foreign plus invalid candidates report foreign/invalid and do not become unsigned | `TestMixedEvidenceCandidatesPreserveValidForeignAndInvalidOutcomes/foreign_X.509_outranks_invalid_Sigstore` | 1-2 | Implemented |
| AT-SIG-019 | All invalid candidates produce invalid, not unsigned | `TestMixedEvidenceCandidatesPreserveValidForeignAndInvalidOutcomes/all_invalid_stays_invalid` | 1-2 | Implemented |
| AT-SIG-020 | Manifest permissions remain in the signed state | Existing state digest tests plus lifecycle mutation test | 1, 5 | Existing/Planned |

## 4. Publisher identity and origin authorization

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-ID-001 | OIDC ID is the SHA-256 of the frozen canonical issuer/repository preimage | `TestOIDCPublisherIDUsesTheFrozenPreimage` | 1 | Implemented |
| AT-ID-002 | X.509 ID is lowercase-hex SHA-256 over DER SPKI | `TestValidDetachedCMSVerifiesAndNormalizesThePublisher` computes the independent SPKI digest | 2 | Implemented |
| AT-ID-003 | Same-key certificate renewal preserves X.509 publisher ID | `TestX509PublisherIdentityFollowsTheSPKI` | 2 | Implemented |
| AT-ID-004 | New publisher key creates a different ID | `TestX509PublisherIdentityFollowsTheSPKI` | 2 | Implemented |
| AT-ID-005 | Display-name changes do not change authorization or reputation ID | `TestX509PublisherIdentityFollowsTheSPKI` | 2, 4 | Implemented (Phase 2 identity scope) |
| AT-ID-006 | Certificate subject and package metadata never authorize an origin | `TestX509PublisherIdentityFollowsTheSPKI` and exact-state tests | 2 | Implemented |
| AT-ID-007 | X.509 signer covers the exact state containing the origin | `TestCMSIsBoundToEveryCanonicalStateField/origin` | 2 | Implemented |
| AT-ID-008 | Host policy can restrict an X.509 publisher ID to an exact origin | Policy unit and authority integration test | 2, 5 | Planned |
| AT-ID-009 | Publisher and distributor identities are reported separately | CLI structured-output and explain tests | 5 | Planned |
| AT-ID-010 | Unsafe subject characters cannot inject terminal or log output | `TestX509DisplayNamesCannotInjectTerminalOutput`; full CLI snapshots remain Phase 5 | 2, 5 | Implemented (Phase 2 identity scope) |

## 5. X.509 path, usage, algorithms, and time

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-X509-001 | Chain to an admitted public code-signing root succeeds | `TestPublicAndImportedLocalRootsProduceDistinctTrustResults/public` | 2 | Implemented |
| AT-X509-002 | Chain to an explicitly imported local root succeeds | `TestPublicAndImportedLocalRootsProduceDistinctTrustResults/local` | 2 | Implemented |
| AT-X509-003 | Unknown root fails | `TestCMSRejectsCertificateSubstitutionAndBrokenChains/unknown_root` | 2 | Implemented |
| AT-X509-004 | Missing or wrong intermediate fails | `TestCMSRejectsCertificateSubstitutionAndBrokenChains` | 2 | Implemented |
| AT-X509-005 | Leaf without Code Signing EKU fails | `TestX509LeafProfileFailsClosed/wrong_EKU` | 2 | Implemented |
| AT-X509-006 | Leaf without digital-signature key usage fails | `TestX509LeafProfileFailsClosed/missing_digital_signature` | 2 | Implemented |
| AT-X509-007 | Leaf with `CA=true` fails | `TestX509LeafProfileFailsClosed/CA_leaf` | 2 | Implemented |
| AT-X509-008 | Not-yet-valid leaf fails at both sides of the boundary | `TestX509LeafProfileFailsClosed/not_yet_valid` | 2 | Implemented |
| AT-X509-009 | Currently valid leaf without timestamp succeeds as `current` | `TestValidDetachedCMSVerifiesAndNormalizesThePublisher` | 2 | Implemented |
| AT-X509-010 | Expired leaf without verified timestamp fails | `TestExpiredLeafNeedsAnRFC3161Timestamp` | 2 | Implemented |
| AT-X509-011 | Valid RFC 3161 token preserves verification after leaf expiry | `TestRFC3161TimestampPreservesAnExpiredPublisherCertificate` | 2-3 | Implemented (Phase 2 verifier scope) |
| AT-X509-012 | Timestamp message-imprint mismatch fails | `TestRFC3161MessageImprintMismatchFails` | 2 | Implemented |
| AT-X509-013 | Untrusted, wrong-EKU, expired, or malformed TSA chain fails | `TestRFC3161RejectsUntrustedAndWrongEKUTSAs` | 2 | Implemented |
| AT-X509-014 | CMS `signingTime` alone never extends validity | `TestExpiredLeafNeedsAnRFC3161Timestamp` | 2 | Implemented |
| AT-X509-015 | SHA-1, MD5, DSA, RSA-PSS, unknown parameters, and mismatched algorithm identifiers fail as invalid or explicitly unsupported | `TestCMSRejectsMalformedAndWeakInputs` and `TestCMSRejectsAmbiguousSignersAttributesAndAlgorithms` | 2 | Implemented |
| AT-X509-016 | Approved RSA and ECDSA profiles succeed | RSA positive tests plus `TestApprovedECDSACMSProfileVerifies` | 2 | Implemented |
| AT-X509-017 | System TLS roots are not consulted | `TestX509VerifierNeverConsultsTheSystemTLSRoots` | 2 | Implemented |

## 6. Revocation

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-REV-001 | Current issuer-signed CRL without the serial produces `good` | `TestOfflineCRLStatusesAndCutoff/good` | 2 | Implemented |
| AT-REV-002 | Applicable CRL entry produces `revoked` and blocks | `TestOfflineCRLStatusesAndCutoff/revoked` | 2, 5 | Implemented (Phase 2 verifier scope) |
| AT-REV-003 | No applicable CRL produces `unknown` | `TestOfflineCRLStatusesAndCutoff/missing` | 2 | Implemented |
| AT-REV-004 | Expired or not-yet-valid CRL produces `stale` and blocks | `TestOfflineCRLStatusesAndCutoff` and `TestOfflineCRLRejectsInvalidAndFutureEvidence` | 2 | Implemented |
| AT-REV-005 | Wrong issuer, invalid signature, and unknown critical extension are rejected | `TestOfflineCRLRejectsInvalidAndFutureEvidence` and `TestUnknownCriticalCRLExtensionFailsClosed` | 2 | Implemented |
| AT-REV-006 | A current CRL blocks revocation at or before timestamp time and does not retroactively block a later revocation | `TestOfflineCRLStatusesAndCutoff` | 2 | Implemented |
| AT-REV-007 | No implicit OCSP or network request occurs | X.509 verifier and CRL loader contain no network path; Linux suite runs offline verification | 2 | Implemented |
| AT-REV-008 | Reputation or publisher exception cannot override revocation | Decision-precedence unit and lifecycle test | 4-5 | Planned |

## 7. Root bundle and local-root administration

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-ROOT-001 | Embedded root manifest is ABI 1, strictly decoded, and fingerprint-verified | `TestEmbeddedRootBundleIsStrictAndFingerprintVerified` and `FuzzRootBundleParser` | 2 | Implemented |
| AT-ROOT-002 | Every source URL, retrieval time, source hash, licence, and attribution is present | `TestEmbeddedSectigoRootsCarryReviewedProvenance` | 2 | Implemented |
| AT-ROOT-003 | Duplicate, non-root, non-self-signed, and fingerprint-mismatched entries fail generation | `TestRootBundleFailsClosed` | 2 | Implemented |
| AT-ROOT-004 | Code-signing and timestamp purposes load into separate pools | `TestLocalRootImportRequiresThePreviewedFingerprintAndKeepsPurposesSeparate` | 2 | Implemented |
| AT-ROOT-005 | Sectigo example root fingerprint matches reviewed CCADB and Sectigo sources | `TestEmbeddedSectigoRootsCarryReviewedProvenance` plus Phase 2 source review | 2 | Implemented |
| AT-ROOT-006 | Administrator sees subject and exact SHA-256 before confirmation | `TestTrustRootPreviewShowsTheExactIdentityBeforeMutation` | 2 | Implemented |
| AT-ROOT-007 | Non-root caller cannot add or remove a root | `TestTrustRootMutationEscalationBindsThePreviewedFingerprint` on native Linux proves mutation is handed to the existing administrator re-entry; live escalation frontends remain lifecycle scope | 2, 5 | Implemented (Phase 2 command boundary) |
| AT-ROOT-008 | Symlink, traversal, unsafe parent, unsafe ownership, and writable file are rejected | `TestLocalRootStoreRejectsFilesystemConfusion`, `TestLocalRootDirectoryCannotEscapeItsBoundary`, and writable root/CRL cases | 2 | Implemented |
| AT-ROOT-009 | Root update is atomic across interruption | `TestRootImportHasAnAtomicCommitPointAcrossFailures` | 2 | Implemented |
| AT-ROOT-010 | Duplicate import, removal, and re-addition have deterministic outcomes | `TestTrustRootCommandImportRemoveAndReaddLifecycle` | 2 | Implemented |
| AT-ROOT-011 | Corrupt embedded bundle or future schema fails as cpak error, not untrusted package | `TestRootBundleFailsClosed` | 2 | Implemented |
| AT-ROOT-012 | Public and local roots remain distinguishable in explanation output | `TestPublicAndImportedLocalRootsProduceDistinctTrustResults` and reporting paths | 2, 5 | Implemented (Phase 2 result scope) |

## 8. POC CA and signing workflow

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-CA-001 | Offline root signs only dedicated intermediates | `TestGeneratedProfilesSeparateRootIntermediatePublisherAndTSA`, public sample inspection, and CP/CPS | 3 | Implemented |
| AT-CA-002 | Code-signing intermediate is `CA=true`, `pathLen=0`, and policy constrained | `TestGeneratedProfilesSeparateRootIntermediatePublisherAndTSA` | 3 | Implemented |
| AT-CA-003 | Leaf is `CA=false`, digital signature, Code Signing EKU, bounded subject | `TestGeneratedProfilesSeparateRootIntermediatePublisherAndTSA` and publisher-name rejection paths | 3 | Implemented |
| AT-CA-004 | TSA certificate and chain have only the timestamping purpose | `TestGeneratedProfilesSeparateRootIntermediatePublisherAndTSA` | 3 | Implemented |
| AT-CA-005 | No reusable private key or passphrase is tracked | Phase 3 tracked-file inventory and secret-pattern scan; generator emits keys only into a new caller-selected directory | 3, 6 | Implemented for Phase 3; repeat at publication |
| AT-CA-006 | Signing accepts an encrypted software key through a safe runtime path | `TestX509SignAcceptsEncryptedSoftwareKeyAndProducesDetachedEvidence` and unsafe-mode/wrong-passphrase negatives | 3 | Implemented |
| AT-CA-007 | Signing boundary accepts `crypto.Signer` without evidence-format changes | `TestSignX509CMSUsesCryptoSignerAndProducesVerifierEvidence` | 3 | Implemented |
| AT-CA-008 | Clean Linux environment can generate, sign, attach, import, verify, and enrol | Linux portability suite exercises generator, signer, fake OCI attach, local-root lifecycle, verification, and authority enrolment; `application-trust-poc-demo.md` composes the same commands | 3, 5 | Implemented for Phase 3 POC; real install/update matrix remains Phase 5 |
| AT-CA-009 | Same artifact is untrusted before explicit POC-root import | `TestAttachPublishesX509CMSOnlyAfterPublicationTimeTrust`, unknown-root verifier cases, and explicit root-store lifecycle tests | 3 | Implemented |
| AT-CA-010 | Root removal causes full re-verification failure without ledger corruption | `TestRemovingX509TrustBreaksFullReverificationWithoutChangingTheLedger` | 3 | Implemented |
| AT-CA-011 | CLI labels POC assurance experimental | `TestX509SigningReportDoesNotImplyPublicTrustOrReputation` and runbook wording | 3, 5 | Implemented for Phase 3 CLI |

## 9. Reputation snapshot and provider

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-REP-001 | Valid fresh configured snapshot is accepted | `TestValidFreshSnapshotVerifiesAndLooksUpEveryStatus` and `TestReputationStoreImportsAndServesOnlyAuthenticatedSnapshots` | 4 | Implemented |
| AT-REP-002 | Tampered or wrongly signed snapshot is rejected | `TestSnapshotSignatureBindsCanonicalSignedObject`, `TestSnapshotRejectsWrongAuthorityAndKey`, and `TestInvalidSnapshotNeverReplacesTheActiveRecord` | 4 | Implemented |
| AT-REP-003 | Unsupported ABI, unknown fields, duplicate keys, duplicate publisher IDs, and oversize fail closed | `TestSnapshotRejectsUnsupportedAmbiguousAndUnsafeContent`, `FuzzSnapshotParsers`, and `FuzzAuthorityParser` | 4 | Implemented |
| AT-REP-004 | Expired and future-issued snapshot are unavailable | `TestSnapshotFreshnessBoundariesAreUnavailableNotUnknown` | 4 | Implemented |
| AT-REP-005 | Equal or lower sequence is rejected as rollback | `TestReputationStoreRejectsRollbackEvenAfterActiveSnapshotExpires` | 4 | Implemented |
| AT-REP-006 | Wrong provider or key ID is rejected | `TestSnapshotRejectsWrongAuthorityAndKey` and `TestReputationStoreRequiresThePreviewedProviderKey` | 4 | Implemented |
| AT-REP-007 | The single active snapshot record, including its sequence, is durably replaced atomically | `TestInterruptedSnapshotReplacementLeavesThePriorRecord` plus file and directory `fsync` in `ReputationStore.Import` | 4 | Implemented |
| AT-REP-008 | Absent publisher is `unknown`; absent provider is `unavailable` | `TestValidFreshSnapshotVerifiesAndLooksUpEveryStatus` and `TestAbsentProviderAndSnapshotAreDifferentUnavailableResults` | 4 | Implemented |
| AT-REP-009 | All five reputation statuses are deterministic | Verifier/provider and frozen policy tables in `TestValidFreshSnapshotVerifiesAndLooksUpEveryStatus` and `TestReputationPolicyModesHaveFrozenConsequences` | 4 | Implemented |
| AT-REP-010 | Reason codes and display text are bounded and terminal-safe | Strict reason-code grammar in `TestSnapshotRejectsUnsupportedAmbiguousAndUnsafeContent`; snapshots carry no provider-controlled display prose | 4-5 | Implemented for Phase 4; complete output golden coverage remains Phase 5 |
| AT-REP-011 | Display-name changes cannot hijack reputation identity | `TestNormalizedPublisherSelectorDoesNotUseDisplayNamesOrPrefixes` and exact normalized-ID provider lookup | 4 | Implemented |
| AT-REP-012 | Provider performs no network or telemetry operation | `pkg/reputation` is a pure caller-supplied snapshot parser/provider with no filesystem or network dependency; Linux lifecycle runs without provider network configuration | 4 | Implemented by construction and integration audit |

## 10. Policy modes and precedence

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-POL-001 | `off` does not consult reputation | `TestReputationOffDoesNotConsultAProvider` | 4 | Implemented |
| AT-POL-002 | `audit` records every result without changing prior allow/deny | `TestReputationPolicyModesHaveFrozenConsequences` and `TestAuthorityReputationModesControlEnrolmentAndRecordedEvidence` | 4 | Implemented |
| AT-POL-003 | `warn` warns on unknown, caution, and unavailable but denies blocked | `TestReputationPolicyModesHaveFrozenConsequences` and `TestWarnRequiresConfirmationWithoutAnInteractiveCaller` | 4 | Implemented |
| AT-POL-004 | `require-established` allows only established | `TestReputationPolicyModesHaveFrozenConsequences` and authority decision table | 4 | Implemented |
| AT-POL-005 | Exception applies only to its exact publisher, origin, status, and unexpired time and overrides only unknown or caution | `TestReputationExceptionIsExactScopedAndNeverOverridesBlocked` | 4 | Implemented |
| AT-POL-006 | Blocked reputation cannot be overridden | `TestReputationExceptionIsExactScopedAndNeverOverridesBlocked` | 4 | Implemented |
| AT-POL-007 | Invalid cryptography, untrusted chain, stale evidence, and revocation precede reputation | `TestAuthorityAppliesReputationOnlyAfterSignatureAndAdministratorPolicy` plus Phase 2 verifier precedence suites | 4-5 | Implemented for authority sequencing; full lifecycle table remains Phase 5 |
| AT-POL-008 | Origin, publisher, approval, and release revocation precede reputation | `TestAuthorityAppliesReputationOnlyAfterSignatureAndAdministratorPolicy` plus existing trust-policy decision suites | 4-5 | Implemented for authority sequencing; full lifecycle table remains Phase 5 |
| AT-POL-009 | Administrator remains the final authority | `TestAuthorityReputationModesControlEnrolmentAndRecordedEvidence` and privileged provider-store tests | 4-5 | Implemented for Phase 4 enrolment path |
| AT-POL-010 | ABI 1 policies retain exact existing semantics | Legacy fixture and existing trust-policy suite remain green; ABI 2 fields are rejected under ABI 1 | 1, 5 | Existing; regression-covered in Phase 4 |
| AT-POL-011 | ABI 2 is rejected by an ABI 1 decoder instead of partially applied | strict ABI dispatch and `TestPolicyV2ValidationRejectsAmbiguousOrUnsafeReputationRules` | 4 | Implemented in current decoder; cross-version binary fixture remains Phase 5 |

## 11. Lifecycle, explainability, and runtime

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-LIFE-001 | Fresh signed install succeeds for Sigstore and POC X.509 | Real OCI end-to-end matrix | 5 | Planned |
| AT-LIFE-002 | Signed update succeeds for the same publisher and next generation | Real OCI end-to-end matrix | 5 | Planned |
| AT-LIFE-003 | Replayed or downgraded generation fails | Existing ledger downgrade tests plus X.509 path | 1, 5 | Existing/Planned |
| AT-LIFE-004 | Publisher key change is visible and policy-controlled | Update integration test | 5 | Planned |
| AT-LIFE-005 | Signed-to-unsigned transition remains visible and follows policy | Existing enrolment tests plus common evidence path | 1, 5 | Existing/Planned |
| AT-LIFE-006 | Invalid attached evidence never falls back to unsigned | Existing tests plus both evidence kinds | 1-2, 5 | Implemented common fail-closed enrolment path; executed Linux fixtures for both evidence kinds remain Phase 5 |
| AT-LIFE-007 | Changed package with stale evidence is not enrolled under old state | Update integration test | 5 | Planned |
| AT-LIFE-008 | Reputation is evaluated at install/update, not every launch | Provider call-count lifecycle test | 5 | Implemented published-state refresh even when the image is unchanged; executed Linux lifecycle remains Phase 5 |
| AT-LIFE-009 | Launch after provider outage uses anchored runtime integrity without PKI/network work | Network-deny launch test | 5 | Runtime gate already consumes only anchor/store state; authority verification is now recorded for explain without PKI replay; executed network-deny lifecycle remains Phase 5 |
| AT-LIFE-010 | Trust-root or snapshot correction permits clean retry without corrupt state | Recovery scenarios | 5 | Exact-manifest retry now re-evaluates an installed but unenrolled package without rewriting store state; changed published state and already-enrolled no-op cases are rejected; executed Linux recovery remains Phase 5 |
| AT-LIFE-011 | CLI separates evidence, publisher, root source, reputation, policy, and final action | Structured and human-output golden tests | 5 | Implemented shared install/update/audit/explain human and versioned JSON projection; Linux golden tests remain Phase 5 |
| AT-LIFE-012 | CLI never describes signed or established software as safe | Forbidden-vocabulary assertion over all outputs | 5-6 | Planned |
| AT-LIFE-013 | Empty, long, malformed, stale, and unavailable data remain readable and safe | CLI matrix and terminal escape tests | 5 | Planned |
| AT-LIFE-014 | Existing unmanaged-host defaults remain backward compatible | Existing install/enrol/launch suite | 1-5 | Existing/Planned |

## 12. Invocation context and desktopless operation

| ID | Requirement | Evidence | Phase | State |
| --- | --- | --- | --- | --- |
| AT-HDL-001 | Graphical, interactive-terminal, and non-interactive callers consume the same versioned decision result | Shared decision-core table plus frontend adapter tests | 4-5 | Implemented shared core plus explicit install/update graphical adapter and install/update/audit/explain projections; real Linux frontend lifecycle remains Phase 5 |
| AT-HDL-002 | A binary-only package with no desktop entry uses the normal install, update, enrolment, audit, explain, and run paths | Real OCI lifecycle fixture with `binaries` and no `desktop_entries` | 5 | Planned |
| AT-HDL-003 | Missing display, session bus, portal, Secret Service, and graphical privilege agent cannot weaken policy or prevent safe headless operation | Environment-cleared Linux integration test | 5 | Graphical adapter failure is fail-closed and closed bootstrap stdin no longer defaults to consent; environment-cleared Linux execution remains Phase 5 |
| AT-HDL-004 | Non-interactive `warn` returns confirmation-required and does not block, launch a helper, or assume consent | Detached-stdio timeout test plus decision and exit-code assertions | 4-5 | Implemented decision core, authority challenge, explicit graphical selection, and CLI exit mapping; detached Linux lifecycle remains Phase 5 |
| AT-HDL-005 | `--yes` acknowledges an operation but cannot accept unknown/caution reputation or override invalid, revoked, or denied evidence | CLI negative table across every protected result | 4-5 | Implemented separate typed confirmation path; complete CLI negative lifecycle remains Phase 5 |
| AT-HDL-006 | Trust-root and reputation administration work through direct root, `sudo`, and `doas` without `pkexec` or `run0` | Linux privilege-frontend matrix with exact fingerprint assertions | 5 | Planned |
| AT-HDL-007 | Human output, machine output, audit record, reason code, final action, and exit code agree | Golden-output and structured-result consistency test | 5 | Install/update/audit/explain share one validated result and exit projection; Linux golden tests remain Phase 5 |
| AT-HDL-008 | Offline or unavailable reputation follows configured policy without desktop or launch-time network access | Network-deny lifecycle table for all policy modes | 4-5 | Planned |
| AT-HDL-009 | Service start/restart verifies enrolled state, while a later policy/reputation change does not claim to terminate an already running process | systemd-equivalent lifecycle fixture and documented non-goal assertion | 5 | Production prepare/reuse path already gates before mount; recorded trust snapshot avoids launch-time policy/reputation reevaluation; service lifecycle fixture remains Phase 5 |
| AT-HDL-010 | cpak and the AppImage actor emit conforming results for shared valid, unknown, invalid, and blocked headless fixtures | Cross-actor schema and reason-code conformance harness | 6 | Planned |

## 13. Phase and final verification commands

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
`application-trust-poc-plan.md`, including tagged UI tests, headless and no-TTY
tests, schema generation, Linux builds, fuzzing, real OCI referrers, offline
verification, cpak/AppImage conformance, dependency and license audit, secret
inspection, and the scoped security review.
