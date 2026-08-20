/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package cpak

import (
	"errors"
	"testing"
	"time"

	"github.com/mirkobrombin/cpak/pkg/applicationtrust"
	"github.com/mirkobrombin/cpak/pkg/integrity"
	"github.com/mirkobrombin/cpak/pkg/reputation"
	"github.com/mirkobrombin/cpak/pkg/signature"
	"github.com/mirkobrombin/cpak/pkg/systemauthority"
	"github.com/mirkobrombin/cpak/pkg/trustpolicy"
)

func TestApplicationTrustResultMapsEveryStableExitClass(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	base := ApplicationEnrolment{
		Origin:         testOrigin,
		Anchor:         integrity.Anchor{Origin: testOrigin, Generation: 4, ImageDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Signature:      EnrolmentSignature{Reason: ErrPackageUnsigned},
		SignatureMode:  systemauthority.SignaturesOptional,
		ReputationMode: trustpolicy.ReputationOff,
	}
	warning := func(outcome EnrolmentOutcome, confirmation applicationtrust.ConfirmationState) ApplicationEnrolment {
		value := base
		value.Outcome = outcome
		value.Signature = EnrolmentSignature{
			Verified: true,
			State: signature.State{
				ABI: signature.ABIVersion, Origin: testOrigin,
				ManifestSHA256: "2222222222222222222222222222222222222222222222222222222222222222",
				ImageDigest:    base.Anchor.ImageDigest, Generation: 4,
			},
			Verification: verifiedTrustResult(t),
		}
		value.ReputationMode = trustpolicy.ReputationWarn
		value.Reputation = &reputation.Result{
			ProviderID: "cpak-poc", PublisherID: "oidc:example", Status: reputation.Caution,
			IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Sequence: 2, ReasonCode: "new-publisher",
		}
		value.ReputationDecision = &trustpolicy.ReputationDecision{
			Allowed: true, Action: trustpolicy.ActionWarn, ReasonCode: "new-publisher", Reason: "publisher reputation requires a warning before continuing",
		}
		value.Confirmation = confirmation
		return value
	}

	tests := []struct {
		name      string
		enrolment ApplicationEnrolment
		context   applicationtrust.InvocationContext
		action    applicationtrust.FinalAction
		exit      int
		confirm   applicationtrust.ConfirmationState
	}{
		{"unsigned optional", withOutcome(base, EnrolmentRecorded), applicationtrust.ContextNonInteractive, applicationtrust.FinalAllow, 0, applicationtrust.ConfirmationNotRequired},
		{"unsigned required", withModes(withOutcome(base, EnrolmentUnsigned), systemauthority.SignaturesRequired, trustpolicy.ReputationOff), applicationtrust.ContextNonInteractive, applicationtrust.FinalDeny, 20, applicationtrust.ConfirmationNotRequired},
		{"warning without tty", warning(EnrolmentConfirmationRequired, applicationtrust.ConfirmationRequired), applicationtrust.ContextNonInteractive, applicationtrust.FinalConfirmationRequired, 23, applicationtrust.ConfirmationNotAvailable},
		{"warning accepted", warning(EnrolmentRecorded, applicationtrust.ConfirmationAccepted), applicationtrust.ContextInteractiveTerminal, applicationtrust.FinalWarn, 0, applicationtrust.ConfirmationAccepted},
		{"warning declined", warning(EnrolmentDeclined, applicationtrust.ConfirmationDeclined), applicationtrust.ContextInteractiveTerminal, applicationtrust.FinalDeny, 20, applicationtrust.ConfirmationDeclined},
		{"invalid evidence", withSignatureFailure(withOutcome(base, EnrolmentRecorded), ErrSignatureUnverified), applicationtrust.ContextNonInteractive, applicationtrust.FinalInvalid, 21, applicationtrust.ConfirmationNotRequired},
		{"authority unavailable", withReason(withOutcome(base, EnrolmentUnrecordable), errors.New("authority offline")), applicationtrust.ContextNonInteractive, applicationtrust.FinalUnavailable, 22, applicationtrust.ConfirmationNotRequired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.enrolment.applicationTrustResultAt(applicationtrust.OperationInstall, test.context, now)
			if err != nil {
				t.Fatal(err)
			}
			if result.Final.Action != test.action || result.Final.ExitCode != test.exit || result.Policy.Confirmation != test.confirm {
				t.Fatalf("final=%+v policy=%+v", result.Final, result.Policy)
			}
		})
	}

	recorded, err := warning(EnrolmentRecorded, applicationtrust.ConfirmationAccepted).applicationTrustResultAtSource(
		applicationtrust.OperationExplain, applicationtrust.ContextNonInteractive, applicationtrust.SourceRecorded, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.DecisionSource != applicationtrust.SourceRecorded || recorded.Final.Action != applicationtrust.FinalWarn ||
		recorded.Policy.Confirmation != applicationtrust.ConfirmationAccepted {
		t.Fatalf("recorded warning=%+v", recorded)
	}
}

func withOutcome(value ApplicationEnrolment, outcome EnrolmentOutcome) ApplicationEnrolment {
	value.Outcome = outcome
	return value
}

func withModes(value ApplicationEnrolment, signatures systemauthority.SignaturePolicy, reputationMode trustpolicy.ReputationMode) ApplicationEnrolment {
	value.SignatureMode = signatures
	value.ReputationMode = reputationMode
	return value
}

func withReason(value ApplicationEnrolment, reason error) ApplicationEnrolment {
	value.Reason = reason
	return value
}

func withSignatureFailure(value ApplicationEnrolment, reason error) ApplicationEnrolment {
	value.Signature = EnrolmentSignature{Reason: reason}
	return value
}

func verifiedTrustResult(t *testing.T) signature.VerificationResult {
	t.Helper()
	publisher, reason := signature.NormalizeOIDCIdentity(publisherIdentity(testOrigin))
	if publisher == nil {
		t.Fatal(reason.ReasonCode)
	}
	return signature.VerificationResult{
		EvidenceKind: signature.EvidenceSigstoreBundle, Cryptographic: signature.CryptographicVerified,
		Chain: signature.ChainNotApplicable, SigningTime: signature.SigningTimeCurrent,
		Publisher: publisher, OriginAuthorization: string(signature.OriginAuthorized), ReasonCode: "oidc-repository-matches-origin",
	}
}
