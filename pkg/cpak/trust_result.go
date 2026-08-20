/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package cpak

import (
	"errors"
	"time"

	"github.com/mirkobrombin/cpak/pkg/applicationtrust"
	"github.com/mirkobrombin/cpak/pkg/applicationtrust/cpakadapter"
	"github.com/mirkobrombin/cpak/pkg/systemauthority"
	"github.com/mirkobrombin/cpak/pkg/trustpolicy"
)

// ApplicationTrustResult projects the authoritative enrolment outcome onto
// the portable v1 contract. The authority remains the decision maker; this
// method only gives every cpak presentation surface one representation.
func (e ApplicationEnrolment) ApplicationTrustResult(operation applicationtrust.Operation, context applicationtrust.InvocationContext) (applicationtrust.Result, error) {
	return e.applicationTrustResultAt(operation, context, time.Now())
}

func (e ApplicationEnrolment) applicationTrustResultAt(operation applicationtrust.Operation, context applicationtrust.InvocationContext, now time.Time) (applicationtrust.Result, error) {
	result, err := e.signatureTrustResult(operation, context)
	if err != nil {
		return applicationtrust.Result{}, err
	}
	result.Policy.SignatureMode = string(e.SignatureMode)
	if result.Policy.SignatureMode == "" {
		result.Policy.SignatureMode = string(systemauthority.SignaturesOptional)
	}
	result.Policy.ReputationMode = string(e.ReputationMode)
	if result.Policy.ReputationMode == "" {
		result.Policy.ReputationMode = string(trustpolicy.ReputationOff)
	}
	result.Reputation = portableReputation(e, now)
	result.Policy.Exception = e.ReputationDecision != nil && e.ReputationDecision.Exception

	action, reason := enrolmentPolicyAction(e)
	result.Policy.Action = action
	result.Policy.ReasonCode = reason
	result.Policy.Confirmation = applicationtrust.ConfirmationNotRequired

	finalAction, finalReason := enrolmentPrerequisiteFailure(e)
	if finalAction != "" {
		result.Policy.Action = applicationtrust.PolicyNotEvaluated
		result.Policy.ReasonCode = finalReason
		result.Final, err = applicationtrust.NewFinal(finalAction, finalReason)
	} else if action == applicationtrust.PolicyWarn {
		response := applicationtrust.NoConfirmation
		switch e.Confirmation {
		case applicationtrust.ConfirmationAccepted:
			response = applicationtrust.Confirm
		case applicationtrust.ConfirmationDeclined:
			response = applicationtrust.Decline
		}
		result.Policy.Confirmation, result.Final, err = applicationtrust.ResolvePolicyAction(action, context, response, reason)
	} else {
		result.Policy.Confirmation, result.Final, err = applicationtrust.ResolvePolicyAction(action, context, applicationtrust.NoConfirmation, reason)
	}
	if err != nil {
		return applicationtrust.Result{}, err
	}
	if err := result.Validate(); err != nil {
		return applicationtrust.Result{}, err
	}
	return result, nil
}

func (e ApplicationEnrolment) signatureTrustResult(operation applicationtrust.Operation, context applicationtrust.InvocationContext) (applicationtrust.Result, error) {
	state := e.Signature.State
	if state.Origin == "" {
		state.Origin = e.Origin
		state.ImageDigest = e.Anchor.ImageDigest
		state.Generation = e.Anchor.Generation
	}
	if e.Signature.Verified || e.Signature.Verification.ReasonCode != "" {
		return cpakadapter.SignatureVerification(cpakadapter.SignatureVerificationInput{
			Actor: "cpak", Operation: operation, Context: context, State: state,
			Verification: e.Signature.Verification, RequireOrigin: true,
		})
	}

	verificationStatus := applicationtrust.VerificationUnavailable
	verificationReason := "verification-unavailable"
	publisherStatus := applicationtrust.PublisherUnavailable
	publisherReason := verificationReason
	evidenceKind := "unknown"
	chain, signingTime, revocation, trustReason := "not-evaluated", "not-evaluated", "not-evaluated", "not-evaluated"
	if e.Signature.Unsigned() {
		verificationStatus, verificationReason = applicationtrust.VerificationUnsigned, "package-unsigned"
		publisherStatus, publisherReason = applicationtrust.PublisherAbsent, "publisher-absent"
		evidenceKind = "none"
		chain, signingTime, revocation, trustReason = "not-applicable", "not-applicable", "not-applicable", "not-applicable"
	} else if errors.Is(e.Signature.Reason, ErrSignatureForeign) {
		verificationStatus, verificationReason = applicationtrust.VerificationNotEvaluated, "publisher-foreign"
		publisherStatus, publisherReason = applicationtrust.PublisherInvalid, "publisher-foreign"
	} else if errors.Is(e.Signature.Reason, ErrSignatureUnverified) || errors.Is(e.Signature.Reason, ErrSignatureUnnamed) {
		verificationStatus, verificationReason = applicationtrust.VerificationInvalid, "evidence-invalid"
		publisherStatus, publisherReason = applicationtrust.PublisherInvalid, "publisher-not-verified"
		chain, signingTime, revocation, trustReason = "invalid", "invalid", "not-evaluated", "evidence-invalid"
	}
	origin := applicationtrust.SanitizeText(e.Origin, 512)
	if origin == "" {
		origin = "invalid-origin"
	}
	digest := e.Anchor.ImageDigest
	if !applicationtrust.ValidArtifactDigest(digest) {
		digest = ""
	}
	final, _ := applicationtrust.NewFinal(applicationtrust.FinalUnavailable, verificationReason)
	return applicationtrust.Result{
		SchemaVersion: applicationtrust.SchemaVersion, Actor: "cpak", Operation: operation, Context: context,
		DecisionSource: applicationtrust.SourceEvaluated,
		Subject:        applicationtrust.Subject{Origin: origin, ArtifactDigest: digest, Generation: e.Anchor.Generation},
		Verification:   applicationtrust.Verification{Status: verificationStatus, EvidenceKind: evidenceKind, ReasonCode: verificationReason},
		Publisher:      applicationtrust.Publisher{Status: publisherStatus, OriginAuthorization: "not-evaluated", ReasonCode: publisherReason},
		Trust:          applicationtrust.Trust{Chain: chain, SigningTime: signingTime, Revocation: revocation, ReasonCode: trustReason},
		Reputation:     applicationtrust.Reputation{Status: "not-consulted", Freshness: "not-applicable", ReasonCode: "not-consulted"},
		Policy:         applicationtrust.Policy{SignatureMode: "optional", ReputationMode: "off", Action: applicationtrust.PolicyNotEvaluated, Confirmation: applicationtrust.ConfirmationNotRequired, ReasonCode: "not-evaluated"},
		Final:          final,
	}, nil
}

func portableReputation(e ApplicationEnrolment, now time.Time) applicationtrust.Reputation {
	if e.Reputation == nil {
		return applicationtrust.Reputation{Status: "not-consulted", Freshness: "not-applicable", ReasonCode: "not-consulted"}
	}
	result := e.Reputation
	freshness := "fresh"
	if result.Status == "unavailable" {
		freshness = "unavailable"
	} else if now.Before(result.IssuedAt) || !now.Before(result.ExpiresAt) {
		freshness = "stale"
	}
	return applicationtrust.Reputation{
		ProviderID: result.ProviderID, Status: string(result.Status), Freshness: freshness,
		IssuedAt: canonicalTrustTime(result.IssuedAt), ExpiresAt: canonicalTrustTime(result.ExpiresAt),
		ReasonCode: stableTrustReason(result.ReasonCode, "reputation-unavailable"),
	}
}

func enrolmentPolicyAction(e ApplicationEnrolment) (applicationtrust.PolicyAction, string) {
	if e.Outcome == EnrolmentDeclined {
		return applicationtrust.PolicyWarn, "reputation-warning"
	}
	if e.Outcome == EnrolmentConfirmationRequired {
		return applicationtrust.PolicyWarn, "reputation-warning"
	}
	if e.ReputationDecision != nil {
		reason := stableTrustReason(e.ReputationDecision.ReasonCode, "reputation-policy")
		switch e.ReputationDecision.Action {
		case trustpolicy.ActionAllow:
			return applicationtrust.PolicyAllow, reason
		case trustpolicy.ActionWarn, trustpolicy.ActionConfirmationRequired:
			return applicationtrust.PolicyWarn, reason
		case trustpolicy.ActionDeny:
			return applicationtrust.PolicyDeny, reason
		}
	}
	if e.Outcome == EnrolmentUnsigned || errors.Is(e.Reason, systemauthority.ErrTrustRefused) || errors.Is(e.Signature.Reason, ErrSignatureForeign) {
		return applicationtrust.PolicyDeny, "trust-policy-denied"
	}
	return applicationtrust.PolicyAllow, "trust-policy-allowed"
}

func enrolmentPrerequisiteFailure(e ApplicationEnrolment) (applicationtrust.FinalAction, string) {
	if errors.Is(e.Signature.Reason, ErrSignatureUnverified) || errors.Is(e.Signature.Reason, ErrSignatureUnnamed) {
		return applicationtrust.FinalInvalid, "evidence-invalid"
	}
	if e.Outcome == EnrolmentUndescribed {
		return applicationtrust.FinalInvalid, "subject-invalid"
	}
	if e.Outcome == EnrolmentUnrecordable && !errors.Is(e.Reason, systemauthority.ErrTrustRefused) {
		return applicationtrust.FinalUnavailable, "authority-unavailable"
	}
	return "", ""
}

func canonicalTrustTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func stableTrustReason(value, fallback string) string {
	if applicationtrust.ValidReasonCode(value) {
		return value
	}
	return fallback
}
