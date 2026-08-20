/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

// Package cpakadapter maps cpak verification facts onto the portable
// application-trust contract. Policy and presentation do not feed facts back
// into this adapter.
package cpakadapter

import (
	"errors"

	"github.com/mirkobrombin/cpak/pkg/applicationtrust"
	"github.com/mirkobrombin/cpak/pkg/signature"
)

type SignatureVerificationInput struct {
	Actor          string
	Operation      applicationtrust.Operation
	Context        applicationtrust.InvocationContext
	State          signature.State
	Verification   signature.VerificationResult
	OperationalErr error
	RequireOrigin  bool
}

// SignatureVerification produces the complete portable result for a direct
// evidence verification. It accepts a VerificationResult even on failure so
// that cryptographic, chain, time, and revocation failures stay distinct from
// operational unavailability.
func SignatureVerification(input SignatureVerificationInput) (applicationtrust.Result, error) {
	origin := applicationtrust.SanitizeText(input.State.Origin, 512)
	if origin == "" {
		origin = "invalid-origin"
	}
	artifactDigest := input.State.ImageDigest
	if !applicationtrust.ValidArtifactDigest(artifactDigest) {
		artifactDigest = ""
	}

	verification, publisher, trust := verificationStages(input.Verification, input.OperationalErr)
	policy := applicationtrust.Policy{
		SignatureMode:  "not-applicable",
		ReputationMode: "not-applicable",
		Action:         applicationtrust.PolicyNotEvaluated,
		Confirmation:   applicationtrust.ConfirmationNotRequired,
		ReasonCode:     "not-evaluated",
	}
	final := verificationFinal(input.Verification, input.OperationalErr, input.RequireOrigin)
	if final.Action == applicationtrust.FinalDeny {
		policy.Action = applicationtrust.PolicyDeny
		policy.ReasonCode = final.ReasonCode
	}

	result := applicationtrust.Result{
		SchemaVersion:  applicationtrust.SchemaVersion,
		Actor:          input.Actor,
		Operation:      input.Operation,
		Context:        input.Context,
		DecisionSource: applicationtrust.SourceEvaluated,
		Subject: applicationtrust.Subject{
			Origin:         origin,
			ArtifactDigest: artifactDigest,
			Generation:     input.State.Generation,
		},
		Verification: verification,
		Publisher:    publisher,
		Trust:        trust,
		Reputation: applicationtrust.Reputation{
			Status:     "not-consulted",
			Freshness:  "not-applicable",
			ReasonCode: "not-consulted",
		},
		Policy: policy,
		Final:  final,
	}
	if err := result.Validate(); err != nil {
		return applicationtrust.Result{}, err
	}
	return result, nil
}

func verificationStages(result signature.VerificationResult, operationalErr error) (applicationtrust.Verification, applicationtrust.Publisher, applicationtrust.Trust) {
	reason := stableReason(result.ReasonCode, "verification-failed")
	evidenceKind := string(result.EvidenceKind)
	if evidenceKind != string(signature.EvidenceSigstoreBundle) && evidenceKind != string(signature.EvidenceX509CMS) {
		evidenceKind = "unknown"
	}
	verification := applicationtrust.Verification{
		Status:       applicationtrust.VerificationInvalid,
		EvidenceKind: evidenceKind,
		ReasonCode:   reason,
		Diagnostic:   applicationtrust.SanitizeText(result.Diagnostic, 512),
	}
	publisher := applicationtrust.Publisher{
		Status:              applicationtrust.PublisherInvalid,
		OriginAuthorization: "not-evaluated",
		ReasonCode:          "publisher-not-verified",
	}
	trust := applicationtrust.Trust{
		Chain:       trustChain(result.Chain),
		RootSource:  applicationtrust.SanitizeText(result.RootSource, 512),
		SigningTime: trustSigningTime(result.SigningTime),
		Revocation:  trustRevocation(result.Revocation),
		ReasonCode:  trustReason(result),
	}

	if operationalErr != nil {
		verification.Status = applicationtrust.VerificationUnavailable
		verification.ReasonCode = "verification-unavailable"
		verification.Diagnostic = "required verification input is unavailable"
		publisher.Status = applicationtrust.PublisherUnavailable
		publisher.ReasonCode = "verification-unavailable"
		trust.Chain = "not-evaluated"
		trust.SigningTime = "not-evaluated"
		trust.Revocation = "not-evaluated"
		trust.ReasonCode = "not-evaluated"
		trust.RootSource = ""
		return verification, publisher, trust
	}

	if signatureStands(result) && applicationtrust.SanitizeText(result.Publisher.ID, 512) != "" {
		verification.Status = applicationtrust.VerificationVerified
		verification.ReasonCode = "evidence-verified"
		if result.Publisher != nil {
			publisher.Status = applicationtrust.PublisherVerified
			publisher.ID = applicationtrust.SanitizeText(result.Publisher.ID, 512)
			publisher.DisplayName = applicationtrust.SanitizeText(result.Publisher.DisplayName, 200)
			publisher.OriginAuthorization = originAuthorization(result.OriginAuthorization)
			publisher.ReasonCode = "publisher-verified"
		}
	}
	return verification, publisher, trust
}

func verificationFinal(result signature.VerificationResult, operationalErr error, requireOrigin bool) applicationtrust.Final {
	if operationalErr != nil {
		return mustFinal(applicationtrust.FinalUnavailable, "verification-unavailable")
	}
	reason := stableReason(result.ReasonCode, "verification-failed")
	if result.Revocation == signature.RevocationRevoked || result.Revocation == signature.RevocationStale {
		return mustFinal(applicationtrust.FinalDeny, reason)
	}
	if result.Cryptographic != signature.CryptographicVerified || result.Chain == signature.ChainUntrusted || result.Chain == signature.ChainInvalid {
		return mustFinal(applicationtrust.FinalInvalid, reason)
	}
	if result.SigningTime == signature.SigningTimeMissing || result.SigningTime == signature.SigningTimeExpired ||
		result.SigningTime == signature.SigningTimeNotYetValid || result.SigningTime == signature.SigningTimeInvalid {
		return mustFinal(applicationtrust.FinalDeny, reason)
	}
	if result.Publisher == nil || applicationtrust.SanitizeText(result.Publisher.ID, 512) == "" {
		return mustFinal(applicationtrust.FinalInvalid, "publisher-not-verified")
	}
	if requireOrigin {
		switch result.OriginAuthorization {
		case string(signature.OriginAuthorized):
		case string(signature.OriginForeign):
			return mustFinal(applicationtrust.FinalDeny, reason)
		default:
			return mustFinal(applicationtrust.FinalInvalid, reason)
		}
	}
	return mustFinal(applicationtrust.FinalAllow, reason)
}

func signatureStands(result signature.VerificationResult) bool {
	if result.Cryptographic != signature.CryptographicVerified || result.Publisher == nil || result.Publisher.ID == "" {
		return false
	}
	if result.Chain == signature.ChainUntrusted || result.Chain == signature.ChainInvalid {
		return false
	}
	if result.SigningTime == signature.SigningTimeMissing || result.SigningTime == signature.SigningTimeExpired ||
		result.SigningTime == signature.SigningTimeNotYetValid || result.SigningTime == signature.SigningTimeInvalid {
		return false
	}
	return result.Revocation != signature.RevocationRevoked && result.Revocation != signature.RevocationStale
}

func originAuthorization(value string) string {
	switch value {
	case string(signature.OriginAuthorized):
		return "authorized"
	case string(signature.OriginForeign):
		return "foreign"
	case string(signature.OriginUnsupported):
		return "unsupported"
	default:
		return "not-evaluated"
	}
}

func trustChain(value string) string {
	if value == "" {
		return "not-evaluated"
	}
	if value == signature.ChainTrustedPublic || value == signature.ChainTrustedLocal || value == signature.ChainNotApplicable ||
		value == signature.ChainUntrusted || value == signature.ChainInvalid {
		return value
	}
	return "invalid"
}

func trustSigningTime(value string) string {
	if value == "" {
		return "not-evaluated"
	}
	if value == signature.SigningTimeCurrent || value == signature.SigningTimeTimestamped || value == signature.SigningTimeMissing ||
		value == signature.SigningTimeExpired || value == signature.SigningTimeNotYetValid || value == signature.SigningTimeInvalid {
		return value
	}
	return "invalid"
}

func trustRevocation(value string) string {
	if value == "" {
		return "not-evaluated"
	}
	if value == signature.RevocationGood || value == signature.RevocationRevoked || value == signature.RevocationUnknown || value == signature.RevocationStale {
		return value
	}
	return "not-evaluated"
}

func trustReason(result signature.VerificationResult) string {
	if result.Chain == signature.ChainTrustedPublic || result.Chain == signature.ChainTrustedLocal {
		if result.Revocation == signature.RevocationRevoked || result.Revocation == signature.RevocationStale {
			return stableReason(result.ReasonCode, "revocation-blocked")
		}
		return "chain-trusted"
	}
	if result.Chain == signature.ChainNotApplicable {
		return "not-applicable"
	}
	if result.Chain == "" {
		return "not-evaluated"
	}
	return stableReason(result.ReasonCode, "chain-invalid")
}

func stableReason(value, fallback string) string {
	if applicationtrust.ValidReasonCode(value) {
		return value
	}
	if !applicationtrust.ValidReasonCode(fallback) {
		panic(errors.New("cpak adapter has an invalid fallback reason code"))
	}
	return fallback
}

func mustFinal(action applicationtrust.FinalAction, reason string) applicationtrust.Final {
	final, err := applicationtrust.NewFinal(action, reason)
	if err != nil {
		panic(err)
	}
	return final
}
