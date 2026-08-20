/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package cpakadapter

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mirkobrombin/cpak/pkg/applicationtrust"
	"github.com/mirkobrombin/cpak/pkg/signature"
)

func TestSignatureVerificationSeparatesEveryDecisionStage(t *testing.T) {
	input := validSignatureInput()
	result, err := SignatureVerification(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verification.Status != applicationtrust.VerificationVerified || result.Verification.ReasonCode != "evidence-verified" {
		t.Fatalf("verification = %+v", result.Verification)
	}
	if result.Publisher.Status != applicationtrust.PublisherVerified || result.Publisher.ID != input.Verification.Publisher.ID || result.Publisher.OriginAuthorization != "authorized" {
		t.Fatalf("publisher = %+v", result.Publisher)
	}
	if result.Trust.Chain != signature.ChainTrustedLocal || result.Trust.RootSource != "local:test-root" || result.Trust.SigningTime != signature.SigningTimeTimestamped || result.Trust.Revocation != signature.RevocationGood {
		t.Fatalf("trust = %+v", result.Trust)
	}
	if result.Reputation.Status != "not-consulted" || result.Policy.Action != applicationtrust.PolicyNotEvaluated {
		t.Fatalf("later stages were invented: reputation=%+v policy=%+v", result.Reputation, result.Policy)
	}
	if result.Final.Action != applicationtrust.FinalAllow || result.Final.ExitCode != applicationtrust.ExitAllowed {
		t.Fatalf("final = %+v", result.Final)
	}
}

func TestSignatureVerificationClassifiesFailuresWithoutFallback(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SignatureVerificationInput)
		action applicationtrust.FinalAction
		code   int
	}{
		{"foreign publisher", func(input *SignatureVerificationInput) {
			input.Verification.OriginAuthorization = string(signature.OriginForeign)
			input.Verification.ReasonCode = "source-repository-does-not-match-origin"
		}, applicationtrust.FinalDeny, applicationtrust.ExitDenied},
		{"unsupported origin", func(input *SignatureVerificationInput) {
			input.Verification.OriginAuthorization = string(signature.OriginUnsupported)
			input.Verification.ReasonCode = "invalid-package-origin"
		}, applicationtrust.FinalInvalid, applicationtrust.ExitInvalid},
		{"revoked certificate", func(input *SignatureVerificationInput) {
			input.Verification.Cryptographic = signature.CryptographicInvalid
			input.Verification.Revocation = signature.RevocationRevoked
			input.Verification.Publisher = nil
			input.Verification.ReasonCode = "certificate-revoked"
		}, applicationtrust.FinalDeny, applicationtrust.ExitDenied},
		{"stale revocation", func(input *SignatureVerificationInput) {
			input.Verification.Cryptographic = signature.CryptographicInvalid
			input.Verification.Revocation = signature.RevocationStale
			input.Verification.Publisher = nil
			input.Verification.ReasonCode = "stale-revocation-evidence"
		}, applicationtrust.FinalDeny, applicationtrust.ExitDenied},
		{"invalid cryptography", func(input *SignatureVerificationInput) {
			input.Verification.Cryptographic = signature.CryptographicInvalid
			input.Verification.Publisher = nil
			input.Verification.ReasonCode = "invalid-cms"
		}, applicationtrust.FinalInvalid, applicationtrust.ExitInvalid},
		{"missing publisher", func(input *SignatureVerificationInput) {
			input.Verification.Publisher = nil
		}, applicationtrust.FinalInvalid, applicationtrust.ExitInvalid},
		{"operational failure", func(input *SignatureVerificationInput) {
			input.OperationalErr = errors.New("trust store unavailable")
		}, applicationtrust.FinalUnavailable, applicationtrust.ExitUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validSignatureInput()
			test.mutate(&input)
			result, err := SignatureVerification(input)
			if err != nil {
				t.Fatal(err)
			}
			if result.Final.Action != test.action || result.Final.ExitCode != test.code {
				t.Fatalf("final = %+v", result.Final)
			}
		})
	}
}

func TestIdentityOnlyVerificationDoesNotAuthorizeTheForeignOrigin(t *testing.T) {
	input := validSignatureInput()
	input.RequireOrigin = false
	input.Verification.OriginAuthorization = string(signature.OriginForeign)
	input.Verification.ReasonCode = "source-repository-does-not-match-origin"
	result, err := SignatureVerification(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Final.Action != applicationtrust.FinalAllow || result.Publisher.OriginAuthorization != "foreign" {
		t.Fatalf("identity-only result hid the foreign origin: %+v", result)
	}
}

func TestSignatureVerificationBoundsExternalDiagnostics(t *testing.T) {
	input := validSignatureInput()
	secret := "credential=do-not-report"
	input.OperationalErr = errors.New("failure\x1b[2J" + strings.Repeat("é", 400) + secret)
	input.State.Origin = "registry.example/org/app\x1b[2J"
	result, err := SignatureVerification(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(result.Verification.Diagnostic, '\x1b') || len(result.Verification.Diagnostic) > 512 || !utf8.ValidString(result.Verification.Diagnostic) {
		t.Fatalf("unsafe diagnostic = %q", result.Verification.Diagnostic)
	}
	if strings.Contains(result.Verification.Diagnostic, secret) {
		t.Fatalf("operational error leaked into the portable result: %q", result.Verification.Diagnostic)
	}
	if strings.ContainsRune(result.Subject.Origin, '\x1b') || result.Subject.Origin == input.State.Origin {
		t.Fatalf("unsafe subject origin = %q", result.Subject.Origin)
	}
}

func validSignatureInput() SignatureVerificationInput {
	publisher := &signature.PublisherIdentity{
		Kind:        "x509-spki-v1",
		ID:          "x509-spki-v1:sha256:0123456789abcdef",
		DisplayName: "Example Publisher",
		Assurance:   "certificate-chain",
	}
	return SignatureVerificationInput{
		Actor:     "cpak",
		Operation: applicationtrust.OperationVerify,
		Context:   applicationtrust.ContextNonInteractive,
		State: signature.State{
			ABI:            signature.ABIVersion,
			Origin:         "registry.example/org/application",
			ManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ImageDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Generation:     4,
		},
		Verification: signature.VerificationResult{
			EvidenceKind:        signature.EvidenceX509CMS,
			Cryptographic:       signature.CryptographicVerified,
			Chain:               signature.ChainTrustedLocal,
			SigningTime:         signature.SigningTimeTimestamped,
			Revocation:          signature.RevocationGood,
			Publisher:           publisher,
			RootSource:          "local:test-root",
			OriginAuthorization: string(signature.OriginAuthorized),
			ReasonCode:          "x509-signer-covers-origin",
			Diagnostic:          "the X.509 publisher signed the exact canonical state containing this origin",
		},
		RequireOrigin: true,
	}
}
