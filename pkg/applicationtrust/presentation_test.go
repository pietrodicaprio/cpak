/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package applicationtrust

import (
	"strings"
	"testing"
)

func TestHumanLinesExposeEveryDecisionLayerWithoutPositiveSafetyClaims(t *testing.T) {
	result := validResult(t)
	result.Publisher.DisplayName = "Demo Publisher"
	result.Publisher.ID = "oidc:https://issuer.example:subject"
	result.Trust.RootSource = "public:fulcio"
	result.Reputation.ProviderID = "cpak-poc"
	output := strings.Join(HumanLines(result), "\n")
	for _, expected := range []string{
		result.Subject.Origin, "Demo Publisher", result.Publisher.ID, result.Verification.ReasonCode,
		"public:fulcio", "cpak-poc", result.Reputation.ReasonCode, result.Policy.ReasonCode,
		string(result.Final.Action), result.Final.ReasonCode,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("human decision omitted %q: %q", expected, output)
		}
	}
	lower := strings.ToLower(output)
	for _, forbidden := range []string{"software is safe", "application is safe", "trusted application", "trusted publisher"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("human decision makes a positive safety claim %q: %q", forbidden, output)
		}
	}
}

func TestHumanLinesBoundAndRemoveControlsFromPresentationFields(t *testing.T) {
	result := validResult(t)
	tainted := strings.Repeat("publisher", 100) + "\x00\x1b[2J"
	result.Subject.Origin = tainted
	result.Publisher.DisplayName = tainted
	result.Publisher.ID = tainted
	result.Publisher.ReasonCode = tainted
	result.Publisher.OriginAuthorization = tainted
	result.Verification.Status = VerificationStatus(tainted)
	result.Verification.EvidenceKind = tainted
	result.Verification.ReasonCode = tainted
	result.Trust.Chain = tainted
	result.Trust.RootSource = tainted
	result.Trust.SigningTime = tainted
	result.Trust.Revocation = tainted
	result.Trust.ReasonCode = tainted
	result.Reputation.ProviderID = tainted
	result.Reputation.Status = tainted
	result.Reputation.Freshness = tainted
	result.Reputation.ReasonCode = tainted
	result.Policy.SignatureMode = tainted
	result.Policy.ReputationMode = tainted
	result.Policy.Action = PolicyAction(tainted)
	result.Policy.Confirmation = ConfirmationState(tainted)
	result.Policy.ReasonCode = tainted
	result.Final.Action = FinalAction(tainted)
	result.Final.ReasonCode = tainted
	output := strings.Join(HumanLines(result), "\n")
	if strings.ContainsAny(output, "\x00\x1b") {
		t.Fatalf("human decision contains terminal controls: %q", output)
	}
	for _, line := range strings.Split(output, "\n") {
		if len([]byte(line)) > 900 {
			t.Fatalf("human decision line is unbounded: %d bytes", len([]byte(line)))
		}
	}
}

func TestHumanLinesHaveAStableCompleteProjection(t *testing.T) {
	result := validResult(t)
	want := strings.Join([]string{
		"Application trust for registry.example/org/application: warn (publisher-unknown).",
		"  Publisher: Example Publisher; identity: x509-spki-v1:sha256:0123456789abcdef (publisher-verified); origin: authorized.",
		"  Evidence: verified/x509-cms-v1 (verified).",
		"  Trust: chain trusted-local, root local:sha256:0123456789abcdef, signing time timestamped, revocation good (chain-trusted).",
		"  Reputation: provider poc-provider, status unknown, freshness fresh (publisher-not-listed).",
		"  Policy: signatures required, reputation warn, action warn, confirmation accepted (publisher-unknown).",
	}, "\n")
	if got := strings.Join(HumanLines(result), "\n"); got != want {
		t.Fatalf("human projection changed:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestHumanLinesGiveEmptyPresentationFieldsStableFallbacks(t *testing.T) {
	result := validResult(t)
	result.Publisher.DisplayName = ""
	result.Publisher.ID = ""
	result.Trust.RootSource = ""
	result.Reputation.ProviderID = ""
	output := strings.Join(HumanLines(result), "\n")
	for _, expected := range []string{string(result.Publisher.Status), "identity: not-provided", "root not-applicable", "provider not-consulted"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("human decision omitted fallback %q: %q", expected, output)
		}
	}
}
