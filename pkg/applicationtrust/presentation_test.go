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
	result.Trust.RootSource = tainted
	result.Reputation.ProviderID = tainted
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
