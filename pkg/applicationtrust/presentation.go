/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package applicationtrust

import "fmt"

// HumanLines is the common human-readable projection of a validated decision.
// It explains evidence, identity, trust material, reputation, policy, and the
// final action separately. Presentation text is bounded again here because a
// future actor may construct a result without using cpak's adapter first.
func HumanLines(result Result) []string {
	publisher := presentationText(result.Publisher.DisplayName, string(result.Publisher.Status), 200)
	publisherID := presentationText(result.Publisher.ID, "not-provided", 512)
	return []string{
		fmt.Sprintf("Application trust for %s: %s (%s).",
			presentationText(result.Subject.Origin, "unknown-origin", 512),
			presentationToken(string(result.Final.Action), "invalid-action"),
			presentationToken(result.Final.ReasonCode, "missing-reason")),
		fmt.Sprintf("  Publisher: %s; identity: %s (%s); origin: %s.",
			publisher, publisherID, presentationToken(result.Publisher.ReasonCode, "missing-reason"),
			presentationToken(result.Publisher.OriginAuthorization, "not-evaluated")),
		fmt.Sprintf("  Evidence: %s/%s (%s).",
			presentationToken(string(result.Verification.Status), "invalid-status"),
			presentationToken(result.Verification.EvidenceKind, "unknown"),
			presentationToken(result.Verification.ReasonCode, "missing-reason")),
		fmt.Sprintf("  Trust: chain %s, root %s, signing time %s, revocation %s (%s).",
			presentationToken(result.Trust.Chain, "not-evaluated"),
			presentationText(result.Trust.RootSource, "not-applicable", 512),
			presentationToken(result.Trust.SigningTime, "not-evaluated"),
			presentationToken(result.Trust.Revocation, "not-evaluated"),
			presentationToken(result.Trust.ReasonCode, "missing-reason")),
		fmt.Sprintf("  Reputation: provider %s, status %s, freshness %s (%s).",
			presentationText(result.Reputation.ProviderID, "not-consulted", 128),
			presentationToken(result.Reputation.Status, "not-consulted"),
			presentationToken(result.Reputation.Freshness, "not-applicable"),
			presentationToken(result.Reputation.ReasonCode, "missing-reason")),
		fmt.Sprintf("  Policy: signatures %s, reputation %s, action %s, confirmation %s (%s).",
			presentationToken(result.Policy.SignatureMode, "not-evaluated"),
			presentationToken(result.Policy.ReputationMode, "not-evaluated"),
			presentationToken(string(result.Policy.Action), "not-evaluated"),
			presentationToken(string(result.Policy.Confirmation), "not-evaluated"),
			presentationToken(result.Policy.ReasonCode, "missing-reason")),
	}
}

func presentationText(value, fallback string, limit int) string {
	value = SanitizeText(value, limit)
	if value == "" {
		return fallback
	}
	return value
}

func presentationToken(value, fallback string) string {
	return presentationText(value, fallback, 64)
}
