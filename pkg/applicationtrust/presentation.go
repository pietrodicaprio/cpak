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
			presentationText(result.Subject.Origin, "unknown-origin", 512), result.Final.Action, result.Final.ReasonCode),
		fmt.Sprintf("  Publisher: %s; identity: %s (%s); verification: %s/%s (%s); origin: %s.",
			publisher, publisherID, result.Publisher.ReasonCode, result.Verification.Status,
			result.Verification.EvidenceKind, result.Verification.ReasonCode, result.Publisher.OriginAuthorization),
		fmt.Sprintf("  Trust: chain %s, root %s, signing time %s, revocation %s (%s).",
			result.Trust.Chain, presentationText(result.Trust.RootSource, "not-applicable", 512),
			result.Trust.SigningTime, result.Trust.Revocation, result.Trust.ReasonCode),
		fmt.Sprintf("  Reputation: provider %s, status %s, freshness %s (%s); policy: signatures %s, reputation %s, action %s, confirmation %s (%s).",
			presentationText(result.Reputation.ProviderID, "not-consulted", 512), result.Reputation.Status,
			result.Reputation.Freshness, result.Reputation.ReasonCode, result.Policy.SignatureMode,
			result.Policy.ReputationMode, result.Policy.Action, result.Policy.Confirmation, result.Policy.ReasonCode),
	}
}

func presentationText(value, fallback string, limit int) string {
	value = SanitizeText(value, limit)
	if value == "" {
		return fallback
	}
	return value
}
