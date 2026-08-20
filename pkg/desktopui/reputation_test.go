/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package desktopui

import (
	"context"
	"errors"
	"image"
	"strings"
	"testing"
)

func TestHeadlessReputationPromptCannotInferConsent(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	accepted, err := ConfirmPublisherReputation(context.Background(), BackendBuiltin, ReputationPrompt{})
	if accepted || !errors.Is(err, ErrReputationPromptUnavailable) {
		t.Fatalf("accepted=%v err=%v", accepted, err)
	}
}

func TestReputationPromptBoundsAndSanitizesEveryExternalField(t *testing.T) {
	tainted := strings.Repeat("publisher", 100) + "\x00\x1b[2J"
	request := cleanReputationPrompt(ReputationPrompt{
		Origin: tainted, PublisherName: tainted, PublisherID: tainted, ProviderID: tainted,
		Status: tainted, ProviderReason: tainted, PolicyReason: tainted,
	})
	for name, value := range map[string]string{
		"origin": request.Origin, "publisher_name": request.PublisherName, "publisher_id": request.PublisherID,
		"provider": request.ProviderID, "status": request.Status, "provider_reason": request.ProviderReason,
		"policy_reason": request.PolicyReason,
	} {
		if len([]rune(value)) > 512 || strings.ContainsAny(value, "\x00\x1b") {
			t.Fatalf("%s was not bounded and sanitized: %q", name, value)
		}
	}
}

func TestReputationPromptNamesIdentityAndScope(t *testing.T) {
	body := reputationPromptBody(ReputationPrompt{
		Origin: "github.com/user/demo", PublisherName: "Demo Publisher", PublisherID: "oidc:demo",
		ProviderID: "cpak-poc", Status: "caution", ProviderReason: "recent-key-change", PolicyReason: "reputation-warning",
	})
	for _, expected := range []string{"github.com/user/demo", "Demo Publisher", "oidc:demo", "cpak-poc", "caution", "recent-key-change", "reputation-warning", "only to this install", "does not mark"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("prompt omitted %q: %q", expected, body)
		}
	}
}

func TestReputationRiskActionRequiresItsOwnHitTarget(t *testing.T) {
	risk := reputationAction(620, 540, 1)
	if got := reputationActionAt(image.Pt(risk.Min.X+1, risk.Min.Y+1), 620, 540); got != 1 {
		t.Fatalf("risk action = %d", got)
	}
	if got := reputationActionAt(image.Pt(0, 0), 620, 540); got != -1 {
		t.Fatalf("outside action = %d", got)
	}
}
