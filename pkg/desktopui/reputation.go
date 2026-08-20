/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package desktopui

import (
	"context"
	"errors"
	"os"
	"strings"
	"unicode"
)

var ErrReputationPromptUnavailable = errors.New("publisher reputation prompt is unavailable")

// ReputationPrompt contains only display data. The authority challenge never
// crosses this UI boundary and the boolean answer cannot authorize anything by
// itself; the authority re-evaluates the exact enrolment after the callback.
type ReputationPrompt struct {
	Origin         string
	PublisherName  string
	PublisherID    string
	ProviderID     string
	Status         string
	ProviderReason string
	PolicyReason   string
}

// ConfirmPublisherReputation asks about this installation, not about a
// persistent publisher exception. A missing graphical frontend is an error so
// callers can preserve confirmation-required instead of inferring consent.
func ConfirmPublisherReputation(ctx context.Context, backend Backend, request ReputationPrompt) (bool, error) {
	request = cleanReputationPrompt(request)
	if backend != BackendBuiltin {
		result, err := runAdapterPrompt(ctx, backend, adapterPrompt{
			Title: "Publisher reputation", Heading: "Reputation requires your decision",
			Body: reputationPromptBody(request), AcceptLabel: "Enrol this installation",
			CancelLabel: "Leave unenrolled", Recommended: false,
		})
		if err == nil {
			return result.Accepted, nil
		}
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return false, ErrReputationPromptUnavailable
	}
	return confirmReputationBuiltin(ctx, request)
}

func reputationPromptBody(request ReputationPrompt) string {
	publisher := request.PublisherName
	if publisher == "" {
		publisher = "Not provided"
	}
	return strings.Join([]string{
		"Application: " + fallbackReputationText(request.Origin),
		"Publisher: " + publisher,
		"Publisher ID: " + fallbackReputationText(request.PublisherID),
		"Provider: " + fallbackReputationText(request.ProviderID),
		"Status: " + fallbackReputationText(request.Status),
		"Provider reason: " + fallbackReputationText(request.ProviderReason),
		"Host policy: " + fallbackReputationText(request.PolicyReason),
		"",
		"The publisher signature is verified for this origin. This approval applies only to this install and does not mark the publisher or software as safe.",
	}, "\n")
}

func cleanReputationPrompt(request ReputationPrompt) ReputationPrompt {
	request.Origin = cleanReputationText(request.Origin)
	request.PublisherName = cleanReputationText(request.PublisherName)
	request.PublisherID = cleanReputationText(request.PublisherID)
	request.ProviderID = cleanReputationText(request.ProviderID)
	request.Status = cleanReputationText(request.Status)
	request.ProviderReason = cleanReputationText(request.ProviderReason)
	request.PolicyReason = cleanReputationText(request.PolicyReason)
	return request
}

func cleanReputationText(value string) string {
	value = strings.Map(func(value rune) rune {
		if unicode.IsControl(value) {
			return -1
		}
		return value
	}, value)
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > 512 {
		runes = runes[:512]
	}
	return string(runes)
}

func fallbackReputationText(value string) string {
	if value == "" {
		return "Not provided"
	}
	return value
}
