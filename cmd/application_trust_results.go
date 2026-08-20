/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mirkobrombin/cpak/pkg/applicationtrust"
	"github.com/mirkobrombin/cpak/pkg/cpak"
	"github.com/mirkobrombin/cpak/pkg/tools"
	"github.com/mirkobrombin/cpak/pkg/types"
	clilog "github.com/mirkobrombin/go-cli-builder/v3/pkg/log"
)

func applicationTrustResults(operation applicationtrust.Operation, context applicationtrust.InvocationContext, enrolments []cpak.ApplicationEnrolment) ([]applicationtrust.Result, error) {
	results := make([]applicationtrust.Result, 0, len(enrolments))
	for _, enrolment := range enrolments {
		result, err := enrolment.ApplicationTrustResult(operation, context)
		if err != nil {
			return nil, fmt.Errorf("project application trust decision for %s: %w", enrolment.Origin, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func writeApplicationTrustResults(results []applicationtrust.Result) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(struct {
		SchemaVersion int                       `json:"schema_version"`
		Trust         []applicationtrust.Result `json:"trust"`
	}{SchemaVersion: applicationtrust.SchemaVersion, Trust: results})
}

func reportApplicationTrustResults(logger clilog.Logger, results []applicationtrust.Result) {
	for _, result := range results {
		publisher := result.Publisher.DisplayName
		if publisher == "" {
			publisher = result.Publisher.ID
		}
		if publisher == "" {
			publisher = string(result.Publisher.Status)
		}
		logger.Info("Application trust for %s: %s (%s).", tools.SanitizeForDisplay(result.Subject.Origin), result.Final.Action, result.Final.ReasonCode)
		logger.Info("  Publisher: %s; verification: %s/%s; origin: %s.",
			tools.SanitizeForDisplay(publisher), result.Verification.Status, result.Verification.EvidenceKind, result.Publisher.OriginAuthorization)
		logger.Info("  Trust: chain %s, root %s, signing time %s, revocation %s.",
			result.Trust.Chain, tools.SanitizeForDisplay(result.Trust.RootSource), result.Trust.SigningTime, result.Trust.Revocation)
		logger.Info("  Reputation: provider %s, status %s, freshness %s; policy: signatures %s, reputation %s, action %s, confirmation %s.",
			tools.SanitizeForDisplay(result.Reputation.ProviderID), result.Reputation.Status, result.Reputation.Freshness,
			result.Policy.SignatureMode, result.Policy.ReputationMode, result.Policy.Action, result.Policy.Confirmation)
	}
}

func applicationTrustResultExit(results []applicationtrust.Result) error {
	selected := 0
	rank := 0
	for _, result := range results {
		candidate := applicationTrustExitRank(result.Final.ExitCode)
		if candidate > rank {
			rank = candidate
			selected = result.Final.ExitCode
		}
	}
	if selected == applicationtrust.ExitAllowed {
		return nil
	}
	return &types.ExitError{Code: selected}
}

func applicationTrustExitRank(code int) int {
	switch code {
	case applicationtrust.ExitInvalid:
		return 4
	case applicationtrust.ExitDenied:
		return 3
	case applicationtrust.ExitUnavailable:
		return 2
	case applicationtrust.ExitConfirmationRequired:
		return 1
	default:
		return 0
	}
}
