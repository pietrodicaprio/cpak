/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package trustpolicy

import (
	"strings"
	"testing"
	"time"

	"github.com/mirkobrombin/cpak/pkg/reputation"
)

const reputationPublisherID = "x509-spki-sha256:1111111111111111111111111111111111111111111111111111111111111111"

var policyNow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func reputationPolicy(mode ReputationMode) Policy {
	providerID := "cpak-poc"
	if mode == ReputationOff {
		providerID = ""
	}
	return Policy{
		ABI:        CurrentABIVersion,
		X509:       &X509Policy{Revocation: "allow-unknown"},
		Reputation: &ReputationPolicy{Mode: mode, ProviderID: providerID},
	}
}

func reputationResult(status reputation.Status) reputation.Result {
	return reputation.Result{
		ProviderID: "cpak-poc", PublisherID: reputationPublisherID, Status: status,
		IssuedAt: policyNow.Add(-time.Hour), ExpiresAt: policyNow.Add(time.Hour), Sequence: 7, ReasonCode: "provider-result",
	}
}

func TestReputationPolicyModesHaveFrozenConsequences(t *testing.T) {
	statuses := []reputation.Status{reputation.Established, reputation.Unknown, reputation.Caution, reputation.Blocked, reputation.Unavailable}
	cases := []struct {
		mode    ReputationMode
		status  reputation.Status
		allowed bool
		action  DecisionAction
	}{
		{ReputationOff, reputation.Blocked, true, ActionAllow},
		{ReputationAudit, reputation.Established, true, ActionAllow},
		{ReputationAudit, reputation.Unknown, true, ActionAllow},
		{ReputationAudit, reputation.Caution, true, ActionAllow},
		{ReputationAudit, reputation.Blocked, true, ActionAllow},
		{ReputationAudit, reputation.Unavailable, true, ActionAllow},
		{ReputationWarn, reputation.Established, true, ActionAllow},
		{ReputationWarn, reputation.Unknown, true, ActionWarn},
		{ReputationWarn, reputation.Caution, true, ActionWarn},
		{ReputationWarn, reputation.Blocked, false, ActionDeny},
		{ReputationWarn, reputation.Unavailable, true, ActionWarn},
		{ReputationRequireEstablished, reputation.Established, true, ActionAllow},
		{ReputationRequireEstablished, reputation.Unknown, false, ActionDeny},
		{ReputationRequireEstablished, reputation.Caution, false, ActionDeny},
		{ReputationRequireEstablished, reputation.Blocked, false, ActionDeny},
		{ReputationRequireEstablished, reputation.Unavailable, false, ActionDeny},
	}
	if len(cases) != 1+len(statuses)*3 {
		t.Fatal("decision table does not cover every active mode and status")
	}
	for _, test := range cases {
		t.Run(string(test.mode)+"/"+string(test.status), func(t *testing.T) {
			policy := reputationPolicy(test.mode)
			if test.mode == ReputationOff {
				policy.Reputation.ProviderID = ""
			}
			decision := policy.DecidesReputation(reputationResult(test.status), reputationPublisherID, testOrigin, policyNow, InvocationInteractiveTerminal)
			if decision.Allowed != test.allowed || decision.Action != test.action || decision.ReasonCode == "" || decision.Reason == "" {
				t.Fatalf("got %+v, want allowed=%v action=%s", decision, test.allowed, test.action)
			}
		})
	}
}

func TestWarnRequiresConfirmationWithoutAnInteractiveCaller(t *testing.T) {
	policy := reputationPolicy(ReputationWarn)
	for _, context := range []InvocationContext{InvocationGraphical, InvocationInteractiveTerminal} {
		decision := policy.DecidesReputation(reputationResult(reputation.Unknown), reputationPublisherID, testOrigin, policyNow, context)
		if !decision.Allowed || decision.Action != ActionWarn {
			t.Fatalf("%s: got %+v", context, decision)
		}
	}
	decision := policy.DecidesReputation(reputationResult(reputation.Unknown), reputationPublisherID, testOrigin, policyNow, InvocationNonInteractive)
	if decision.Allowed || decision.Action != ActionConfirmationRequired || decision.ReasonCode != "reputation-confirmation-required" {
		t.Fatalf("non-interactive warn: got %+v", decision)
	}
}

func TestReputationEvaluationDoesNotInferPresentationConsent(t *testing.T) {
	policy := reputationPolicy(ReputationWarn)
	decision := policy.EvaluatesReputation(reputationResult(reputation.Unknown), reputationPublisherID, testOrigin, policyNow)
	if !decision.Allowed || decision.Action != ActionWarn || decision.ReasonCode != "provider-result" {
		t.Fatalf("policy-stage decision = %+v", decision)
	}
}

func TestReputationExceptionIsExactScopedAndNeverOverridesBlocked(t *testing.T) {
	policy := reputationPolicy(ReputationRequireEstablished)
	policy.Reputation.Exceptions = []ReputationException{{
		PublisherID: reputationPublisherID,
		Origins:     []string{testOrigin}, Statuses: []reputation.Status{reputation.Unknown, reputation.Caution},
		ExpiresAt: policyNow.Add(time.Hour).Format(time.RFC3339), ReasonCode: "migration-window",
	}}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, status := range []reputation.Status{reputation.Unknown, reputation.Caution} {
		decision := policy.DecidesReputation(reputationResult(status), reputationPublisherID, testOrigin, policyNow, InvocationNonInteractive)
		if !decision.Allowed || !decision.Exception || decision.ReasonCode != "migration-window" {
			t.Fatalf("%s: got %+v", status, decision)
		}
	}
	for name, test := range map[string]struct {
		status    reputation.Status
		publisher string
		origin    string
		now       time.Time
	}{
		"blocked":          {reputation.Blocked, reputationPublisherID, testOrigin, policyNow},
		"publisher":        {reputation.Unknown, strings.Replace(reputationPublisherID, "1", "2", 1), testOrigin, policyNow},
		"origin":           {reputation.Unknown, reputationPublisherID, otherOrigin, policyNow},
		"at expiry":        {reputation.Unknown, reputationPublisherID, testOrigin, policyNow.Add(time.Hour)},
		"provider missing": {reputation.Unavailable, reputationPublisherID, testOrigin, policyNow},
	} {
		t.Run(name, func(t *testing.T) {
			result := reputationResult(test.status)
			result.PublisherID = test.publisher
			decision := policy.DecidesReputation(result, test.publisher, test.origin, test.now, InvocationInteractiveTerminal)
			if decision.Allowed || decision.Exception {
				t.Fatalf("got %+v", decision)
			}
		})
	}
}

func TestPolicyV2ValidationRejectsAmbiguousOrUnsafeReputationRules(t *testing.T) {
	valid := reputationPolicy(ReputationRequireEstablished)
	valid.RequirePublisher = true
	valid.ApprovedPublisherIDs = []string{reputationPublisherID}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid ABI 2 policy: %v", err)
	}
	cases := map[string]Policy{
		"missing sections":       {ABI: CurrentABIVersion},
		"v2 fields in abi1":      {ABI: ABIVersion, ApprovedPublisherIDs: []string{reputationPublisherID}},
		"unknown revocation":     {ABI: CurrentABIVersion, X509: &X509Policy{Revocation: "online"}, Reputation: &ReputationPolicy{Mode: ReputationOff}},
		"unknown mode":           {ABI: CurrentABIVersion, X509: &X509Policy{Revocation: "allow-unknown"}, Reputation: &ReputationPolicy{Mode: "sometimes"}},
		"provider while off":     {ABI: CurrentABIVersion, X509: &X509Policy{Revocation: "allow-unknown"}, Reputation: &ReputationPolicy{Mode: ReputationOff, ProviderID: "cpak-poc"}},
		"invalid publisher id":   {ABI: CurrentABIVersion, X509: &X509Policy{Revocation: "allow-unknown"}, Reputation: &ReputationPolicy{Mode: ReputationOff}, ApprovedPublisherIDs: []string{"x509:wrong"}},
		"duplicate publisher id": {ABI: CurrentABIVersion, X509: &X509Policy{Revocation: "allow-unknown"}, Reputation: &ReputationPolicy{Mode: ReputationOff}, ApprovedPublisherIDs: []string{reputationPublisherID, reputationPublisherID}},
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			if err := policy.Validate(); err == nil {
				t.Fatal("invalid policy was accepted")
			}
		})
	}
}

func TestNormalizedPublisherSelectorDoesNotUseDisplayNamesOrPrefixes(t *testing.T) {
	policy := reputationPolicy(ReputationOff)
	policy.RequirePublisher = true
	policy.ApprovedPublisherIDs = []string{reputationPublisherID}
	if decision := policy.AllowsNormalizedPublisher(reputationPublisherID, "", "", testOrigin); !decision.Allowed {
		t.Fatalf("approved normalized identity: %s", decision.Reason)
	}
	for _, candidate := range []string{"", reputationPublisherID + "0", strings.TrimSuffix(reputationPublisherID, "1")} {
		if decision := policy.AllowsNormalizedPublisher(candidate, "", "", testOrigin); decision.Allowed {
			t.Fatalf("lookalike %q was approved", candidate)
		}
	}
}
