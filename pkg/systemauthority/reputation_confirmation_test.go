/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package systemauthority

import (
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/mirkobrombin/cpak/pkg/reputation"
	"github.com/mirkobrombin/cpak/pkg/trustpolicy"
)

func TestReputationConfirmationIsSingleUseAndBoundToTheExactWarning(t *testing.T) {
	store := &reputationConfirmationStore{random: deterministicConfirmationRandom}
	enrolment := Enrolment{Anchor: testAnchor(), Signature: testSignedState(1)}
	result := authorityReputationResult(testNormalizedPublisher(t).ID, reputation.Unknown)
	decision := trustpolicy.ReputationDecision{Allowed: true, Action: trustpolicy.ActionWarn, ReasonCode: "provider-result", Reason: "publisher reputation requires a warning before continuing"}
	token, err := store.Issue(enrolment, result, decision, reputationNow)
	if err != nil || token == "" {
		t.Fatalf("issue token=%q err=%v", token, err)
	}
	challenge, accepted := store.Consume(token, enrolment, reputationNow)
	if !accepted || !challenge.MatchesWarning(result, decision) {
		t.Fatal("exact confirmation was not accepted")
	}
	if _, replayed := store.Consume(token, enrolment, reputationNow); replayed {
		t.Fatal("confirmation token was replayed")
	}

	token, err = store.Issue(enrolment, result, decision, reputationNow)
	if err != nil {
		t.Fatal(err)
	}
	changed := result
	changed.Sequence++
	challenge, accepted = store.Consume(token, enrolment, reputationNow)
	if !accepted || challenge.MatchesWarning(changed, decision) {
		t.Fatal("confirmation survived a changed provider snapshot")
	}
}

func TestReputationConfirmationCrossesDBusAsValidatedStructuredData(t *testing.T) {
	result := authorityReputationResult(testNormalizedPublisher(t).ID, reputation.Unknown)
	decision := trustpolicy.ReputationDecision{Allowed: true, Action: trustpolicy.ActionWarn, ReasonCode: "provider-result", Reason: "publisher reputation requires a warning before continuing"}
	local := &ReputationConfirmationRequiredError{Result: result, Decision: decision, Token: "confirmation-token"}
	decoded := decodeReputationConfirmationError(enrolmentFailed(local))
	var remote *ReputationConfirmationRequiredError
	if !errors.As(decoded, &remote) || remote.Token != local.Token || remote.Result.Status != result.Status || remote.Decision.Action != trustpolicy.ActionWarn {
		t.Fatalf("decoded confirmation = %#v", decoded)
	}
	if remote.Error() != ErrReputationConfirmationRequired.Error() || remote.Error() == remote.Token {
		t.Fatalf("confirmation token leaked through the error text: %q", remote.Error())
	}

	invalid := dbus.NewError(reputationConfirmationErrorName, []any{"token", `{"result":{"status":"established"},"unexpected":true}`})
	if err := decodeReputationConfirmationError(invalid); err == nil || errors.Is(err, ErrReputationConfirmationRequired) {
		t.Fatalf("invalid authority response was accepted: %v", err)
	}
}

func TestReputationConfirmationExpiresAndCannotMoveToAnotherEnrolment(t *testing.T) {
	store := &reputationConfirmationStore{random: deterministicConfirmationRandom}
	enrolment := Enrolment{Anchor: testAnchor(), Signature: testSignedState(1)}
	result := authorityReputationResult(testNormalizedPublisher(t).ID, reputation.Caution)
	decision := trustpolicy.ReputationDecision{Allowed: true, Action: trustpolicy.ActionWarn, ReasonCode: "provider-result", Reason: "publisher reputation requires a warning before continuing"}
	token, err := store.Issue(enrolment, result, decision, reputationNow)
	if err != nil {
		t.Fatal(err)
	}
	other := enrolment
	other.Generation++
	if _, accepted := store.Consume(token, other, reputationNow); accepted {
		t.Fatal("confirmation moved to another generation")
	}

	token, err = store.Issue(enrolment, result, decision, reputationNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, accepted := store.Consume(token, enrolment, reputationNow.Add(reputationConfirmationTTL)); accepted {
		t.Fatal("expired confirmation was accepted")
	}
}

func deterministicConfirmationRandom(target []byte) (int, error) {
	for index := range target {
		target[index] = byte(index + 1)
	}
	return len(target), nil
}
