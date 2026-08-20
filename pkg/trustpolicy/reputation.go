/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package trustpolicy

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/mirkobrombin/cpak/pkg/reputation"
)

type ReputationMode string

const (
	ReputationOff                ReputationMode = "off"
	ReputationAudit              ReputationMode = "audit"
	ReputationWarn               ReputationMode = "warn"
	ReputationRequireEstablished ReputationMode = "require-established"
)

type InvocationContext string

const (
	InvocationGraphical           InvocationContext = "graphical"
	InvocationInteractiveTerminal InvocationContext = "interactive-terminal"
	InvocationNonInteractive      InvocationContext = "non-interactive"
)

type DecisionAction string

const (
	ActionAllow                DecisionAction = "allow"
	ActionWarn                 DecisionAction = "warn"
	ActionDeny                 DecisionAction = "deny"
	ActionConfirmationRequired DecisionAction = "confirmation-required"
)

type X509Policy struct {
	Revocation string `json:"revocation"`
}

type ReputationPolicy struct {
	Mode       ReputationMode        `json:"mode"`
	ProviderID string                `json:"provider_id,omitempty"`
	Exceptions []ReputationException `json:"exceptions,omitempty"`
}

type ReputationException struct {
	PublisherID string              `json:"publisher_id"`
	Origins     []string            `json:"origins"`
	Statuses    []reputation.Status `json:"statuses"`
	ExpiresAt   string              `json:"expires_at,omitempty"`
	ReasonCode  string              `json:"reason_code"`
}

type ReputationDecision struct {
	Allowed    bool           `json:"allowed"`
	Action     DecisionAction `json:"action"`
	ReasonCode string         `json:"reason_code"`
	Reason     string         `json:"reason"`
	Exception  bool           `json:"exception,omitempty"`
}

func (d ReputationDecision) Validate() error {
	switch d.Action {
	case ActionAllow, ActionWarn:
		if !d.Allowed {
			return errors.New("allowing reputation action is marked refused")
		}
	case ActionDeny, ActionConfirmationRequired:
		if d.Allowed {
			return errors.New("refusing reputation action is marked allowed")
		}
	default:
		return errors.New("reputation decision has an unknown action")
	}
	if !policyNamePattern.MatchString(d.ReasonCode) {
		return errors.New("reputation decision has an invalid reason code")
	}
	if d.Reason == "" || len(d.Reason) > reasonLimit {
		return errors.New("reputation decision has an invalid reason")
	}
	return nil
}

var policyNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func (p Policy) validateV2() error {
	if p.X509.Revocation != "allow-unknown" && p.X509.Revocation != "require-good" {
		return fmt.Errorf("%w: x509 revocation must be allow-unknown or require-good", ErrInvalidPolicy)
	}
	switch p.Reputation.Mode {
	case ReputationOff:
		if p.Reputation.ProviderID != "" || len(p.Reputation.Exceptions) != 0 {
			return fmt.Errorf("%w: reputation mode off cannot name a provider or exceptions", ErrInvalidPolicy)
		}
	case ReputationAudit, ReputationWarn, ReputationRequireEstablished:
		if !policyNamePattern.MatchString(p.Reputation.ProviderID) {
			return fmt.Errorf("%w: reputation mode %s requires a valid provider id", ErrInvalidPolicy, p.Reputation.Mode)
		}
	default:
		return fmt.Errorf("%w: unsupported reputation mode %q", ErrInvalidPolicy, p.Reputation.Mode)
	}
	seenPublishers := make(map[string]struct{}, len(p.ApprovedPublisherIDs))
	for _, publisherID := range p.ApprovedPublisherIDs {
		if !reputation.ValidPublisherID(publisherID) {
			return fmt.Errorf("%w: unsupported normalized publisher id", ErrInvalidPolicy)
		}
		if _, duplicate := seenPublishers[publisherID]; duplicate {
			return fmt.Errorf("%w: duplicate normalized publisher id", ErrInvalidPolicy)
		}
		seenPublishers[publisherID] = struct{}{}
	}
	seenExceptions := make(map[string]struct{}, len(p.Reputation.Exceptions))
	for index, exception := range p.Reputation.Exceptions {
		if err := validateReputationException(exception); err != nil {
			return fmt.Errorf("%w: reputation exception %d: %v", ErrInvalidPolicy, index, err)
		}
		origins := append([]string(nil), exception.Origins...)
		statuses := append([]reputation.Status(nil), exception.Statuses...)
		sort.Strings(origins)
		sort.Slice(statuses, func(i, j int) bool { return statuses[i] < statuses[j] })
		key := exception.PublisherID + "\x00" + fmt.Sprint(origins) + "\x00" + fmt.Sprint(statuses) + "\x00" + exception.ExpiresAt
		if _, duplicate := seenExceptions[key]; duplicate {
			return fmt.Errorf("%w: duplicate reputation exception scope", ErrInvalidPolicy)
		}
		seenExceptions[key] = struct{}{}
	}
	return nil
}

func validateReputationException(exception ReputationException) error {
	if !reputation.ValidPublisherID(exception.PublisherID) {
		return fmt.Errorf("unsupported publisher id")
	}
	if len(exception.Origins) == 0 || len(exception.Statuses) == 0 {
		return fmt.Errorf("scope is empty")
	}
	seenOrigins := make(map[string]struct{}, len(exception.Origins))
	for _, origin := range exception.Origins {
		if err := validateOrigin("reputation exception", origin); err != nil {
			return err
		}
		if _, duplicate := seenOrigins[origin]; duplicate {
			return fmt.Errorf("duplicate origin")
		}
		seenOrigins[origin] = struct{}{}
	}
	seenStatuses := make(map[reputation.Status]struct{}, len(exception.Statuses))
	for _, status := range exception.Statuses {
		if status != reputation.Unknown && status != reputation.Caution {
			return fmt.Errorf("status %q cannot be excepted", status)
		}
		if _, duplicate := seenStatuses[status]; duplicate {
			return fmt.Errorf("duplicate status")
		}
		seenStatuses[status] = struct{}{}
	}
	if exception.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, exception.ExpiresAt)
		if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != exception.ExpiresAt {
			return fmt.Errorf("expiry is not a canonical UTC whole-second timestamp")
		}
	}
	if !policyNamePattern.MatchString(exception.ReasonCode) {
		return fmt.Errorf("reason code is invalid")
	}
	return nil
}

// DecidesReputation applies only the reputation stage. Earlier cryptographic,
// origin, publisher, and administrator decisions must already have allowed.
func (p Policy) DecidesReputation(result reputation.Result, publisherID, origin string, now time.Time, context InvocationContext) ReputationDecision {
	decision := p.EvaluatesReputation(result, publisherID, origin, now)
	if decision.Action == ActionWarn && context != InvocationGraphical && context != InvocationInteractiveTerminal {
		return ReputationDecision{Action: ActionConfirmationRequired, ReasonCode: "reputation-confirmation-required", Reason: "publisher reputation requires confirmation, and this invocation is non-interactive"}
	}
	return decision
}

// EvaluatesReputation computes only the host policy stage. It never infers
// presentation consent from a TTY or display; an adapter applies invocation
// context and a dedicated confirmation afterwards.
func (p Policy) EvaluatesReputation(result reputation.Result, publisherID, origin string, now time.Time) ReputationDecision {
	if p.ABI != CurrentABIVersion || p.Reputation == nil || p.Reputation.Mode == ReputationOff {
		return reputationAllow("reputation-off", "publisher reputation is not enforced on this host")
	}
	if result.ProviderID != p.Reputation.ProviderID && result.Status != reputation.Unavailable {
		result = reputation.UnavailableResult(p.Reputation.ProviderID, publisherID, "provider-mismatch")
	}
	if result.PublisherID != publisherID {
		result = reputation.UnavailableResult(p.Reputation.ProviderID, publisherID, "publisher-mismatch")
	}
	switch p.Reputation.Mode {
	case ReputationAudit:
		return reputationAllow("reputation-audited", "publisher reputation was recorded without changing the host decision")
	case ReputationWarn:
		if result.Status == reputation.Blocked {
			return reputationDeny("publisher-blocked", "the configured reputation provider blocks this publisher")
		}
		if result.Status == reputation.Established {
			return reputationAllow("publisher-established", "the configured reputation provider reports an established publisher")
		}
		return ReputationDecision{Allowed: true, Action: ActionWarn, ReasonCode: result.ReasonCode, Reason: "publisher reputation requires a warning before continuing"}
	case ReputationRequireEstablished:
		if result.Status == reputation.Blocked {
			return reputationDeny("publisher-blocked", "the configured reputation provider blocks this publisher")
		}
		if result.Status == reputation.Established {
			return reputationAllow("publisher-established", "the configured reputation provider reports an established publisher")
		}
		if exception := p.reputationException(result.Status, publisherID, origin, now); exception != nil {
			decision := reputationAllow(exception.ReasonCode, "a scoped administrator exception permits this reputation result")
			decision.Exception = true
			return decision
		}
		return reputationDeny("publisher-not-established", "this host requires an established publisher")
	default:
		return reputationDeny("reputation-policy-invalid", "the reputation policy cannot be applied")
	}
}

func (p Policy) reputationException(status reputation.Status, publisherID, origin string, now time.Time) *ReputationException {
	if status != reputation.Unknown && status != reputation.Caution {
		return nil
	}
	for index := range p.Reputation.Exceptions {
		exception := &p.Reputation.Exceptions[index]
		if exception.PublisherID != publisherID || !containsOrigin(exception.Origins, origin) || !containsStatus(exception.Statuses, status) {
			continue
		}
		if exception.ExpiresAt != "" {
			expires, _ := time.Parse(time.RFC3339, exception.ExpiresAt)
			if !now.Before(expires) {
				continue
			}
		}
		return exception
	}
	return nil
}

func containsOrigin(origins []string, wanted string) bool {
	for _, origin := range origins {
		if sameOrigin(origin, wanted) {
			return true
		}
	}
	return false
}

func containsStatus(statuses []reputation.Status, wanted reputation.Status) bool {
	for _, status := range statuses {
		if status == wanted {
			return true
		}
	}
	return false
}

func reputationAllow(code, reason string) ReputationDecision {
	return ReputationDecision{Allowed: true, Action: ActionAllow, ReasonCode: code, Reason: reason}
}

func reputationDeny(code, reason string) ReputationDecision {
	return ReputationDecision{Action: ActionDeny, ReasonCode: code, Reason: reason}
}
