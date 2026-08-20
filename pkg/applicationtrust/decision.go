/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

// Package applicationtrust implements the cpak-independent Application Trust
// Decision Result v1 contract. It deliberately imports no cpak domain, storage,
// policy, presentation, or privilege-transport package.
package applicationtrust

import (
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

const SchemaVersion = 1

const (
	ExitAllowed              = 0
	ExitDenied               = 20
	ExitInvalid              = 21
	ExitUnavailable          = 22
	ExitConfirmationRequired = 23
)

type Operation string

const (
	OperationVerify       Operation = "verify"
	OperationInstall      Operation = "install"
	OperationUpdate       Operation = "update"
	OperationAudit        Operation = "audit"
	OperationExplain      Operation = "explain"
	OperationLaunch       Operation = "launch"
	OperationServiceStart Operation = "service-start"
)

type InvocationContext string

const (
	ContextGraphical           InvocationContext = "graphical"
	ContextInteractiveTerminal InvocationContext = "interactive-terminal"
	ContextNonInteractive      InvocationContext = "non-interactive"
)

type DecisionSource string

const (
	SourceEvaluated DecisionSource = "evaluated"
	SourceRecorded  DecisionSource = "recorded"
)

type VerificationStatus string

const (
	VerificationVerified     VerificationStatus = "verified"
	VerificationUnsigned     VerificationStatus = "unsigned"
	VerificationInvalid      VerificationStatus = "invalid"
	VerificationUnavailable  VerificationStatus = "unavailable"
	VerificationNotEvaluated VerificationStatus = "not-evaluated"
)

type PublisherStatus string

const (
	PublisherVerified     PublisherStatus = "verified"
	PublisherAbsent       PublisherStatus = "absent"
	PublisherInvalid      PublisherStatus = "invalid"
	PublisherUnavailable  PublisherStatus = "unavailable"
	PublisherNotEvaluated PublisherStatus = "not-evaluated"
)

type PolicyAction string

const (
	PolicyAllow        PolicyAction = "allow"
	PolicyWarn         PolicyAction = "warn"
	PolicyDeny         PolicyAction = "deny"
	PolicyNotEvaluated PolicyAction = "not-evaluated"
)

type ConfirmationState string

const (
	ConfirmationNotRequired  ConfirmationState = "not-required"
	ConfirmationRequired     ConfirmationState = "required"
	ConfirmationAccepted     ConfirmationState = "accepted"
	ConfirmationDeclined     ConfirmationState = "declined"
	ConfirmationNotAvailable ConfirmationState = "not-available"
)

// ConfirmationResponse is supplied only by a dedicated interactive trust
// prompt. Operation acknowledgements such as --yes have no representation
// here and therefore cannot become trust confirmation accidentally.
type ConfirmationResponse uint8

const (
	NoConfirmation ConfirmationResponse = iota
	Confirm
	Decline
)

type FinalAction string

const (
	FinalAllow                FinalAction = "allow"
	FinalWarn                 FinalAction = "warn"
	FinalDeny                 FinalAction = "deny"
	FinalInvalid              FinalAction = "invalid"
	FinalUnavailable          FinalAction = "unavailable"
	FinalConfirmationRequired FinalAction = "confirmation-required"
)

type ExitClass string

const (
	ClassAllowed              ExitClass = "allowed"
	ClassDenied               ExitClass = "denied"
	ClassInvalid              ExitClass = "invalid"
	ClassUnavailable          ExitClass = "unavailable"
	ClassConfirmationRequired ExitClass = "confirmation-required"
)

type Result struct {
	SchemaVersion  int               `json:"schema_version"`
	Actor          string            `json:"actor"`
	Operation      Operation         `json:"operation"`
	Context        InvocationContext `json:"context"`
	DecisionSource DecisionSource    `json:"decision_source"`
	Subject        Subject           `json:"subject"`
	Verification   Verification      `json:"verification"`
	Publisher      Publisher         `json:"publisher"`
	Trust          Trust             `json:"trust"`
	Reputation     Reputation        `json:"reputation"`
	Policy         Policy            `json:"policy"`
	Final          Final             `json:"final"`
}

type Subject struct {
	Origin         string `json:"origin"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
	Generation     uint64 `json:"generation,omitempty"`
}

type Verification struct {
	Status       VerificationStatus `json:"status"`
	EvidenceKind string             `json:"evidence_kind"`
	ReasonCode   string             `json:"reason_code"`
	Diagnostic   string             `json:"diagnostic,omitempty"`
}

type Publisher struct {
	Status      PublisherStatus `json:"status"`
	ID          string          `json:"id,omitempty"`
	DisplayName string          `json:"display_name,omitempty"`
	ReasonCode  string          `json:"reason_code"`
}

type Trust struct {
	Chain       string `json:"chain"`
	RootSource  string `json:"root_source,omitempty"`
	SigningTime string `json:"signing_time"`
	Revocation  string `json:"revocation"`
	ReasonCode  string `json:"reason_code"`
}

type Reputation struct {
	ProviderID string `json:"provider_id,omitempty"`
	Status     string `json:"status"`
	Freshness  string `json:"freshness"`
	IssuedAt   string `json:"issued_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	ReasonCode string `json:"reason_code"`
}

type Policy struct {
	SignatureMode  string            `json:"signature_mode"`
	ReputationMode string            `json:"reputation_mode"`
	Action         PolicyAction      `json:"action"`
	Confirmation   ConfirmationState `json:"confirmation"`
	Exception      bool              `json:"exception"`
	ReasonCode     string            `json:"reason_code"`
}

type Final struct {
	Action     FinalAction `json:"action"`
	Class      ExitClass   `json:"class"`
	ReasonCode string      `json:"reason_code"`
	ExitCode   int         `json:"exit_code"`
}

var (
	namePattern   = regexp.MustCompile("^[a-z0-9][a-z0-9._-]{0,63}$")
	digestPattern = regexp.MustCompile("^[a-z0-9][a-z0-9+._-]{0,31}:[0-9a-f]{32,128}$")
)

func (r Result) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported application trust result schema %d", r.SchemaVersion)
	}
	if !namePattern.MatchString(r.Actor) {
		return errors.New("application trust result has an invalid actor")
	}
	if !validOperation(r.Operation) {
		return errors.New("application trust result has an invalid operation")
	}
	if !validContext(r.Context) {
		return errors.New("application trust result has an invalid invocation context")
	}
	if r.DecisionSource != SourceEvaluated && r.DecisionSource != SourceRecorded {
		return errors.New("application trust result has an invalid decision source")
	}
	if err := r.Subject.validate(); err != nil {
		return fmt.Errorf("application trust subject: %w", err)
	}
	if err := r.Verification.validate(); err != nil {
		return fmt.Errorf("application trust verification: %w", err)
	}
	if err := r.Publisher.validate(); err != nil {
		return fmt.Errorf("application trust publisher: %w", err)
	}
	if err := r.Trust.validate(); err != nil {
		return fmt.Errorf("application trust root: %w", err)
	}
	if err := r.Reputation.validate(); err != nil {
		return fmt.Errorf("application trust reputation: %w", err)
	}
	if err := r.Policy.validate(r.Context); err != nil {
		return fmt.Errorf("application trust policy: %w", err)
	}
	if err := r.Final.validate(); err != nil {
		return fmt.Errorf("application trust final action: %w", err)
	}
	return validateResolution(r.Context, r.Policy, r.Final)
}

func (s Subject) validate() error {
	if err := safeText(s.Origin, 512, false); err != nil {
		return fmt.Errorf("invalid origin: %w", err)
	}
	if s.ArtifactDigest != "" && !digestPattern.MatchString(s.ArtifactDigest) {
		return errors.New("invalid artifact digest")
	}
	return nil
}

func (v Verification) validate() error {
	switch v.Status {
	case VerificationVerified, VerificationUnsigned, VerificationInvalid, VerificationUnavailable, VerificationNotEvaluated:
	default:
		return errors.New("invalid status")
	}
	if !oneOf(v.EvidenceKind, "sigstore-bundle-v1", "x509-cms-v1", "none", "unknown") {
		return errors.New("invalid evidence kind")
	}
	if v.EvidenceKind == "none" && v.Status != VerificationUnsigned && v.Status != VerificationNotEvaluated {
		return errors.New("evidence kind none contradicts verification status")
	}
	if v.Status == VerificationUnsigned && v.EvidenceKind != "none" {
		return errors.New("unsigned verification names attached evidence")
	}
	if err := reasonCode(v.ReasonCode); err != nil {
		return err
	}
	return safeText(v.Diagnostic, 512, true)
}

func (p Publisher) validate() error {
	switch p.Status {
	case PublisherVerified, PublisherAbsent, PublisherInvalid, PublisherUnavailable, PublisherNotEvaluated:
	default:
		return errors.New("invalid status")
	}
	if p.Status == PublisherVerified {
		if err := safeText(p.ID, 512, false); err != nil {
			return fmt.Errorf("invalid verified identity: %w", err)
		}
	} else if p.ID != "" {
		return errors.New("unverified publisher carries an identity")
	}
	if p.Status != PublisherVerified && p.DisplayName != "" {
		return errors.New("unverified publisher carries a display name")
	}
	if err := safeText(p.DisplayName, 200, true); err != nil {
		return fmt.Errorf("invalid display name: %w", err)
	}
	return reasonCode(p.ReasonCode)
}

func (t Trust) validate() error {
	if !oneOf(t.Chain, "trusted-public", "trusted-local", "not-applicable", "untrusted", "invalid", "not-evaluated") {
		return errors.New("invalid chain status")
	}
	if !oneOf(t.SigningTime, "current", "timestamped", "missing", "expired", "not-yet-valid", "invalid", "not-applicable", "not-evaluated") {
		return errors.New("invalid signing-time status")
	}
	if !oneOf(t.Revocation, "good", "revoked", "unknown", "stale", "not-applicable", "not-evaluated") {
		return errors.New("invalid revocation status")
	}
	if err := safeText(t.RootSource, 512, true); err != nil {
		return fmt.Errorf("invalid root source: %w", err)
	}
	return reasonCode(t.ReasonCode)
}

func (r Reputation) validate() error {
	if r.ProviderID != "" && !namePattern.MatchString(r.ProviderID) {
		return errors.New("invalid provider id")
	}
	if !oneOf(r.Status, "established", "unknown", "caution", "blocked", "unavailable", "not-consulted") {
		return errors.New("invalid status")
	}
	if !oneOf(r.Freshness, "fresh", "stale", "unavailable", "not-applicable") {
		return errors.New("invalid freshness")
	}
	if err := canonicalTime(r.IssuedAt); err != nil {
		return fmt.Errorf("invalid issued-at time: %w", err)
	}
	if err := canonicalTime(r.ExpiresAt); err != nil {
		return fmt.Errorf("invalid expiry time: %w", err)
	}
	return reasonCode(r.ReasonCode)
}

func (p Policy) validate(context InvocationContext) error {
	if !oneOf(p.SignatureMode, "optional", "required", "not-applicable") {
		return errors.New("invalid signature mode")
	}
	if !oneOf(p.ReputationMode, "off", "audit", "warn", "require-established", "not-applicable") {
		return errors.New("invalid reputation mode")
	}
	switch p.Action {
	case PolicyAllow, PolicyDeny, PolicyNotEvaluated:
		if p.Confirmation != ConfirmationNotRequired {
			return errors.New("non-warning action carries confirmation")
		}
	case PolicyWarn:
		switch p.Confirmation {
		case ConfirmationRequired, ConfirmationAccepted, ConfirmationDeclined, ConfirmationNotAvailable:
		default:
			return errors.New("warning has an invalid confirmation state")
		}
		if context == ContextNonInteractive && p.Confirmation != ConfirmationNotAvailable {
			return errors.New("non-interactive warning inferred confirmation")
		}
		if context != ContextNonInteractive && p.Confirmation == ConfirmationNotAvailable {
			return errors.New("interactive warning says confirmation is unavailable")
		}
	default:
		return errors.New("invalid action")
	}
	return reasonCode(p.ReasonCode)
}

func (f Final) validate() error {
	if err := reasonCode(f.ReasonCode); err != nil {
		return err
	}
	class, code, ok := finalMapping(f.Action)
	if !ok {
		return errors.New("invalid action")
	}
	if f.Class != class || f.ExitCode != code {
		return errors.New("action, class, and exit code disagree")
	}
	return nil
}

func validateResolution(context InvocationContext, policy Policy, final Final) error {
	switch final.Action {
	case FinalAllow:
		if policy.Action != PolicyAllow && policy.Action != PolicyNotEvaluated {
			return errors.New("application trust resolution allows a non-allow policy")
		}
	case FinalWarn:
		if policy.Action != PolicyWarn || policy.Confirmation != ConfirmationAccepted || context == ContextNonInteractive {
			return errors.New("application trust resolution warns without interactive confirmation")
		}
	case FinalDeny:
		if policy.Action == PolicyWarn {
			if policy.Confirmation != ConfirmationDeclined {
				return errors.New("application trust resolution denies a warning without a decline")
			}
		} else if policy.Action != PolicyDeny {
			return errors.New("application trust resolution denies a non-deny policy")
		}
	case FinalConfirmationRequired:
		if policy.Action != PolicyWarn || (policy.Confirmation != ConfirmationRequired && policy.Confirmation != ConfirmationNotAvailable) {
			return errors.New("application trust resolution asks for confirmation outside a warning")
		}
	case FinalInvalid, FinalUnavailable:
		if policy.Confirmation != ConfirmationNotRequired {
			return errors.New("application trust resolution uses confirmation to override a failed prerequisite")
		}
	}
	return nil
}

// ResolvePolicyAction applies presentation confirmation to an already computed
// host policy action. It cannot turn an invalid or unavailable prerequisite
// into a policy action; callers construct those final results directly.
func ResolvePolicyAction(action PolicyAction, context InvocationContext, response ConfirmationResponse, reason string) (ConfirmationState, Final, error) {
	if !validContext(context) {
		return "", Final{}, errors.New("invalid invocation context")
	}
	if err := reasonCode(reason); err != nil {
		return "", Final{}, err
	}
	switch action {
	case PolicyAllow:
		if response != NoConfirmation {
			return "", Final{}, errors.New("allow action does not accept confirmation")
		}
		return ConfirmationNotRequired, finalFor(FinalAllow, reason), nil
	case PolicyDeny:
		if response != NoConfirmation {
			return "", Final{}, errors.New("deny action does not accept confirmation")
		}
		return ConfirmationNotRequired, finalFor(FinalDeny, reason), nil
	case PolicyWarn:
		if context == ContextNonInteractive {
			if response != NoConfirmation {
				return "", Final{}, errors.New("non-interactive invocation cannot answer a trust prompt")
			}
			return ConfirmationNotAvailable, finalFor(FinalConfirmationRequired, "confirmation-required"), nil
		}
		switch response {
		case NoConfirmation:
			return ConfirmationRequired, finalFor(FinalConfirmationRequired, "confirmation-required"), nil
		case Confirm:
			return ConfirmationAccepted, finalFor(FinalWarn, reason), nil
		case Decline:
			return ConfirmationDeclined, finalFor(FinalDeny, "confirmation-declined"), nil
		default:
			return "", Final{}, errors.New("invalid confirmation response")
		}
	default:
		return "", Final{}, errors.New("policy action cannot be resolved")
	}
}

func NewFinal(action FinalAction, reason string) (Final, error) {
	if err := reasonCode(reason); err != nil {
		return Final{}, err
	}
	class, code, ok := finalMapping(action)
	if !ok {
		return Final{}, errors.New("invalid final action")
	}
	return Final{Action: action, Class: class, ReasonCode: reason, ExitCode: code}, nil
}

func finalFor(action FinalAction, reason string) Final {
	class, code, _ := finalMapping(action)
	return Final{Action: action, Class: class, ReasonCode: reason, ExitCode: code}
}

func finalMapping(action FinalAction) (ExitClass, int, bool) {
	switch action {
	case FinalAllow, FinalWarn:
		return ClassAllowed, ExitAllowed, true
	case FinalDeny:
		return ClassDenied, ExitDenied, true
	case FinalInvalid:
		return ClassInvalid, ExitInvalid, true
	case FinalUnavailable:
		return ClassUnavailable, ExitUnavailable, true
	case FinalConfirmationRequired:
		return ClassConfirmationRequired, ExitConfirmationRequired, true
	default:
		return "", 0, false
	}
}

func validOperation(operation Operation) bool {
	switch operation {
	case OperationVerify, OperationInstall, OperationUpdate, OperationAudit, OperationExplain, OperationLaunch, OperationServiceStart:
		return true
	default:
		return false
	}
}

func validContext(context InvocationContext) bool {
	return context == ContextGraphical || context == ContextInteractiveTerminal || context == ContextNonInteractive
}

func reasonCode(value string) error {
	if !namePattern.MatchString(value) {
		return errors.New("invalid reason code")
	}
	return nil
}

func safeText(value string, limit int, empty bool) error {
	if !utf8.ValidString(value) {
		return errors.New("text is not valid UTF-8")
	}
	if !empty && value == "" {
		return errors.New("text is empty")
	}
	if len(value) > limit {
		return errors.New("text exceeds its byte limit")
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return errors.New("text contains a control character")
		}
	}
	return nil
}

func canonicalTime(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != value {
		return errors.New("time is not canonical UTC whole-second RFC 3339")
	}
	return nil
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
