/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package applicationtrust

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/xeipuuv/gojsonschema"
)

func TestFinalActionsHaveFrozenExitCodes(t *testing.T) {
	tests := []struct {
		action FinalAction
		class  ExitClass
		code   int
	}{
		{FinalAllow, ClassAllowed, 0},
		{FinalWarn, ClassAllowed, 0},
		{FinalDeny, ClassDenied, 20},
		{FinalInvalid, ClassInvalid, 21},
		{FinalUnavailable, ClassUnavailable, 22},
		{FinalConfirmationRequired, ClassConfirmationRequired, 23},
	}
	for _, test := range tests {
		t.Run(string(test.action), func(t *testing.T) {
			final, err := NewFinal(test.action, "test-reason")
			if err != nil {
				t.Fatal(err)
			}
			if final.Class != test.class || final.ExitCode != test.code {
				t.Fatalf("got class %q code %d, want %q %d", final.Class, final.ExitCode, test.class, test.code)
			}
		})
	}
}

func TestWarningResolutionNeverInfersConsent(t *testing.T) {
	tests := []struct {
		name         string
		context      InvocationContext
		response     ConfirmationResponse
		confirmation ConfirmationState
		action       FinalAction
		code         int
	}{
		{"graphical unanswered", ContextGraphical, NoConfirmation, ConfirmationRequired, FinalConfirmationRequired, 23},
		{"terminal unanswered", ContextInteractiveTerminal, NoConfirmation, ConfirmationRequired, FinalConfirmationRequired, 23},
		{"graphical accepted", ContextGraphical, Confirm, ConfirmationAccepted, FinalWarn, 0},
		{"terminal accepted", ContextInteractiveTerminal, Confirm, ConfirmationAccepted, FinalWarn, 0},
		{"graphical declined", ContextGraphical, Decline, ConfirmationDeclined, FinalDeny, 20},
		{"terminal declined", ContextInteractiveTerminal, Decline, ConfirmationDeclined, FinalDeny, 20},
		{"noninteractive", ContextNonInteractive, NoConfirmation, ConfirmationNotAvailable, FinalConfirmationRequired, 23},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			confirmation, final, err := ResolvePolicyAction(PolicyWarn, test.context, test.response, "publisher-unknown")
			if err != nil {
				t.Fatal(err)
			}
			if confirmation != test.confirmation || final.Action != test.action || final.ExitCode != test.code {
				t.Fatalf("got confirmation %q final %+v", confirmation, final)
			}
		})
	}
}

func TestNonInteractiveInvocationCannotSupplyConfirmation(t *testing.T) {
	for _, response := range []ConfirmationResponse{Confirm, Decline} {
		if _, _, err := ResolvePolicyAction(PolicyWarn, ContextNonInteractive, response, "publisher-unknown"); err == nil {
			t.Fatalf("response %d was accepted", response)
		}
	}
}

func TestDecisionRejectsContradictoryTrustSurfaces(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Result)
	}{
		{"future schema", func(result *Result) { result.SchemaVersion++ }},
		{"final exit mismatch", func(result *Result) { result.Final.ExitCode = ExitDenied }},
		{"unverified identity", func(result *Result) {
			result.Publisher.Status = PublisherAbsent
			result.Publisher.ID = "x509-spki-v1:sha256:0123456789abcdef"
		}},
		{"unsigned with evidence", func(result *Result) {
			result.Verification.Status = VerificationUnsigned
			result.Verification.EvidenceKind = "x509-cms-v1"
		}},
		{"terminal control", func(result *Result) { result.Publisher.DisplayName = "publisher\u001b[2J" }},
		{"noninteractive consent", func(result *Result) { result.Context = ContextNonInteractive }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := validResult(t)
			test.mutate(&result)
			if err := result.Validate(); err == nil {
				t.Fatal("contradictory result was accepted")
			}
		})
	}
}

func TestPortableSchemaAcceptsTheValidatedResult(t *testing.T) {
	result := validResult(t)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	checked := validateSchema(t, encoded)
	if !checked.Valid() {
		t.Fatalf("validated result does not conform to the portable schema: %+v", checked.Errors())
	}
}

func TestPortableSchemaRejectsContradictoryAndUnknownFields(t *testing.T) {
	result := validResult(t)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown field", func(value map[string]any) { value["trusted"] = true }},
		{"future schema", func(value map[string]any) { value["schema_version"] = float64(2) }},
		{"exit mismatch", func(value map[string]any) { value["final"].(map[string]any)["exit_code"] = float64(20) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copyBytes, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			var copyValue map[string]any
			if err := json.Unmarshal(copyBytes, &copyValue); err != nil {
				t.Fatal(err)
			}
			test.mutate(copyValue)
			mutated, err := json.Marshal(copyValue)
			if err != nil {
				t.Fatal(err)
			}
			if checked := validateSchema(t, mutated); checked.Valid() {
				t.Fatal("contradictory schema result was accepted")
			}
		})
	}
}

func validateSchema(t *testing.T, encoded []byte) *gojsonschema.Result {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "schema", "application-trust-decision-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	checked, err := gojsonschema.Validate(gojsonschema.NewReferenceLoader("file://"+path), gojsonschema.NewBytesLoader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return checked
}

func validResult(t *testing.T) Result {
	t.Helper()
	confirmation, final, err := ResolvePolicyAction(PolicyWarn, ContextInteractiveTerminal, Confirm, "publisher-unknown")
	if err != nil {
		t.Fatal(err)
	}
	result := Result{
		SchemaVersion:  SchemaVersion,
		Actor:          "cpak",
		Operation:      OperationInstall,
		Context:        ContextInteractiveTerminal,
		DecisionSource: SourceEvaluated,
		Subject: Subject{
			Origin:         "registry.example/org/application",
			ArtifactDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Generation:     7,
		},
		Verification: Verification{
			Status:       VerificationVerified,
			EvidenceKind: "x509-cms-v1",
			ReasonCode:   "verified",
			Diagnostic:   "detached CMS signature verified",
		},
		Publisher: Publisher{
			Status:      PublisherVerified,
			ID:          "x509-spki-v1:sha256:0123456789abcdef",
			DisplayName: "Example Publisher",
			ReasonCode:  "publisher-verified",
		},
		Trust: Trust{
			Chain:       "trusted-local",
			RootSource:  "local:sha256:0123456789abcdef",
			SigningTime: "timestamped",
			Revocation:  "good",
			ReasonCode:  "chain-trusted",
		},
		Reputation: Reputation{
			ProviderID: "poc-provider",
			Status:     "unknown",
			Freshness:  "fresh",
			IssuedAt:   "2026-08-20T12:00:00Z",
			ExpiresAt:  "2026-08-21T12:00:00Z",
			ReasonCode: "publisher-not-listed",
		},
		Policy: Policy{
			SignatureMode:  "required",
			ReputationMode: "warn",
			Action:         PolicyWarn,
			Confirmation:   confirmation,
			ReasonCode:     "publisher-unknown",
		},
		Final: final,
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	return result
}
