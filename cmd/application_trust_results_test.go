/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package cmd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mirkobrombin/cpak/pkg/applicationtrust"
	"github.com/mirkobrombin/cpak/pkg/cpak"
	"github.com/mirkobrombin/cpak/pkg/types"
)

func TestApplicationTrustAggregateExitUsesStableSeverityPrecedence(t *testing.T) {
	final := func(action applicationtrust.FinalAction) applicationtrust.Result {
		value, err := applicationtrust.NewFinal(action, "aggregate-test")
		if err != nil {
			t.Fatal(err)
		}
		return applicationtrust.Result{Final: value}
	}
	tests := []struct {
		name    string
		results []applicationtrust.Result
		want    int
	}{
		{name: "empty", want: applicationtrust.ExitAllowed},
		{name: "allowed", results: []applicationtrust.Result{final(applicationtrust.FinalAllow)}, want: applicationtrust.ExitAllowed},
		{name: "confirmation", results: []applicationtrust.Result{final(applicationtrust.FinalAllow), final(applicationtrust.FinalConfirmationRequired)}, want: applicationtrust.ExitConfirmationRequired},
		{name: "unavailable masks confirmation", results: []applicationtrust.Result{final(applicationtrust.FinalConfirmationRequired), final(applicationtrust.FinalUnavailable)}, want: applicationtrust.ExitUnavailable},
		{name: "denial masks unavailable", results: []applicationtrust.Result{final(applicationtrust.FinalUnavailable), final(applicationtrust.FinalDeny)}, want: applicationtrust.ExitDenied},
		{name: "invalid masks every other class", results: []applicationtrust.Result{final(applicationtrust.FinalDeny), final(applicationtrust.FinalInvalid), final(applicationtrust.FinalUnavailable)}, want: applicationtrust.ExitInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := applicationTrustResultExit(test.results)
			if test.want == applicationtrust.ExitAllowed {
				if err != nil {
					t.Fatalf("allowed aggregate returned %v", err)
				}
				return
			}
			var exitErr *types.ExitError
			if !errors.As(err, &exitErr) || exitErr.Code != test.want {
				t.Fatalf("aggregate exit = %v, want %d", err, test.want)
			}
		})
	}
}

func TestApplicationTrustMachineEnvelopePreservesValidatedResults(t *testing.T) {
	results, err := applicationTrustResults(applicationtrust.OperationInstall, applicationtrust.ContextNonInteractive, []cpak.ApplicationEnrolment{{
		Origin: "github.com/example/binary", Outcome: cpak.EnrolmentRecorded,
		Signature: cpak.EnrolmentSignature{Reason: cpak.ErrPackageUnsigned},
	}})
	if err != nil {
		t.Fatal(err)
	}
	output, writeErr := captureVerifySignatureStdout(t, func() error { return writeApplicationTrustResults(results) })
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	var envelope struct {
		SchemaVersion int                       `json:"schema_version"`
		Trust         []applicationtrust.Result `json:"trust"`
	}
	if err := json.Unmarshal(output, &envelope); err != nil {
		t.Fatalf("decode machine envelope %q: %v", output, err)
	}
	if envelope.SchemaVersion != applicationtrust.SchemaVersion || len(envelope.Trust) != 1 {
		t.Fatalf("machine envelope = %+v", envelope)
	}
	if err := envelope.Trust[0].Validate(); err != nil {
		t.Fatalf("machine envelope changed the portable result: %v", err)
	}
	if envelope.Trust[0].Final.ExitCode != applicationtrust.ExitAllowed {
		t.Fatalf("machine result and process outcome disagree: %+v", envelope.Trust[0].Final)
	}
}

func TestExplainDiagnosticsAreBoundedAndTerminalSafe(t *testing.T) {
	tainted := strings.Repeat("external", 100) + "\x00\x1b[2J"
	values := make([]string, 40)
	for index := range values {
		values[index] = tainted
	}
	bounded := boundedDecisionDiagnostics(values)
	if len(bounded) != 32 {
		t.Fatalf("bounded diagnostics count = %d, want 32", len(bounded))
	}
	for _, value := range bounded {
		if len([]byte(value)) > 512 {
			t.Fatalf("diagnostic is not bounded: %d bytes", len([]byte(value)))
		}
		if strings.ContainsAny(value, "\x00\x1b") {
			t.Fatalf("diagnostic retained a terminal control: %q", value)
		}
	}
}
