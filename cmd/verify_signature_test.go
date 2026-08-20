/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/cpak/pkg/applicationtrust"
	"github.com/mirkobrombin/cpak/pkg/signature"
	"github.com/mirkobrombin/cpak/pkg/types"
)

func TestVerifySignatureSelectsAnExplicitEvidenceProfile(t *testing.T) {
	state := signature.State{
		ABI: signature.ABIVersion, Origin: "example.org/publisher/application",
		ManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImageDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Generation:     1,
	}
	payload := []byte("evidence")
	tests := []struct {
		input string
		kind  signature.EvidenceKind
		media string
	}{
		{input: "", kind: signature.EvidenceSigstoreBundle, media: signature.SigstoreBundleMediaType},
		{input: "sigstore", kind: signature.EvidenceSigstoreBundle, media: signature.SigstoreBundleMediaType},
		{input: "x509-cms", kind: signature.EvidenceX509CMS, media: signature.X509CMSMediaType},
	}
	for _, test := range tests {
		command := VerifySignatureCmd{EvidenceKind: test.input}
		evidence, err := command.evidence(state, payload)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Kind != test.kind || evidence.MediaType != test.media || string(evidence.Payload) != string(payload) || evidence.State != state {
			t.Fatalf("profile %q = %+v", test.input, evidence)
		}
	}
	if _, err := (&VerifySignatureCmd{EvidenceKind: "unknown"}).evidence(state, payload); err == nil {
		t.Fatal("unknown evidence profile was accepted")
	}
}

func TestVerifySignatureJSONReportsInvalidEvidenceWithTheStableExitCode(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "signature.p7s")
	if err := os.WriteFile(bundle, []byte("not CMS"), 0o644); err != nil {
		t.Fatal(err)
	}
	command := VerifySignatureCmd{
		Bundle:         bundle,
		Origin:         "registry.example/org/application",
		ManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImageDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Generation:     1,
		EvidenceKind:   "x509-cms",
		JSON:           true,
	}
	output, runErr := captureVerifySignatureStdout(t, command.Run)
	var exitErr *types.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.Code != applicationtrust.ExitInvalid {
		t.Fatalf("run error = %v", runErr)
	}
	var result applicationtrust.Result
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode JSON %q: %v", output, err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("invalid portable result: %v", err)
	}
	if result.Final.Action != applicationtrust.FinalInvalid || result.Final.ExitCode != applicationtrust.ExitInvalid || result.Verification.EvidenceKind != string(signature.EvidenceX509CMS) {
		t.Fatalf("result = %+v", result)
	}
}

func captureVerifySignatureStdout(t *testing.T, run func() error) ([]byte, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = previous }()

	runErr := run()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return output, runErr
}

func TestVerifySignatureReadsTheCanonicalStateProducedByCpakSign(t *testing.T) {
	state := signature.State{
		ABI: signature.ABIVersion, Origin: "example.org/publisher/application",
		ManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImageDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Generation:     2,
	}
	encoded, err := state.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cpak-state")
	if err = os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := (&VerifySignatureCmd{State: path}).signedState()
	if err != nil {
		t.Fatal(err)
	}
	if parsed != state {
		t.Fatalf("parsed state = %+v", parsed)
	}
}
