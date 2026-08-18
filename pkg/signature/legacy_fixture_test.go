/*
 * Copyright (c) 2025 Fabricators and Mirko Brombin <brombin94@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

const legacyFixtureDirectory = "../../testdata/application-trust-v2.6.0"

func readLegacyFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(legacyFixtureDirectory, name))
	if err != nil {
		t.Fatalf("read legacy fixture %s: %v", name, err)
	}
	return content
}

func TestLegacySignatureStateFixtureKeepsItsCanonicalBytes(t *testing.T) {
	document := readLegacyFixture(t, "signature-state-v1.json")
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	state := State{}
	if err := decoder.Decode(&state); err != nil {
		t.Fatalf("decode legacy signature state: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("legacy signature state contains trailing data: %v", err)
	}
	canonical, err := state.Canonical()
	if err != nil {
		t.Fatalf("canonicalize legacy signature state: %v", err)
	}
	want := readLegacyFixture(t, "signature-state-v1.canonical")
	if !bytes.Equal(canonical, want) {
		t.Fatalf("legacy state canonical bytes changed\n got: %q\nwant: %q", canonical, want)
	}
}

func TestLegacySigstoreFixtureReverifiesOffline(t *testing.T) {
	rootJSON := readLegacyFixture(t, "sigstore-trusted-root-v0.1.json")
	trusted, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		t.Fatalf("read legacy Sigstore test root: %v", err)
	}
	stateDocument := readLegacyFixture(t, "signature-state-v1.json")
	state := State{}
	if err := json.Unmarshal(stateDocument, &state); err != nil {
		t.Fatalf("decode legacy signature state: %v", err)
	}
	bundle := readLegacyFixture(t, "sigstore-bundle-v0.3.json")
	// The frozen test authority cannot issue SCTs. This uses the existing test
	// posture, which keeps the production transparency-log and RFC 3161 checks
	// while omitting only the SCT leg pinned by TestProductionPostureIsStrictlyStronger.
	verified, err := verifyWith(trusted, testVerificationOptions(), bundle, state)
	if err != nil {
		t.Fatalf("legacy Sigstore evidence no longer verifies: %v", err)
	}
	if verified.State != state {
		t.Fatalf("verified state %+v, want fixture state %+v", verified.State, state)
	}
	if verified.Identity.Issuer != githubActionsIssuer {
		t.Fatalf("verified issuer %q, want %q", verified.Identity.Issuer, githubActionsIssuer)
	}
}
