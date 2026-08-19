/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/cpak/pkg/signature"
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
