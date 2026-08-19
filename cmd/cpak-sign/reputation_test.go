/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkobrombin/cpak/pkg/reputation"
)

func generateReputationFixture(t *testing.T, directory, name string) (string, string, string) {
	t.Helper()
	passphrasePath := filepath.Join(directory, name+"-passphrase")
	if err := os.WriteFile(passphrasePath, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, name+"-key.pem")
	authorityPath := filepath.Join(directory, name+"-authority.json")
	if err := generateReputationKey([]string{
		"--provider", name, "--output-key", keyPath, "--output-authority", authorityPath,
		"--key-passphrase-file", passphrasePath,
	}); err != nil {
		t.Fatal(err)
	}
	return keyPath, authorityPath, passphrasePath
}

func TestReputationKeygenAndSignerProduceVerifierEvidence(t *testing.T) {
	directory := t.TempDir()
	keyPath, authorityPath, passphrasePath := generateReputationFixture(t, directory, "cpak-poc")
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode is %o", keyInfo.Mode().Perm())
	}
	authorityDocument, err := os.ReadFile(authorityPath)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := reputation.ParseAuthority(authorityDocument)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	publisherID := "x509-spki-sha256:1111111111111111111111111111111111111111111111111111111111111111"
	payloadPath := filepath.Join(directory, "payload.json")
	payload := `{
  "sequence": 1,
  "issued_at": "` + now.Add(-time.Hour).Format(time.RFC3339) + `",
  "expires_at": "` + now.Add(time.Hour).Format(time.RFC3339) + `",
  "entries": [{
    "publisher_id": "` + publisherID + `",
    "status": "established",
    "reason_code": "verified-history"
  }]
}`
	if err := os.WriteFile(payloadPath, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "snapshot.json")
	if err := signReputation([]string{
		"--authority", authorityPath, "--key", keyPath, "--key-passphrase-file", passphrasePath,
		"--payload", payloadPath, "--output", outputPath,
	}); err != nil {
		t.Fatal(err)
	}
	document, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := reputation.Verify(document, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	result := reputation.NewOfflineProvider(snapshot).Lookup(publisherID)
	if result.Status != reputation.Established || result.ReasonCode != "verified-history" {
		t.Fatalf("signed snapshot lookup: %+v", result)
	}
	if err := signReputation([]string{
		"--authority", authorityPath, "--key", keyPath, "--key-passphrase-file", passphrasePath,
		"--payload", payloadPath, "--output", outputPath,
	}); err == nil {
		t.Fatal("signer overwrote an existing snapshot")
	}
}

func TestReputationSignerRejectsMismatchedKeyAndAmbiguousPayload(t *testing.T) {
	directory := t.TempDir()
	_, authorityPath, passphrasePath := generateReputationFixture(t, directory, "first-provider")
	wrongKeyPath, _, wrongPassphrasePath := generateReputationFixture(t, directory, "second-provider")
	payloadPath := filepath.Join(directory, "payload.json")
	payload := `{"sequence":1,"sequence":2,"issued_at":"2026-08-19T11:00:00Z","expires_at":"2026-08-19T13:00:00Z","entries":[]}`
	if err := os.WriteFile(payloadPath, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signReputation([]string{
		"--authority", authorityPath, "--key", wrongKeyPath, "--key-passphrase-file", wrongPassphrasePath,
		"--payload", payloadPath, "--output", filepath.Join(directory, "ambiguous.json"),
	}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("ambiguous payload: got %v", err)
	}
	validPayload := `{"sequence":1,"issued_at":"2026-08-19T11:00:00Z","expires_at":"2026-08-19T13:00:00Z","entries":[]}`
	if err := os.WriteFile(payloadPath, []byte(validPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signReputation([]string{
		"--authority", authorityPath, "--key", wrongKeyPath, "--key-passphrase-file", wrongPassphrasePath,
		"--payload", payloadPath, "--output", filepath.Join(directory, "wrong-key.json"),
	}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key: got %v", err)
	}
	_ = passphrasePath
}

func TestReputationKeygenRefusesUnsafePassphraseFile(t *testing.T) {
	directory := t.TempDir()
	passphrasePath := filepath.Join(directory, "passphrase")
	if err := os.WriteFile(passphrasePath, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := generateReputationKey([]string{
		"--provider", "cpak-poc", "--output-key", filepath.Join(directory, "key.pem"),
		"--output-authority", filepath.Join(directory, "authority.json"), "--key-passphrase-file", passphrasePath,
	})
	if err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("unsafe passphrase file: got %v", err)
	}
}
