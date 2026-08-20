/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mirkobrombin/cpak/pkg/applicationtrust"
	"github.com/mirkobrombin/cpak/pkg/reputation"
	"github.com/mirkobrombin/cpak/pkg/systemauthority"
	"github.com/mirkobrombin/go-cli-builder/v3/pkg/cli"
	clilog "github.com/mirkobrombin/go-cli-builder/v3/pkg/log"
)

var commandReputationNow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func TestRecordedTrustReporterIncludesHistoricalReputationReasonCodes(t *testing.T) {
	var output bytes.Buffer
	logger := clilog.NewWriter(&output, &output)
	reportApplicationTrustResult(logger, applicationtrust.Result{
		Subject:      applicationtrust.Subject{Origin: "github.com/user/demo"},
		Verification: applicationtrust.Verification{Status: applicationtrust.VerificationVerified, EvidenceKind: "sigstore-bundle-v1", ReasonCode: "evidence-verified"},
		Publisher:    applicationtrust.Publisher{Status: applicationtrust.PublisherVerified, ID: "oidc:demo", ReasonCode: "publisher-verified"},
		Trust:        applicationtrust.Trust{Chain: "not-applicable", SigningTime: "current", Revocation: "not-applicable", ReasonCode: "not-applicable"},
		Reputation:   applicationtrust.Reputation{ProviderID: "cpak-poc", Status: "caution", Freshness: "fresh", ReasonCode: "recent-key-change"},
		Policy:       applicationtrust.Policy{SignatureMode: "optional", ReputationMode: "warn", Action: applicationtrust.PolicyWarn, Confirmation: applicationtrust.ConfirmationAccepted, ReasonCode: "reputation-warning"},
		Final:        applicationtrust.Final{Action: applicationtrust.FinalWarn, ReasonCode: "reputation-warning"},
	})
	text := output.String()
	for _, expected := range []string{"cpak-poc", "caution", "recent-key-change", "warn", "reputation-warning"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("diagnostics omitted %q: %s", expected, text)
		}
	}
}

type reputationCommandFixture struct {
	command       *SystemCmd
	store         systemauthority.ReputationStore
	authority     reputation.Authority
	privateKey    ed25519.PrivateKey
	authorityPath string
	snapshotPath  string
	snapshotHash  string
	publisherID   string
	output        *bytes.Buffer
}

func testReputationCommand(t *testing.T) reputationCommandFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := reputation.NewAuthority("cpak-poc", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	authorityDocument, err := reputation.MarshalAuthority(authority)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	authorityPath := filepath.Join(directory, "provider.json")
	if err := os.WriteFile(authorityPath, authorityDocument, 0o600); err != nil {
		t.Fatal(err)
	}
	publisherID := "x509-spki-sha256:1111111111111111111111111111111111111111111111111111111111111111"
	snapshotDocument, err := reputation.Sign(authority.ProviderID, privateKey, reputation.Signed{
		Sequence: 1, IssuedAt: commandReputationNow.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: commandReputationNow.Add(time.Hour).Format(time.RFC3339),
		Entries:   []reputation.Entry{{PublisherID: publisherID, Status: reputation.Established, ReasonCode: "verified-history"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(directory, "snapshot.json")
	if err := os.WriteFile(snapshotPath, snapshotDocument, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshotDocument)
	var output bytes.Buffer
	return reputationCommandFixture{
		command:   &SystemCmd{Base: cli.Base{Logger: clilog.NewWriter(&output, &output)}},
		store:     systemauthority.ReputationStore{Directory: filepath.Join(directory, "store", "v1"), OwnerUID: uint32(os.Getuid())},
		authority: authority, privateKey: privateKey, authorityPath: authorityPath,
		snapshotPath: snapshotPath, snapshotHash: hex.EncodeToString(digest[:]), publisherID: publisherID, output: &output,
	}
}

func useReputationCommandDependencies(t *testing.T, fixture reputationCommandFixture) {
	t.Helper()
	oldStore, oldEUID, oldEscalate := reputationStore, reputationEUID, reputationEscalate
	oldConfirm, oldClock := confirmReputation, reputationClock
	reputationStore = func() reputationAdminStore { return fixture.store }
	reputationClock = func() time.Time { return commandReputationNow }
	t.Cleanup(func() {
		reputationStore, reputationEUID, reputationEscalate = oldStore, oldEUID, oldEscalate
		confirmReputation, reputationClock = oldConfirm, oldClock
	})
}

func TestReputationProviderPreviewAndEscalationBindTheExactKey(t *testing.T) {
	fixture := testReputationCommand(t)
	useReputationCommandDependencies(t, fixture)
	fixture.command.Target = fixture.authorityPath
	if err := fixture.command.manageReputation("reputation-provider-preview"); err != nil {
		t.Fatal(err)
	}
	if text := fixture.output.String(); !strings.Contains(text, fixture.authority.ProviderID) || !strings.Contains(text, fixture.authority.KeyID) {
		t.Fatalf("preview omitted provider identity:\n%s", text)
	}
	reputationEUID = func() int { return 501 }
	confirmReputation = func(string) bool { return true }
	var got []string
	reputationEscalate = func(arguments ...string) error { got = append([]string(nil), arguments...); return nil }
	if err := fixture.command.manageReputation("reputation-provider-set"); err != nil {
		t.Fatal(err)
	}
	want := []string{"system", "reputation-provider-set", fixture.authorityPath, "--fingerprint", fixture.authority.KeyID, "--yes"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("escalation arguments = %q, want %q", got, want)
	}
}

func TestNonInteractiveReputationAdministrationRequiresTheExactFingerprint(t *testing.T) {
	fixture := testReputationCommand(t)
	useReputationCommandDependencies(t, fixture)
	reputationEUID = func() int { return 0 }
	confirmReputation = func(string) bool { t.Fatal("non-interactive command opened a prompt"); return false }
	fixture.command.Target = fixture.authorityPath
	fixture.command.Yes = true
	if err := fixture.command.manageReputation("reputation-provider-set"); err == nil || !strings.Contains(err.Error(), "--fingerprint") {
		t.Fatalf("got %v", err)
	}
	fixture.command.Fingerprint = fixture.authority.KeyID
	if err := fixture.command.manageReputation("reputation-provider-set"); err != nil {
		t.Fatal(err)
	}
}

func TestReputationCommandConfigureImportCheckAndClearLifecycle(t *testing.T) {
	fixture := testReputationCommand(t)
	useReputationCommandDependencies(t, fixture)
	reputationEUID = func() int { return 0 }
	confirmReputation = func(string) bool { t.Fatal("exact non-interactive operation prompted"); return false }
	fixture.command.Yes = true
	fixture.command.Target = fixture.authorityPath
	fixture.command.Fingerprint = fixture.authority.KeyID
	if err := fixture.command.manageReputation("reputation-provider-set"); err != nil {
		t.Fatal(err)
	}
	fixture.command.Target = fixture.snapshotPath
	fixture.command.Fingerprint = fixture.snapshotHash
	if err := fixture.command.manageReputation("reputation-import"); err != nil {
		t.Fatal(err)
	}
	fixture.command.Target = fixture.publisherID
	fixture.command.Fingerprint = ""
	if err := fixture.command.manageReputation("reputation-check"); err != nil {
		t.Fatal(err)
	}
	if text := fixture.output.String(); !strings.Contains(text, "established") || !strings.Contains(text, "verified-history") {
		t.Fatalf("check omitted reputation result:\n%s", text)
	}
	fixture.command.Fingerprint = fixture.authority.KeyID
	if err := fixture.command.manageReputation("reputation-provider-clear"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := fixture.store.Authority(); err != nil || found {
		t.Fatalf("provider survived clear: found=%v err=%v", found, err)
	}
}

func TestReputationSnapshotEscalationBindsPreviewedBytes(t *testing.T) {
	fixture := testReputationCommand(t)
	useReputationCommandDependencies(t, fixture)
	if _, err := fixture.store.SetAuthority(mustReadFile(t, fixture.authorityPath), fixture.authority.KeyID); err != nil {
		t.Fatal(err)
	}
	reputationEUID = func() int { return 501 }
	confirmReputation = func(string) bool { return true }
	var got []string
	reputationEscalate = func(arguments ...string) error { got = append([]string(nil), arguments...); return nil }
	fixture.command.Target = fixture.snapshotPath
	if err := fixture.command.manageReputation("reputation-import"); err != nil {
		t.Fatal(err)
	}
	want := []string{"system", "reputation-import", fixture.snapshotPath, "--fingerprint", fixture.snapshotHash, "--yes"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("escalation arguments = %q, want %q", got, want)
	}
}

func TestReputationCommandRejectsSymlinkedInput(t *testing.T) {
	fixture := testReputationCommand(t)
	useReputationCommandDependencies(t, fixture)
	link := filepath.Join(t.TempDir(), "provider.json")
	if err := os.Symlink(fixture.authorityPath, link); err != nil {
		t.Fatal(err)
	}
	fixture.command.Target = link
	if err := fixture.command.manageReputation("reputation-provider-preview"); err == nil {
		t.Fatal("symlinked provider input was accepted")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return document
}
