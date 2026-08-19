/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package systemauthority

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkobrombin/cpak/pkg/reputation"
)

var reputationNow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func testReputationStore(t *testing.T) ReputationStore {
	t.Helper()
	return ReputationStore{Directory: filepath.Join(t.TempDir(), "reputation", "v1"), OwnerUID: uint32(os.Getuid())}
}

func testReputationAuthority(t *testing.T, providerID string) (reputation.Authority, ed25519.PrivateKey, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := reputation.NewAuthority(providerID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	document, err := reputation.MarshalAuthority(authority)
	if err != nil {
		t.Fatal(err)
	}
	return authority, privateKey, document
}

func testReputationDocument(t *testing.T, providerID string, key ed25519.PrivateKey, sequence uint64, issued, expires time.Time, entries ...reputation.Entry) []byte {
	t.Helper()
	document, err := reputation.Sign(providerID, key, reputation.Signed{
		Sequence: sequence, IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339), Entries: entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestReputationStoreRequiresThePreviewedProviderKey(t *testing.T) {
	store := testReputationStore(t)
	authority, _, document := testReputationAuthority(t, "cpak-poc")
	for _, keyID := range []string{"", "ed25519-sha256:wrong"} {
		if _, err := store.SetAuthority(document, keyID); err == nil {
			t.Fatalf("provider was configured with unconfirmed key id %q", keyID)
		}
	}
	configured, err := store.SetAuthority(document, authority.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if configured.ProviderID != authority.ProviderID || configured.KeyID != authority.KeyID {
		t.Fatalf("configured authority: got %+v, want %+v", configured, authority)
	}
	loaded, found, err := store.Authority()
	if err != nil || !found || loaded.KeyID != authority.KeyID {
		t.Fatalf("load authority: got %+v, %v, %v", loaded, found, err)
	}
}

func TestReputationStoreImportsAndServesOnlyAuthenticatedSnapshots(t *testing.T) {
	store := testReputationStore(t)
	authority, privateKey, authorityDocument := testReputationAuthority(t, "cpak-poc")
	if _, err := store.SetAuthority(authorityDocument, authority.KeyID); err != nil {
		t.Fatal(err)
	}
	publisherID := "x509-spki-sha256:1111111111111111111111111111111111111111111111111111111111111111"
	document := testReputationDocument(t, authority.ProviderID, privateKey, 7, reputationNow.Add(-time.Hour), reputationNow.Add(time.Hour), reputation.Entry{
		PublisherID: publisherID, Status: reputation.Established, ReasonCode: "verified-history",
	})
	imported, err := store.Import(document, reputationNow)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Sequence != 7 {
		t.Fatalf("imported sequence %d", imported.Sequence)
	}
	result, err := store.Lookup(publisherID, reputationNow)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != reputation.Established || result.ReasonCode != "verified-history" || result.ProviderID != authority.ProviderID {
		t.Fatalf("lookup: got %+v", result)
	}
}

func TestReputationStoreRejectsRollbackEvenAfterActiveSnapshotExpires(t *testing.T) {
	store := testReputationStore(t)
	authority, privateKey, authorityDocument := testReputationAuthority(t, "cpak-poc")
	if _, err := store.SetAuthority(authorityDocument, authority.KeyID); err != nil {
		t.Fatal(err)
	}
	active := testReputationDocument(t, authority.ProviderID, privateKey, 10, reputationNow.Add(-2*time.Hour), reputationNow.Add(-time.Hour))
	path, _ := store.path(reputationSnapshotFile)
	if err := writeReputationFile(path, active, 0644); err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []uint64{9, 10} {
		offered := testReputationDocument(t, authority.ProviderID, privateKey, sequence, reputationNow.Add(-time.Minute), reputationNow.Add(time.Hour))
		if _, err := store.Import(offered, reputationNow); !errors.Is(err, ErrReputationRollback) {
			t.Fatalf("sequence %d: got %v", sequence, err)
		}
	}
	newer := testReputationDocument(t, authority.ProviderID, privateKey, 11, reputationNow.Add(-time.Minute), reputationNow.Add(time.Hour))
	if _, err := store.Import(newer, reputationNow); err != nil {
		t.Fatalf("newer sequence was rejected: %v", err)
	}
}

func TestInvalidSnapshotNeverReplacesTheActiveRecord(t *testing.T) {
	store := testReputationStore(t)
	authority, privateKey, authorityDocument := testReputationAuthority(t, "cpak-poc")
	if _, err := store.SetAuthority(authorityDocument, authority.KeyID); err != nil {
		t.Fatal(err)
	}
	active := testReputationDocument(t, authority.ProviderID, privateKey, 1, reputationNow.Add(-time.Hour), reputationNow.Add(time.Hour))
	if _, err := store.Import(active, reputationNow); err != nil {
		t.Fatal(err)
	}
	path, _ := store.path(reputationSnapshotFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongKey, _ := testReputationAuthority(t, "cpak-poc")
	invalid := testReputationDocument(t, authority.ProviderID, wrongKey, 2, reputationNow.Add(-time.Minute), reputationNow.Add(time.Hour))
	if _, err := store.Import(invalid, reputationNow); !errors.Is(err, reputation.ErrInvalidSnapshot) {
		t.Fatalf("got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("invalid snapshot changed the active record")
	}
}

func TestInterruptedSnapshotReplacementLeavesThePriorRecord(t *testing.T) {
	store := testReputationStore(t)
	authority, privateKey, authorityDocument := testReputationAuthority(t, "cpak-poc")
	if _, err := store.SetAuthority(authorityDocument, authority.KeyID); err != nil {
		t.Fatal(err)
	}
	active := testReputationDocument(t, authority.ProviderID, privateKey, 1, reputationNow.Add(-time.Hour), reputationNow.Add(time.Hour))
	if _, err := store.Import(active, reputationNow); err != nil {
		t.Fatal(err)
	}
	path, _ := store.path(reputationSnapshotFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := writeReputationFile
	writeReputationFile = func(string, []byte, os.FileMode) error { return errors.New("injected interruption") }
	t.Cleanup(func() { writeReputationFile = original })
	newer := testReputationDocument(t, authority.ProviderID, privateKey, 2, reputationNow.Add(-time.Minute), reputationNow.Add(time.Hour))
	if _, err := store.Import(newer, reputationNow); err == nil {
		t.Fatal("interrupted replacement succeeded")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("interrupted replacement changed the active record")
	}
}

func TestChangingProviderInvalidatesThePriorSnapshot(t *testing.T) {
	store := testReputationStore(t)
	first, key, firstDocument := testReputationAuthority(t, "first-provider")
	if _, err := store.SetAuthority(firstDocument, first.KeyID); err != nil {
		t.Fatal(err)
	}
	snapshot := testReputationDocument(t, first.ProviderID, key, 1, reputationNow.Add(-time.Hour), reputationNow.Add(time.Hour))
	if _, err := store.Import(snapshot, reputationNow); err != nil {
		t.Fatal(err)
	}
	second, _, secondDocument := testReputationAuthority(t, "second-provider")
	if _, err := store.SetAuthority(secondDocument, second.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.Current(reputationNow); err != nil || found {
		t.Fatalf("snapshot survived provider change: found=%v err=%v", found, err)
	}
	result, err := store.Lookup("x509-spki-sha256:1111111111111111111111111111111111111111111111111111111111111111", reputationNow)
	if err != nil || result.Status != reputation.Unavailable || result.ReasonCode != "snapshot-not-installed" {
		t.Fatalf("lookup after provider change: %+v, %v", result, err)
	}
}

func TestReputationStoreFailsClosedOnUnsafeFilesystemState(t *testing.T) {
	store := testReputationStore(t)
	authority, _, document := testReputationAuthority(t, "cpak-poc")
	if _, err := store.SetAuthority(document, authority.KeyID); err != nil {
		t.Fatal(err)
	}
	path, _ := store.path(reputationAuthorityFile)
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Authority(); err == nil {
		t.Fatal("writable provider authority was trusted")
	}
}

func TestAbsentProviderAndSnapshotAreDifferentUnavailableResults(t *testing.T) {
	store := testReputationStore(t)
	publisherID := "x509-spki-sha256:1111111111111111111111111111111111111111111111111111111111111111"
	result, err := store.Lookup(publisherID, reputationNow)
	if err != nil || result.Status != reputation.Unavailable || result.ReasonCode != "provider-not-configured" {
		t.Fatalf("absent provider: %+v, %v", result, err)
	}
	authority, _, document := testReputationAuthority(t, "cpak-poc")
	if _, err := store.SetAuthority(document, authority.KeyID); err != nil {
		t.Fatal(err)
	}
	result, err = store.Lookup(publisherID, reputationNow)
	if err != nil || result.Status != reputation.Unavailable || result.ReasonCode != "snapshot-not-installed" {
		t.Fatalf("absent snapshot: %+v, %v", result, err)
	}
}
