/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package reputation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func testPublisher(seed string) string {
	return "x509-spki-sha256:" + strings.Repeat("0", 64-len(seed)) + seed
}

func testSnapshot(t *testing.T, entries ...Entry) ([]byte, Authority, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority("cpak-poc", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	document, err := Sign(authority.ProviderID, privateKey, Signed{
		Sequence:  42,
		IssuedAt:  testNow.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
		Entries:   entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return document, authority, privateKey
}

func TestValidFreshSnapshotVerifiesAndLooksUpEveryStatus(t *testing.T) {
	entries := []Entry{
		{PublisherID: testPublisher("1"), Status: Unknown, ReasonCode: "history-not-found"},
		{PublisherID: testPublisher("2"), Status: Established, ReasonCode: "verified-history"},
		{PublisherID: testPublisher("3"), Status: Caution, ReasonCode: "recent-key-change"},
		{PublisherID: testPublisher("4"), Status: Blocked, ReasonCode: "provider-blocked"},
	}
	document, authority, _ := testSnapshot(t, entries...)
	snapshot, err := Verify(document, authority, testNow)
	if err != nil {
		t.Fatal(err)
	}
	provider := NewOfflineProvider(snapshot)
	for _, entry := range entries {
		result := provider.Lookup(entry.PublisherID)
		if result.Status != entry.Status || result.ReasonCode != entry.ReasonCode {
			t.Fatalf("lookup %s: got %+v, want status %s and reason %s", entry.PublisherID, result, entry.Status, entry.ReasonCode)
		}
		if result.ProviderID != authority.ProviderID || result.Sequence != 42 || result.IssuedAt.IsZero() || result.ExpiresAt.IsZero() {
			t.Fatalf("lookup dropped authenticated snapshot metadata: %+v", result)
		}
	}
	missing := provider.Lookup(testPublisher("9"))
	if missing.Status != Unknown || missing.ReasonCode != "publisher-not-listed" {
		t.Fatalf("absent publisher: got %+v", missing)
	}
	unavailable := UnavailableResult(authority.ProviderID, testPublisher("9"), "provider-not-configured")
	if unavailable.Status != Unavailable || unavailable.ReasonCode != "provider-not-configured" {
		t.Fatalf("unavailable provider: got %+v", unavailable)
	}
}

func TestSnapshotSignatureBindsCanonicalSignedObject(t *testing.T) {
	document, authority, _ := testSnapshot(t, Entry{
		PublisherID: testPublisher("1"), Status: Established, ReasonCode: "verified-history",
	})
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatal(err)
	}
	signed := decoded["signed"].(map[string]any)
	signed["sequence"] = float64(43)
	tampered, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tampered, authority, testNow); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("tampered signed object: got %v", err)
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(document, &envelope); err != nil {
		t.Fatal(err)
	}
	prettySigned := bytes.ReplaceAll(envelope["signed"], []byte(","), []byte(",\n    "))
	envelope["signed"] = prettySigned
	reformatted, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(reformatted, authority, testNow); err != nil {
		t.Fatalf("RFC 8785-equivalent formatting changed the signature input: %v", err)
	}
}

func TestSnapshotRejectsWrongAuthorityAndKey(t *testing.T) {
	document, authority, _ := testSnapshot(t)
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewAuthority(authority.ProviderID, otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Authority{
		"wrong provider": {ProviderID: "another-provider", KeyID: authority.KeyID, PublicKey: authority.PublicKey},
		"wrong key":      other,
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(document, candidate, testNow); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestSnapshotRejectsUnsupportedAmbiguousAndUnsafeContent(t *testing.T) {
	document, authority, privateKey := testSnapshot(t)
	cases := map[string][]byte{
		"duplicate outer key": bytes.Replace(document, []byte(`"abi": 1`), []byte(`"abi": 1, "abi": 1`), 1),
		"unknown outer key":   bytes.Replace(document, []byte(`"abi": 1`), []byte(`"abi": 1, "future": true`), 1),
		"multiple values":     append(append([]byte(nil), document...), []byte("{}")...),
		"unsupported abi":     bytes.Replace(document, []byte(`"abi": 1`), []byte(`"abi": 2`), 1),
		"oversized":           bytes.Repeat([]byte(" "), MaxSnapshotSize+1),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(candidate, authority, testNow); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("got %v", err)
			}
		})
	}

	invalidSigned := map[string]Signed{
		"zero sequence": {
			IssuedAt: testNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
		},
		"unsafe reason": {
			Sequence: 1, IssuedAt: testNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
			Entries: []Entry{{PublisherID: testPublisher("1"), Status: Established, ReasonCode: "unsafe\nreason"}},
		},
		"unsupported status": {
			Sequence: 1, IssuedAt: testNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
			Entries: []Entry{{PublisherID: testPublisher("1"), Status: Status("safe"), ReasonCode: "made-up"}},
		},
		"duplicate publisher": {
			Sequence: 1, IssuedAt: testNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
			Entries: []Entry{
				{PublisherID: testPublisher("1"), Status: Unknown, ReasonCode: "first"},
				{PublisherID: testPublisher("1"), Status: Blocked, ReasonCode: "second"},
			},
		},
		"unsorted publishers": {
			Sequence: 1, IssuedAt: testNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
			Entries: []Entry{
				{PublisherID: testPublisher("2"), Status: Unknown, ReasonCode: "second"},
				{PublisherID: testPublisher("1"), Status: Unknown, ReasonCode: "first"},
			},
		},
		"noncanonical time": {
			Sequence: 1, IssuedAt: "2026-08-19T11:00:00+00:00", ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
		},
		"backwards validity": {
			Sequence: 1, IssuedAt: testNow.Format(time.RFC3339), ExpiresAt: testNow.Add(-time.Hour).Format(time.RFC3339),
		},
	}
	for name, signed := range invalidSigned {
		t.Run(name, func(t *testing.T) {
			if _, err := Sign(authority.ProviderID, privateKey, signed); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestSnapshotFreshnessBoundariesAreUnavailableNotUnknown(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority("cpak-poc", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Signed{
		"future": {
			Sequence: 1, IssuedAt: testNow.Add(time.Second).Format(time.RFC3339), ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339),
		},
		"at expiry": {
			Sequence: 2, IssuedAt: testNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: testNow.Format(time.RFC3339),
		},
	}
	for name, signed := range cases {
		t.Run(name, func(t *testing.T) {
			document, err := Sign(authority.ProviderID, privateKey, signed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(document, authority, testNow); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestAuthorityAndPublisherIdentifiersAreExact(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, providerID := range []string{"", "Uppercase", "unsafe/provider", strings.Repeat("a", 65)} {
		if _, err := NewAuthority(providerID, publicKey); !errors.Is(err, ErrInvalidSnapshot) {
			t.Fatalf("provider %q: got %v", providerID, err)
		}
	}
	if KeyID(publicKey) == "" || !strings.HasPrefix(KeyID(publicKey), "ed25519-sha256:") {
		t.Fatalf("unexpected key id %q", KeyID(publicKey))
	}
	authority, err := NewAuthority("cpak-poc", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	document, err := MarshalAuthority(authority)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAuthority(document)
	if err != nil || parsed.ProviderID != authority.ProviderID || parsed.KeyID != authority.KeyID || !bytes.Equal(parsed.PublicKey, authority.PublicKey) {
		t.Fatalf("authority round trip: got %+v, %v", parsed, err)
	}
	for name, candidate := range map[string][]byte{
		"duplicate": bytes.Replace(document, []byte(`"abi": 1`), []byte(`"abi": 1, "abi": 1`), 1),
		"unknown":   bytes.Replace(document, []byte(`"abi": 1`), []byte(`"abi": 1, "future": true`), 1),
		"trailing":  append(append([]byte(nil), document...), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAuthority(candidate); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
