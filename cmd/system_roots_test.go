/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mirkobrombin/cpak/pkg/signature"
	"github.com/mirkobrombin/go-cli-builder/v3/pkg/cli"
	clilog "github.com/mirkobrombin/go-cli-builder/v3/pkg/log"
)

func testTrustRootCommand(t *testing.T) (*SystemCmd, signature.LocalRootStore, string, string, *bytes.Buffer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cpak command test root"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "root.der")
	if err := os.WriteFile(source, der, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(sum[:])
	boundary := t.TempDir()
	store := signature.LocalRootStore{
		Boundary: boundary, CodeSigningDirectory: filepath.Join(boundary, "code-signing.d"),
		TimestampingDirectory: filepath.Join(boundary, "timestamping.d"), OwnerUID: uint32(os.Getuid()),
	}
	var output bytes.Buffer
	command := &SystemCmd{Target: source, Purpose: signature.RootPurposeCodeSigning, Base: cli.Base{Logger: clilog.NewWriter(&output, &output)}}
	return command, store, source, fingerprint, &output
}

func useTrustRootCommandDependencies(t *testing.T, store signature.LocalRootStore) {
	t.Helper()
	oldStore, oldEUID, oldEscalate, oldConfirm := trustRootStore, trustRootEUID, trustRootEscalate, confirmTrustRoot
	trustRootStore = func() signature.LocalRootStore { return store }
	t.Cleanup(func() {
		trustRootStore, trustRootEUID, trustRootEscalate, confirmTrustRoot = oldStore, oldEUID, oldEscalate, oldConfirm
	})
}

func TestTrustRootPreviewShowsTheExactIdentityBeforeMutation(t *testing.T) {
	command, store, _, fingerprint, output := testTrustRootCommand(t)
	useTrustRootCommandDependencies(t, store)
	if err := command.manageTrustRoots("trust-root-preview"); err != nil {
		t.Fatal(err)
	}
	if text := output.String(); !strings.Contains(text, fingerprint) || !strings.Contains(text, "cpak command test root") {
		t.Fatalf("preview omitted the root identity:\n%s", text)
	}
	if _, err := os.Stat(store.CodeSigningDirectory); !os.IsNotExist(err) {
		t.Fatalf("preview mutated the trust store: %v", err)
	}
}

func TestTrustRootMutationEscalationBindsThePreviewedFingerprint(t *testing.T) {
	command, store, source, fingerprint, _ := testTrustRootCommand(t)
	useTrustRootCommandDependencies(t, store)
	trustRootEUID = func() int { return 501 }
	confirmTrustRoot = func(string) bool { return true }
	var got []string
	trustRootEscalate = func(arguments ...string) error { got = append([]string(nil), arguments...); return nil }
	if err := command.manageTrustRoots("trust-root-add"); err != nil {
		t.Fatal(err)
	}
	want := []string{"system", "trust-root-add", source, "--purpose", signature.RootPurposeCodeSigning, "--fingerprint", fingerprint, "--yes"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("escalation arguments = %q, want %q", got, want)
	}
}

func TestTrustRootCommandImportRemoveAndReaddLifecycle(t *testing.T) {
	command, store, source, fingerprint, _ := testTrustRootCommand(t)
	useTrustRootCommandDependencies(t, store)
	trustRootEUID = func() int { return 0 }
	command.Yes = true
	command.Fingerprint = fingerprint
	if err := command.manageTrustRoots("trust-root-add"); err != nil {
		t.Fatal(err)
	}
	if err := command.manageTrustRoots("trust-root-add"); err == nil {
		t.Fatal("duplicate import succeeded")
	}
	command.Target = fingerprint
	if err := command.manageTrustRoots("trust-root-remove"); err != nil {
		t.Fatal(err)
	}
	command.Target = source
	if err := command.manageTrustRoots("trust-root-add"); err != nil {
		t.Fatal(err)
	}
}
