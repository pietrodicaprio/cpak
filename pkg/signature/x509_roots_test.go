/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSelfSignedRoot(t *testing.T, commonName string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"cpak test"}, CommonName: commonName},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}

func validTestRootBundle(t *testing.T) RootBundle {
	t.Helper()
	cert, der := testSelfSignedRoot(t, "test root")
	return RootBundle{
		ABI: RootBundleABIVersion,
		Sources: []RootBundleSource{{
			Name: "test source", URL: "https://example.invalid/roots",
			RetrievedAt: "2026-08-19T00:00:00Z", SHA256: strings.Repeat("1", 64), License: "test-only",
		}},
		Roots: []RootBundleEntry{{
			SHA256: fingerprintOf(cert), Subject: cert.Subject.String(),
			Purposes: []string{RootPurposeCodeSigning}, DER: der,
		}},
	}
}

func encodeRootBundle(t *testing.T, bundle RootBundle) []byte {
	t.Helper()
	document, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestEmbeddedRootBundleIsStrictAndFingerprintVerified(t *testing.T) {
	trust, err := LoadEmbeddedX509Trust()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"7e76260ae69a55d3f060b0fd18b2a8c01443c87b60791030c9fa0b0585101a38",
		"8f6371d8cc5aa7ca149667a98b5496398951e4319f7afbcc6a660d673e438d0b",
	}
	got := SortedRootFingerprints(trust)
	if len(got) != len(want) {
		t.Fatalf("embedded roots = %v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("embedded roots = %v", got)
		}
	}
	if len(trust.CodeSigningRoots.Subjects()) != 2 || len(trust.TimestampRoots.Subjects()) != 0 {
		t.Fatalf("purpose pools were merged: code=%d timestamp=%d", len(trust.CodeSigningRoots.Subjects()), len(trust.TimestampRoots.Subjects()))
	}
}

func TestEmbeddedSectigoRootsCarryReviewedProvenance(t *testing.T) {
	document, err := EmbeddedRootBundle()
	if err != nil {
		t.Fatal(err)
	}
	var bundle RootBundle
	if err := json.Unmarshal(document, &bundle); err != nil {
		t.Fatal(err)
	}
	wantSources := map[string]string{
		"https://ccadb.my.salesforce-sites.com/microsoft/IncludedRootsPEMTxtForMSFT?MicrosoftEKUs=Code+Signing":     "7686156ec2528a6dc6ee1a03afef15a9d626420e6ba73e7d4d8e050326c684e1",
		"https://www.sectigo.com/knowledge-base/detail/sectigo-new-rsa-and-ecc-root-intermediate-certificates-2025": "349d4f2b5b95486085c82343811525586012bfe59f13d3b478cddb45017c7c80",
	}
	if len(bundle.Sources) != len(wantSources) {
		t.Fatalf("provenance sources = %+v", bundle.Sources)
	}
	for _, source := range bundle.Sources {
		if wantSources[source.URL] != source.SHA256 || source.RetrievedAt != "2026-08-19T07:20:25Z" || source.License == "" {
			t.Fatalf("unreviewed provenance source = %+v", source)
		}
	}
	wantSubjects := map[string]string{
		"7e76260ae69a55d3f060b0fd18b2a8c01443c87b60791030c9fa0b0585101a38": "Sectigo Public Code Signing Root R46",
		"8f6371d8cc5aa7ca149667a98b5496398951e4319f7afbcc6a660d673e438d0b": "Sectigo Public Code Signing Root E46",
	}
	for _, root := range bundle.Roots {
		if !strings.Contains(root.Subject, wantSubjects[root.SHA256]) {
			t.Fatalf("embedded root does not match reviewed Sectigo identity: %+v", root)
		}
	}
}

func TestRootBundleFailsClosed(t *testing.T) {
	tests := map[string]func(*RootBundle){
		"future ABI":           func(bundle *RootBundle) { bundle.ABI++ },
		"fingerprint mismatch": func(bundle *RootBundle) { bundle.Roots[0].SHA256 = strings.Repeat("0", 64) },
		"unsafe subject":       func(bundle *RootBundle) { bundle.Roots[0].Subject = "Root\nInjected" },
		"duplicate root":       func(bundle *RootBundle) { bundle.Roots = append(bundle.Roots, bundle.Roots[0]) },
		"unknown purpose":      func(bundle *RootBundle) { bundle.Roots[0].Purposes = []string{"tls"} },
		"duplicate purpose": func(bundle *RootBundle) {
			bundle.Roots[0].Purposes = []string{RootPurposeCodeSigning, RootPurposeCodeSigning}
		},
		"missing provenance":     func(bundle *RootBundle) { bundle.Sources = nil },
		"invalid source digest":  func(bundle *RootBundle) { bundle.Sources[0].SHA256 = "sha256:1234" },
		"insecure source URL":    func(bundle *RootBundle) { bundle.Sources[0].URL = "http://example.invalid/roots" },
		"noncanonical timestamp": func(bundle *RootBundle) { bundle.Sources[0].RetrievedAt = "2026-08-19T00:00:00.1Z" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			bundle := validTestRootBundle(t)
			mutate(&bundle)
			if _, err := ParseRootBundle(encodeRootBundle(t, bundle)); err == nil {
				t.Fatal("invalid root bundle was accepted")
			}
		})
	}
	bundle := validTestRootBundle(t)
	document := encodeRootBundle(t, bundle)
	document = append(document[:len(document)-1], []byte(`,"abi":1}`)...)
	if _, err := ParseRootBundle(document); err == nil {
		t.Fatal("duplicate JSON key was accepted")
	}

	issueInvalid := func(isCA, selfSigned bool) RootBundleEntry {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		parentKey := key
		template := &x509.Certificate{
			SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "invalid root"},
			NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		parent := *template
		if !selfSigned {
			parentKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			parent.Subject = pkix.Name{CommonName: "different issuer"}
			parent.SerialNumber = big.NewInt(12)
		}
		der, err := x509.CreateCertificate(rand.Reader, template, &parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return RootBundleEntry{SHA256: fingerprintOf(cert), Subject: cert.Subject.String(), Purposes: []string{RootPurposeCodeSigning}, DER: der}
	}
	for name, entry := range map[string]RootBundleEntry{
		"non-CA": issueInvalid(false, true), "not self-signed": issueInvalid(true, false),
	} {
		t.Run(name, func(t *testing.T) {
			bundle := validTestRootBundle(t)
			bundle.Roots[0] = entry
			if _, err := ParseRootBundle(encodeRootBundle(t, bundle)); err == nil {
				t.Fatal("invalid root certificate was accepted")
			}
		})
	}
}

func TestLocalRootImportRequiresThePreviewedFingerprintAndKeepsPurposesSeparate(t *testing.T) {
	root := t.TempDir()
	store := LocalRootStore{
		Boundary: root, CodeSigningDirectory: filepath.Join(root, "code-signing.d"),
		TimestampingDirectory: filepath.Join(root, "timestamping.d"), OwnerUID: uint32(os.Getuid()),
	}
	cert, der := testSelfSignedRoot(t, "local timestamp root")
	source := filepath.Join(t.TempDir(), "root.der")
	if err := os.WriteFile(source, der, 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err := store.Preview(source)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Fingerprint != fingerprintOf(cert) || !strings.Contains(preview.Subject, "local timestamp root") {
		t.Fatalf("preview = %+v", preview)
	}
	if _, err := store.Import(source, RootPurposeTimestamping, strings.Repeat("0", 64)); err == nil {
		t.Fatal("a root changed after preview was imported")
	}
	if _, err := store.Import(source, RootPurposeTimestamping, preview.Fingerprint); err != nil {
		t.Fatal(err)
	}
	admitted := filepath.Join(store.TimestampingDirectory, preview.Fingerprint+".der")
	if info, err := os.Stat(admitted); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("admitted root mode = %v, %v", info, err)
	}
	for _, directory := range []string{store.Boundary, store.TimestampingDirectory} {
		if info, err := os.Stat(directory); err != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("trust directory %q mode = %v, %v", directory, info, err)
		}
	}
	trust, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(trust.CodeSigningRoots.Subjects()) != 2 || len(trust.TimestampRoots.Subjects()) != 1 {
		t.Fatalf("purpose pools were merged: code=%d timestamp=%d", len(trust.CodeSigningRoots.Subjects()), len(trust.TimestampRoots.Subjects()))
	}
	if trust.Roots[preview.Fingerprint].Source != RootSourceLocal {
		t.Fatalf("local root source = %q", trust.Roots[preview.Fingerprint].Source)
	}
	if err := os.Chmod(admitted, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("unprivileged-writable root file was accepted")
	}
	if err := os.Chmod(admitted, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(source, RootPurposeTimestamping, preview.Fingerprint); err == nil {
		t.Fatal("duplicate root import was accepted")
	}
	if err := store.Remove(RootPurposeTimestamping, preview.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(RootPurposeTimestamping, preview.Fingerprint); !os.IsNotExist(err) {
		t.Fatalf("second removal = %v", err)
	}
}

func TestRootImportHasAnAtomicCommitPointAcrossFailures(t *testing.T) {
	boundary := t.TempDir()
	if err := os.Chmod(boundary, 0o755); err != nil {
		t.Fatal(err)
	}
	store := LocalRootStore{Boundary: boundary, CodeSigningDirectory: filepath.Join(boundary, "code-signing.d"), OwnerUID: uint32(os.Getuid())}
	cert, der := testSelfSignedRoot(t, "atomic root")
	source := filepath.Join(t.TempDir(), "root.der")
	if err := os.WriteFile(source, der, 0o600); err != nil {
		t.Fatal(err)
	}
	oldLink, oldSync := linkRootFile, syncTrustRootPath
	t.Cleanup(func() { linkRootFile, syncTrustRootPath = oldLink, oldSync })
	linkRootFile = func(_, _ string) error { return errors.New("injected pre-commit failure") }
	if _, err := store.Import(source, RootPurposeCodeSigning, fingerprintOf(cert)); err == nil {
		t.Fatal("pre-commit failure was hidden")
	}
	entries, err := os.ReadDir(store.CodeSigningDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("pre-commit failure left files behind: %+v", entries)
	}

	linkRootFile = oldLink
	syncTrustRootPath = func(string) error { return errors.New("injected post-commit durability failure") }
	if _, err := store.Import(source, RootPurposeCodeSigning, fingerprintOf(cert)); err == nil {
		t.Fatal("post-commit durability failure was hidden")
	}
	// Once the no-overwrite link commit happened, interruption can leave only
	// the complete DER root, never a partial destination.
	trust, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if trust.Roots[fingerprintOf(cert)].Source != RootSourceLocal {
		t.Fatalf("post-commit root is not a complete admitted local root: %+v", trust.Roots[fingerprintOf(cert)])
	}
}

func TestLocalRootStoreRejectsFilesystemConfusion(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "code-signing.d")
	if err := os.Symlink(realDirectory, symlink); err != nil {
		t.Fatal(err)
	}
	store := LocalRootStore{Boundary: root, CodeSigningDirectory: symlink, OwnerUID: uint32(os.Getuid())}
	if _, err := store.Load(); err == nil {
		t.Fatal("symlinked trust directory was accepted")
	}
	if err := os.Remove(symlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(symlink, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(symlink, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("world-writable trust directory was accepted")
	}
}

func TestRootImportDoesNotCreateThroughASymlinkedBoundaryComponent(t *testing.T) {
	boundary := t.TempDir()
	outside := t.TempDir()
	redirect := filepath.Join(boundary, "redirect")
	if err := os.Symlink(outside, redirect); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(redirect, "code-signing.d")
	store := LocalRootStore{Boundary: boundary, CodeSigningDirectory: directory, OwnerUID: uint32(os.Getuid())}
	cert, der := testSelfSignedRoot(t, "redirected root")
	source := filepath.Join(t.TempDir(), "root.der")
	if err := os.WriteFile(source, der, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(source, RootPurposeCodeSigning, fingerprintOf(cert)); err == nil {
		t.Fatal("root import followed a symlink inside the trust boundary")
	}
	if _, err := os.Lstat(filepath.Join(outside, "code-signing.d")); !os.IsNotExist(err) {
		t.Fatalf("root import created outside its boundary: %v", err)
	}
}

func TestLocalTrustLoadsOnlyRootOwnedOfflineCRLs(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	boundary := t.TempDir()
	if err := os.Chmod(boundary, 0o755); err != nil {
		t.Fatal(err)
	}
	revocation := filepath.Join(boundary, "revocation", "code-signing.d")
	if err := os.MkdirAll(revocation, 0o755); err != nil {
		t.Fatal(err)
	}
	list := createTestCRL(t, pki.intermediate, pki.intermediateKey, now, nil, nil)
	path := filepath.Join(revocation, "publisher.crl")
	if err := os.WriteFile(path, list.Raw, 0o644); err != nil {
		t.Fatal(err)
	}
	store := LocalRootStore{Boundary: boundary, PublisherCRLDirectory: revocation, OwnerUID: uint32(os.Getuid())}
	trust, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(trust.PublisherCRLs) != 1 || !strings.Contains(trust.PublisherCRLs[0].Issuer.String(), "test code-signing intermediate") {
		t.Fatalf("publisher CRLs = %+v", trust.PublisherCRLs)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("unprivileged-writable CRL was accepted")
	}
}

func TestPrepareVerifierAccessMigratesOnlySafeTrustMaterial(t *testing.T) {
	boundary := t.TempDir()
	directory := filepath.Join(boundary, "code-signing.d")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	_, der := testSelfSignedRoot(t, "legacy local root")
	path := filepath.Join(directory, "legacy.der")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatal(err)
	}
	store := LocalRootStore{Boundary: boundary, CodeSigningDirectory: directory, OwnerUID: uint32(os.Getuid())}
	if err := store.PrepareVerifierAccess(); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		path string
		mode os.FileMode
	}{{boundary, 0o755}, {directory, 0o755}, {path, 0o644}} {
		info, err := os.Stat(candidate.path)
		if err != nil || info.Mode().Perm() != candidate.mode {
			t.Fatalf("%q mode = %v, %v; want %o", candidate.path, info, err, candidate.mode)
		}
	}

	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := store.PrepareVerifierAccess(); err == nil {
		t.Fatal("migration made an unprivileged-writable root look safe")
	}
}

func TestLocalRootDirectoryCannotEscapeItsBoundary(t *testing.T) {
	boundary := t.TempDir()
	outside := t.TempDir()
	store := LocalRootStore{Boundary: boundary, CodeSigningDirectory: outside, OwnerUID: uint32(os.Getuid())}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("escaped root directory = %v", err)
	}
}
