/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkobrombin/cpak/pkg/signature"
	"github.com/youmark/pkcs8"
)

type commandPKI struct {
	root, intermediate, leaf *x509.Certificate
	leafKey                  *ecdsa.PrivateKey
}

func TestX509SignAcceptsEncryptedSoftwareKeyAndProducesDetachedEvidence(t *testing.T) {
	directory := t.TempDir()
	pki := newCommandPKI(t, time.Now())
	state := signedState("sha256:" + strings.Repeat("a", 64))
	statePath, certificatePath, chainPath, rootPath, keyPath, passphrasePath := stageX509Signing(t, directory, state, pki)
	output := filepath.Join(directory, "state.cms")
	if err := signX509([]string{
		"--state", statePath, "--certificate", certificatePath, "--chain", chainPath,
		"--key", keyPath, "--key-passphrase-file", passphrasePath, "--output", output,
	}); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := publicationTrust(rootPath, signature.EvidenceX509CMS)
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := checkStateEvidence(signature.NewX509CMSEvidence(state, payload), trust)
	if err != nil {
		t.Fatal(err)
	}
	if result.Cryptographic != signature.CryptographicVerified || result.Chain != signature.ChainTrustedLocal {
		t.Fatalf("verification = %+v", result)
	}
}

func TestX509SignRejectsUnsafeKeyAndPassphraseInputs(t *testing.T) {
	directory := t.TempDir()
	pki := newCommandPKI(t, time.Now())
	state := signedState("sha256:" + strings.Repeat("b", 64))
	statePath, certificatePath, chainPath, _, keyPath, passphrasePath := stageX509Signing(t, directory, state, pki)
	arguments := []string{"--state", statePath, "--certificate", certificatePath, "--chain", chainPath, "--key", keyPath, "--key-passphrase-file", passphrasePath, "--output", filepath.Join(directory, "state.cms")}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signX509(arguments); err == nil || !strings.Contains(err.Error(), "only by its owner") {
		t.Fatalf("unsafe key mode error = %v", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passphrasePath, []byte("wrong passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := signX509(arguments); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("wrong passphrase error = %v", err)
	}
}

func TestAttachPublishesX509CMSOnlyAfterPublicationTimeTrust(t *testing.T) {
	registry := newFakeRegistry(t)
	imageDigest := registry.publishImage("main")
	directory := t.TempDir()
	pki := newCommandPKI(t, time.Now())
	state := signedState(imageDigest)
	statePath, certificatePath, chainPath, rootPath, keyPath, passphrasePath := stageX509Signing(t, directory, state, pki)
	output := filepath.Join(directory, defaultCMSPath)
	if err := signX509([]string{"--state", statePath, "--certificate", certificatePath, "--chain", chainPath, "--key", keyPath, "--key-passphrase-file", passphrasePath, "--output", output}); err != nil {
		t.Fatal(err)
	}
	arguments := []string{"--image", registry.reference(""), "--state", statePath, "--bundle", output, "--evidence-kind", "x509-cms"}
	if err := attachSignature(arguments); err == nil {
		t.Fatal("experimental evidence attached without publication-time or system trust")
	}
	if registry.requests != 0 {
		t.Fatalf("registry contacted %d times before evidence was trusted", registry.requests)
	}
	arguments = append(arguments, "--trust-root", rootPath)
	if err := attachSignature(arguments); err != nil {
		t.Fatal(err)
	}
	if len(registry.pushed) != 1 {
		t.Fatalf("registry received %d referrer manifests", len(registry.pushed))
	}
	for _, encoded := range registry.pushed {
		var published referrer
		if err := json.Unmarshal(encoded, &published); err != nil {
			t.Fatal(err)
		}
		if published.ArtifactType != signature.X509ArtifactType || len(published.Layers) != 1 || published.Layers[0].MediaType != signature.X509CMSMediaType {
			t.Fatalf("X.509 publication profile = %+v", published)
		}
	}
}

func stageX509Signing(t *testing.T, directory string, state signature.State, pki commandPKI) (string, string, string, string, string, string) {
	t.Helper()
	canonical, err := state.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, "state")
	if err = os.WriteFile(statePath, canonical, 0o644); err != nil {
		t.Fatal(err)
	}
	writeCertificate := func(name string, certificate *x509.Certificate) string {
		path := filepath.Join(directory, name)
		if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certificatePath := writeCertificate("publisher.pem", pki.leaf)
	chainPath := writeCertificate("chain.pem", pki.intermediate)
	rootPath := writeCertificate("root.pem", pki.root)
	passphrase := []byte("correct horse battery staple")
	keyDER, err := pkcs8.MarshalPrivateKey(pki.leafKey, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "publisher-key.pem")
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	passphrasePath := filepath.Join(directory, "passphrase")
	if err = os.WriteFile(passphrasePath, append(passphrase, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return statePath, certificatePath, chainPath, rootPath, keyPath, passphrasePath
}

func newCommandPKI(t *testing.T, now time.Time) commandPKI {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	serial := int64(1)
	issue := func(template, parent *x509.Certificate, public any, signer *ecdsa.PrivateKey) *x509.Certificate {
		template.SerialNumber = big.NewInt(serial)
		serial++
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	rootKey := newKey()
	rootTemplate := &x509.Certificate{Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 1}
	root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	intermediateKey := newKey()
	intermediateTemplate := &x509.Certificate{Subject: pkix.Name{CommonName: "test intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLenZero: true}
	intermediate := issue(intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	leafKey := newKey()
	leafTemplate := &x509.Certificate{Subject: pkix.Name{Organization: []string{"Example Publisher"}, CommonName: "Example Publisher"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(6 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	leaf := issue(leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	return commandPKI{root: root, intermediate: intermediate, leaf: leaf, leafKey: leafKey}
}

func fingerprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:])
}
