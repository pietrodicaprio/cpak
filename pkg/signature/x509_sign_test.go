/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"testing"
	"time"
)

type recordingSigner struct {
	key   *rsa.PrivateKey
	calls int
}

func (s *recordingSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s *recordingSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.key.Sign(random, digest, opts)
}

func TestSignX509CMSUsesCryptoSignerAndProducesVerifierEvidence(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	signer := &recordingSigner{key: pki.leafKey}
	der, err := SignX509CMS(testX509State(), pki.leaf, []*x509.Certificate{pki.intermediate}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if signer.calls != 1 {
		t.Fatalf("crypto.Signer was called %d times", signer.calls)
	}
	result, err := VerifyEvidence(NewX509CMSEvidence(testX509State(), der), pki.trust, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Cryptographic != CryptographicVerified || result.Chain != ChainTrustedLocal {
		t.Fatalf("signed evidence did not verify: %+v", result)
	}
}

func TestSignX509CMSRejectsMismatchedKey(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = SignX509CMS(testX509State(), pki.leaf, []*x509.Certificate{pki.intermediate}, other); err == nil {
		t.Fatal("a private key for another certificate was accepted")
	}
}
