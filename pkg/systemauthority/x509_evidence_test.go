/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package systemauthority

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/mirkobrombin/cpak/pkg/signature"
)

func testX509AuthorityEvidence(t *testing.T, now time.Time) (signature.SignatureEvidence, *signature.X509TrustSet) {
	t.Helper()
	key := func() *rsa.PrivateKey {
		created, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	rootKey, intermediateKey, leafKey := key(), key(), key()
	issue := func(template, parent *x509.Certificate, public any, signer crypto.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(301), Subject: pkix.Name{CommonName: "authority test root"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(302), Subject: pkix.Name{CommonName: "authority test intermediate"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(180 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	intermediate := issue(intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(303), Subject: pkix.Name{Organization: []string{"Authority Test Publisher"}}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	leaf := issue(leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	state := testSignedState(1).State
	canonical, err := state.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(canonical)
	if err != nil {
		t.Fatal(err)
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := signed.AddSignerChain(leaf, leafKey, []*x509.Certificate{intermediate}, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	signed.Detach()
	payload, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	sum := sha256.Sum256(root.Raw)
	fingerprint := hex.EncodeToString(sum[:])
	trust := &signature.X509TrustSet{
		CodeSigningRoots: pool, TimestampRoots: x509.NewCertPool(),
		Roots: map[string]signature.X509Root{fingerprint: {
			Certificate: root, Fingerprint: fingerprint, Source: signature.RootSourceLocal,
			Purposes: map[string]bool{signature.RootPurposeCodeSigning: true},
		}},
	}
	return signature.SignatureEvidence{ABI: signature.EvidenceABIVersion, Kind: signature.EvidenceX509CMS, State: state, MediaType: signature.X509CMSMediaType, Payload: payload}, trust
}

func TestAuthorityIndependentlyReverifiesTaggedX509Evidence(t *testing.T) {
	now := time.Now().UTC()
	evidence, trust := testX509AuthorityEvidence(t, now)
	saved := verifyEvidence
	t.Cleanup(func() { verifyEvidence = saved })
	checks := 0
	verifyEvidence = func(got signature.SignatureEvidence, _ signature.TrustMaterial, _ time.Time) (signature.VerificationResult, error) {
		checks++
		return signature.VerifyEvidence(got, trust, now)
	}
	ledger := testAnchorLedger(t)
	if err := ledger.Record(Enrolment{Anchor: testAnchor(), Signature: SignedStateFromEvidence(evidence)}); err != nil {
		t.Fatal(err)
	}
	recorded, found, err := ledger.Recorded(testAnchor().UID, testAnchor().Origin)
	if err != nil || !found || recorded.Signature == nil {
		t.Fatalf("recorded X.509 evidence: found=%v err=%v enrolment=%+v", found, err, recorded)
	}
	verified, err := recorded.Signer()
	if err != nil {
		t.Fatal(err)
	}
	if checks < 2 || verified.Publisher == nil || verified.Publisher.Kind != "x509-spki-v1" || recorded.Signature.Kind != signature.EvidenceX509CMS {
		t.Fatalf("authority checks=%d verified=%+v recorded=%+v", checks, verified, recorded.Signature)
	}
}

func TestRemovingX509TrustBreaksFullReverificationWithoutChangingTheLedger(t *testing.T) {
	now := time.Now().UTC()
	evidence, admitted := testX509AuthorityEvidence(t, now)
	saved := verifyEvidence
	t.Cleanup(func() { verifyEvidence = saved })
	currentTrust := admitted
	verifyEvidence = func(got signature.SignatureEvidence, _ signature.TrustMaterial, _ time.Time) (signature.VerificationResult, error) {
		return signature.VerifyEvidence(got, currentTrust, now)
	}
	ledger := testAnchorLedger(t)
	anchor := testAnchor()
	if err := ledger.Record(Enrolment{Anchor: anchor, Signature: SignedStateFromEvidence(evidence)}); err != nil {
		t.Fatal(err)
	}
	before, found, err := ledger.Recorded(anchor.UID, anchor.Origin)
	if err != nil || !found || before.Signature == nil {
		t.Fatalf("record before removal: found=%v err=%v record=%+v", found, err, before)
	}
	currentTrust = &signature.X509TrustSet{
		CodeSigningRoots: x509.NewCertPool(), TimestampRoots: x509.NewCertPool(),
		Roots: map[string]signature.X509Root{},
	}
	if _, err = before.Signer(); err == nil {
		t.Fatal("full verification succeeded after the only trusted root was removed")
	}
	after, found, err := ledger.Recorded(anchor.UID, anchor.Origin)
	if err != nil || !found || after.Signature == nil {
		t.Fatalf("record after removal: found=%v err=%v record=%+v", found, err, after)
	}
	if after.Signature.Kind != before.Signature.Kind || string(after.Signature.Bundle) != string(before.Signature.Bundle) || after.Signature.State != before.Signature.State {
		t.Fatalf("trust removal changed ledger evidence: before=%+v after=%+v", before.Signature, after.Signature)
	}
}
