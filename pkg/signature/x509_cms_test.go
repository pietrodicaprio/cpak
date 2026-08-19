/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

type cmsTestPKI struct {
	root, intermediate, leaf          *x509.Certificate
	rootKey, intermediateKey, leafKey *rsa.PrivateKey
	trust                             *X509TrustSet
}

func newCMSTestPKI(t testing.TB, now time.Time, leafKey *rsa.PrivateKey, mutateLeaf func(*x509.Certificate)) cmsTestPKI {
	t.Helper()
	key := func() *rsa.PrivateKey {
		created, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	rootKey := key()
	intermediateKey := key()
	if leafKey == nil {
		leafKey = key()
	}
	serial := int64(1)
	issue := func(template, parent *x509.Certificate, public any, signer crypto.PrivateKey) *x509.Certificate {
		template.SerialNumber = big.NewInt(serial)
		serial++
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
	rootTemplate := &x509.Certificate{
		Subject:   pkix.Name{Organization: []string{"cpak test"}, CommonName: "test code-signing root"},
		NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	intermediateTemplate := &x509.Certificate{
		Subject:   pkix.Name{Organization: []string{"cpak test"}, CommonName: "test code-signing intermediate"},
		NotBefore: now.Add(-180 * 24 * time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermediate := issue(intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	leafTemplate := &x509.Certificate{
		Subject:   pkix.Name{Organization: []string{"Example Publisher"}, CommonName: "Example Code Signing"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if mutateLeaf != nil {
		mutateLeaf(leafTemplate)
	}
	leaf := issue(leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	fingerprint := fingerprintOf(root)
	trust := &X509TrustSet{
		CodeSigningRoots: pool, TimestampRoots: x509.NewCertPool(),
		Roots: map[string]X509Root{fingerprint: {
			Certificate: root, Fingerprint: fingerprint, Source: RootSourceLocal,
			Purposes: map[string]bool{RootPurposeCodeSigning: true},
		}},
	}
	return cmsTestPKI{root: root, intermediate: intermediate, leaf: leaf, rootKey: rootKey, intermediateKey: intermediateKey, leafKey: leafKey, trust: trust}
}

func testX509State() State {
	return State{
		ABI: ABIVersion, Origin: "example.org/publisher/application",
		ManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImageDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		LockSHA256:     "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Generation:     7,
	}
}

func signTestCMS(t testing.TB, state State, pki cmsTestPKI, digest asn1.ObjectIdentifier, unsigned []pkcs7.Attribute) []byte {
	t.Helper()
	canonical, err := state.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(canonical)
	if err != nil {
		t.Fatal(err)
	}
	signed.SetDigestAlgorithm(digest)
	if err := signed.AddSignerChain(pki.leaf, pki.leafKey, []*x509.Certificate{pki.intermediate}, pkcs7.SignerInfoConfig{ExtraUnsignedAttributes: unsigned}); err != nil {
		t.Fatal(err)
	}
	signed.Detach()
	der, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mutateTestCMS(t *testing.T, document []byte, mutate func(*cmsSignedData)) []byte {
	t.Helper()
	var outer cmsContentInfo
	if rest, err := asn1.Unmarshal(document, &outer); err != nil || len(rest) != 0 {
		t.Fatalf("parse test CMS: %v", err)
	}
	var signed cmsSignedData
	if rest, err := asn1.Unmarshal(outer.Content.Bytes, &signed); err != nil || len(rest) != 0 {
		t.Fatalf("parse test SignedData: %v", err)
	}
	mutate(&signed)
	inner, err := asn1.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	outer.Raw = nil
	outer.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner}
	changed, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func signTestCMSWithoutChain(t *testing.T, state State, pki cmsTestPKI, extra *x509.Certificate) []byte {
	t.Helper()
	canonical, err := state.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(canonical)
	if err != nil {
		t.Fatal(err)
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := signed.AddSigner(pki.leaf, pki.leafKey, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	if extra != nil {
		signed.AddCertificate(extra)
	}
	signed.Detach()
	der, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func verifyTestCMS(t *testing.T, state State, der []byte, trust *X509TrustSet, now time.Time) VerificationResult {
	t.Helper()
	result, err := VerifyEvidence(SignatureEvidence{
		ABI: EvidenceABIVersion, Kind: EvidenceX509CMS, State: state,
		MediaType: X509CMSMediaType, Payload: der,
	}, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestValidDetachedCMSVerifiesAndNormalizesThePublisher(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	state := testX509State()
	der := signTestCMS(t, state, pki, pkcs7.OIDDigestAlgorithmSHA256, nil)
	result := verifyTestCMS(t, state, der, pki.trust, now)
	if result.Cryptographic != CryptographicVerified || result.Chain != ChainTrustedLocal || result.SigningTime != SigningTimeCurrent || result.Revocation != RevocationUnknown {
		t.Fatalf("verification = %+v", result)
	}
	want := sha256.Sum256(pki.leaf.RawSubjectPublicKeyInfo)
	if result.Publisher == nil || result.Publisher.ID != "x509-spki-sha256:"+fmtHex(want[:]) || result.Publisher.DisplayName != "Example Publisher" {
		t.Fatalf("publisher = %+v", result.Publisher)
	}
	if result.OriginAuthorization != string(OriginAuthorized) {
		t.Fatalf("origin authorization = %q", result.OriginAuthorization)
	}
}

func TestPublicAndImportedLocalRootsProduceDistinctTrustResults(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	state := testX509State()
	der := signTestCMS(t, state, pki, pkcs7.OIDDigestAlgorithmSHA256, nil)
	fingerprint := fingerprintOf(pki.root)
	pki.trust.Roots[fingerprint] = X509Root{Certificate: pki.root, Fingerprint: fingerprint, Source: RootSourcePublic, Purposes: map[string]bool{RootPurposeCodeSigning: true}}
	if result := verifyTestCMS(t, state, der, pki.trust, now); result.Cryptographic != CryptographicVerified || result.Chain != ChainTrustedPublic || result.RootSource != RootSourcePublic {
		t.Fatalf("public-root verification = %+v", result)
	}

	boundary := t.TempDir()
	store := LocalRootStore{Boundary: boundary, CodeSigningDirectory: filepath.Join(boundary, "code-signing.d"), OwnerUID: uint32(os.Getuid())}
	source := filepath.Join(t.TempDir(), "root.der")
	if err := os.WriteFile(source, pki.root.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(source, RootPurposeCodeSigning, fingerprint); err != nil {
		t.Fatal(err)
	}
	local, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if result := verifyTestCMS(t, state, der, local, now); result.Cryptographic != CryptographicVerified || result.Chain != ChainTrustedLocal || result.RootSource != RootSourceLocal {
		t.Fatalf("local-root verification = %+v", result)
	}
}

func TestCMSIsBoundToEveryCanonicalStateField(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	state := testX509State()
	der := signTestCMS(t, state, pki, pkcs7.OIDDigestAlgorithmSHA256, nil)
	tests := map[string]func(*State){
		"origin":     func(s *State) { s.Origin = "example.org/attacker/application" },
		"manifest":   func(s *State) { s.ManifestSHA256 = strings64("d") },
		"image":      func(s *State) { s.ImageDigest = "sha256:" + strings64("e") },
		"lock":       func(s *State) { s.LockSHA256 = strings64("f") },
		"generation": func(s *State) { s.Generation++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := state
			mutate(&changed)
			if result := verifyTestCMS(t, changed, der, pki.trust, now); result.Cryptographic != CryptographicInvalid {
				t.Fatalf("changed state verified: %+v", result)
			}
		})
	}
}

func TestX509PublisherIdentityFollowsTheSPKI(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	first := newCMSTestPKI(t, now, key, nil)
	second := newCMSTestPKI(t, now, key, func(cert *x509.Certificate) {
		cert.Subject.Organization = []string{"Renamed Publisher"}
		cert.NotAfter = cert.NotAfter.Add(90 * 24 * time.Hour)
	})
	third := newCMSTestPKI(t, now, nil, nil)
	firstID, _ := NormalizeX509Identity(first.leaf)
	secondID, _ := NormalizeX509Identity(second.leaf)
	thirdID, _ := NormalizeX509Identity(third.leaf)
	if firstID.ID != secondID.ID || firstID.ID == thirdID.ID {
		t.Fatalf("SPKI identity changed incorrectly: first=%s renewal=%s rotation=%s", firstID.ID, secondID.ID, thirdID.ID)
	}
}

func TestX509LeafProfileFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	tests := map[string]func(*x509.Certificate){
		"wrong EKU":                 func(cert *x509.Certificate) { cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"missing digital signature": func(cert *x509.Certificate) { cert.KeyUsage = x509.KeyUsageKeyEncipherment },
		"CA leaf":                   func(cert *x509.Certificate) { cert.IsCA = true; cert.KeyUsage |= x509.KeyUsageCertSign },
		"not yet valid":             func(cert *x509.Certificate) { cert.NotBefore = now.Add(time.Hour) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			pki := newCMSTestPKI(t, now, nil, mutate)
			der := signTestCMS(t, testX509State(), pki, pkcs7.OIDDigestAlgorithmSHA256, nil)
			if result := verifyTestCMS(t, testX509State(), der, pki.trust, now); result.Cryptographic != CryptographicInvalid {
				t.Fatalf("invalid leaf verified: %+v", result)
			}
		})
	}
}

func TestExpiredLeafNeedsAnRFC3161Timestamp(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, func(cert *x509.Certificate) {
		cert.NotBefore = now.Add(-48 * time.Hour)
		cert.NotAfter = now.Add(-time.Hour)
	})
	der := signTestCMS(t, testX509State(), pki, pkcs7.OIDDigestAlgorithmSHA256, nil)
	result := verifyTestCMS(t, testX509State(), der, pki.trust, now)
	if result.Cryptographic != CryptographicInvalid || result.SigningTime != SigningTimeExpired || result.ReasonCode != "certificate-expired-without-timestamp" {
		t.Fatalf("expired verification = %+v", result)
	}
}

func TestCMSRejectsMalformedAndWeakInputs(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	valid := signTestCMS(t, testX509State(), pki, pkcs7.OIDDigestAlgorithmSHA256, nil)
	tests := map[string][]byte{
		"empty":     nil,
		"BER only":  {0x30, 0x80, 0x00, 0x00},
		"truncated": valid[:len(valid)-1],
		"trailing":  append(append([]byte(nil), valid...), 0),
		"bit flip":  func() []byte { changed := append([]byte(nil), valid...); changed[len(changed)-1] ^= 1; return changed }(),
		"oversized": make([]byte, MaxSignatureEvidenceSize+1),
	}
	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			result := verifyTestCMS(t, testX509State(), der, pki.trust, now)
			if result.Cryptographic != CryptographicInvalid {
				t.Fatalf("malformed CMS verified: %+v", result)
			}
		})
	}
	weak := signTestCMS(t, testX509State(), pki, pkcs7.OIDDigestAlgorithmSHA1, nil)
	if result := verifyTestCMS(t, testX509State(), weak, pki.trust, now); result.Cryptographic != CryptographicInvalid {
		t.Fatalf("SHA-1 CMS verified: %+v", result)
	}
}

func TestCMSRejectsAmbiguousSignersAttributesAndAlgorithms(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	valid := signTestCMS(t, testX509State(), pki, pkcs7.OIDDigestAlgorithmSHA256, nil)
	tests := map[string]func(*cmsSignedData){
		"zero signers": func(signed *cmsSignedData) { signed.SignerInfos = nil },
		"multiple signers": func(signed *cmsSignedData) {
			signed.SignerInfos = append(signed.SignerInfos, signed.SignerInfos[0])
		},
		"duplicate signed attribute": func(signed *cmsSignedData) {
			signed.SignerInfos[0].AuthenticatedAttributes = append(signed.SignerInfos[0].AuthenticatedAttributes, signed.SignerInfos[0].AuthenticatedAttributes[0])
		},
		"multiple digest algorithms": func(signed *cmsSignedData) {
			signed.DigestAlgorithmIdentifiers = append(signed.DigestAlgorithmIdentifiers, signed.DigestAlgorithmIdentifiers[0])
		},
		"mismatched digest identifiers": func(signed *cmsSignedData) {
			signed.SignerInfos[0].DigestAlgorithm.Algorithm = oidSHA384
		},
		"RSA-PSS": func(signed *cmsSignedData) {
			signed.SignerInfos[0].DigestEncryptionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
		},
		"unknown digest parameters": func(signed *cmsSignedData) {
			signed.SignerInfos[0].DigestAlgorithm.Parameters = asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x01}}
			signed.DigestAlgorithmIdentifiers[0].Parameters = asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x01}}
		},
		"unknown signature algorithm": func(signed *cmsSignedData) {
			signed.SignerInfos[0].DigestEncryptionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := verifyTestCMS(t, testX509State(), mutateTestCMS(t, valid, mutate), pki.trust, now)
			if result.Cryptographic != CryptographicInvalid {
				t.Fatalf("ambiguous CMS verified: %+v", result)
			}
		})
	}
}

func TestCMSRejectsCertificateSubstitutionAndBrokenChains(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	state := testX509State()
	valid := signTestCMS(t, state, pki, pkcs7.OIDDigestAlgorithmSHA256, nil)
	position := bytes.Index(valid, pki.leaf.RawSubjectPublicKeyInfo)
	if position < 0 {
		t.Fatal("test CMS does not contain its signer SPKI")
	}
	changed := append([]byte(nil), valid...)
	changed[position+len(pki.leaf.RawSubjectPublicKeyInfo)-1] ^= 1
	if result := verifyTestCMS(t, state, changed, pki.trust, now); result.Cryptographic != CryptographicInvalid {
		t.Fatalf("altered signer certificate verified: %+v", result)
	}

	if result := verifyTestCMS(t, state, signTestCMSWithoutChain(t, state, pki, nil), pki.trust, now); result.Cryptographic != CryptographicInvalid {
		t.Fatalf("missing intermediate verified: %+v", result)
	}
	unrelated := newCMSTestPKI(t, now, nil, nil)
	if result := verifyTestCMS(t, state, signTestCMSWithoutChain(t, state, pki, unrelated.intermediate), pki.trust, now); result.Cryptographic != CryptographicInvalid {
		t.Fatalf("wrong intermediate verified: %+v", result)
	}
	if result := verifyTestCMS(t, state, valid, unrelated.trust, now); result.Cryptographic != CryptographicInvalid {
		t.Fatalf("unknown root verified: %+v", result)
	}
}

func TestX509VerifierNeverConsultsTheSystemTLSRoots(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	path := filepath.Join(t.TempDir(), "system-roots.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.root.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", path)
	evidence := SignatureEvidence{ABI: EvidenceABIVersion, Kind: EvidenceX509CMS, State: testX509State(), MediaType: X509CMSMediaType, Payload: signTestCMS(t, testX509State(), pki, pkcs7.OIDDigestAlgorithmSHA256, nil)}
	result, err := X509CMSVerifier{}.Verify(evidence, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Cryptographic != CryptographicInvalid || result.Chain != ChainUntrusted {
		t.Fatalf("system-only root was trusted: %+v", result)
	}
}

func TestApprovedECDSACMSProfileVerifies(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	key := func() *ecdsa.PrivateKey {
		created, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(201), Subject: pkix.Name{CommonName: "ECDSA root"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(202), Subject: pkix.Name{CommonName: "ECDSA intermediate"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(180 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	intermediate := issue(intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(203), Subject: pkix.Name{Organization: []string{"ECDSA Publisher"}}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	leaf := issue(leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	canonical, _ := testX509State().Canonical()
	signed, err := pkcs7.NewSignedData(canonical)
	if err != nil {
		t.Fatal(err)
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := signed.AddSignerChain(leaf, leafKey, []*x509.Certificate{intermediate}, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	signed.Detach()
	der, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	fingerprint := fingerprintOf(root)
	trust := &X509TrustSet{CodeSigningRoots: pool, TimestampRoots: x509.NewCertPool(), Roots: map[string]X509Root{fingerprint: {Certificate: root, Fingerprint: fingerprint, Source: RootSourceLocal, Purposes: map[string]bool{RootPurposeCodeSigning: true}}}}
	if result := verifyTestCMS(t, testX509State(), der, trust, now); result.Cryptographic != CryptographicVerified {
		t.Fatalf("ECDSA CMS did not verify: %+v", result)
	}
}

func createTestCRL(t *testing.T, issuer *x509.Certificate, key *rsa.PrivateKey, now time.Time, revoked []pkix.RevokedCertificate, mutate func(*x509.RevocationList)) *x509.RevocationList {
	t.Helper()
	template := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA256WithRSA,
		RevokedCertificates: revoked,
		Number:              big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour),
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func currentTestCRLs(t *testing.T, pki cmsTestPKI, now time.Time) []*x509.RevocationList {
	t.Helper()
	return []*x509.RevocationList{
		createTestCRL(t, pki.intermediate, pki.intermediateKey, now, nil, nil),
		createTestCRL(t, pki.root, pki.rootKey, now, nil, nil),
	}
}

func TestOfflineCRLStatusesAndCutoff(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	state := testX509State()
	der := signTestCMS(t, state, pki, pkcs7.OIDDigestAlgorithmSHA256, nil)

	pki.trust.PublisherCRLs = currentTestCRLs(t, pki, now)
	if result := verifyTestCMS(t, state, der, pki.trust, now); result.Cryptographic != CryptographicVerified || result.Revocation != RevocationGood {
		t.Fatalf("good CRLs = %+v", result)
	}

	pki.trust.PublisherCRLs = nil
	if result := verifyTestCMS(t, state, der, pki.trust, now); result.Cryptographic != CryptographicVerified || result.Revocation != RevocationUnknown {
		t.Fatalf("missing CRLs = %+v", result)
	}

	revokedAt := now.Add(-time.Minute)
	pki.trust.PublisherCRLs = []*x509.RevocationList{
		createTestCRL(t, pki.intermediate, pki.intermediateKey, now, []pkix.RevokedCertificate{{SerialNumber: pki.leaf.SerialNumber, RevocationTime: revokedAt}}, nil),
		createTestCRL(t, pki.root, pki.rootKey, now, nil, nil),
	}
	if result := verifyTestCMS(t, state, der, pki.trust, now); result.Revocation != RevocationRevoked || result.ReasonCode != "certificate-revoked" {
		t.Fatalf("revoked CRL = %+v", result)
	}

	pki.trust.PublisherCRLs = []*x509.RevocationList{
		createTestCRL(t, pki.intermediate, pki.intermediateKey, now, nil, func(list *x509.RevocationList) { list.NextUpdate = now }),
		createTestCRL(t, pki.root, pki.rootKey, now, nil, nil),
	}
	if result := verifyTestCMS(t, state, der, pki.trust, now); result.Revocation != RevocationStale || result.ReasonCode != "stale-revocation-evidence" {
		t.Fatalf("stale CRL = %+v", result)
	}

	chain := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	laterRevocation := now.Add(-time.Hour)
	lists := []*x509.RevocationList{
		createTestCRL(t, pki.intermediate, pki.intermediateKey, now, []pkix.RevokedCertificate{{SerialNumber: pki.leaf.SerialNumber, RevocationTime: laterRevocation}}, nil),
		createTestCRL(t, pki.root, pki.rootKey, now, nil, nil),
	}
	if status, err := evaluateRevocation(chain, lists, now, laterRevocation.Add(-time.Second)); err != nil || status != RevocationGood {
		t.Fatalf("later revocation retroactively blocked timestamp: status=%s err=%v", status, err)
	}
}

func TestUnknownCriticalCRLExtensionFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	critical := createTestCRL(t, pki.intermediate, pki.intermediateKey, now, nil, func(list *x509.RevocationList) {
		list.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00}}}
	})
	pki.trust.PublisherCRLs = []*x509.RevocationList{critical, createTestCRL(t, pki.root, pki.rootKey, now, nil, nil)}
	der := signTestCMS(t, testX509State(), pki, pkcs7.OIDDigestAlgorithmSHA256, nil)
	if result := verifyTestCMS(t, testX509State(), der, pki.trust, now); result.Cryptographic != CryptographicInvalid || result.ReasonCode != "invalid-revocation-evidence" {
		t.Fatalf("critical CRL extension was accepted: %+v", result)
	}
}

func TestOfflineCRLRejectsInvalidAndFutureEvidence(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, nil)
	chain := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	unrelated := newCMSTestPKI(t, now, nil, nil)
	wrongIssuer := []*x509.RevocationList{createTestCRL(t, unrelated.intermediate, unrelated.intermediateKey, now, nil, nil)}
	if _, err := evaluateRevocation(chain, wrongIssuer, now, now); err == nil {
		t.Fatal("same-named CRL from the wrong issuer was accepted")
	}
	badSignature := createTestCRL(t, pki.intermediate, unrelated.intermediateKey, now, nil, nil)
	if _, err := evaluateRevocation(chain, []*x509.RevocationList{badSignature}, now, now); err == nil {
		t.Fatal("issuer-named CRL with an invalid signature was accepted")
	}
	future := createTestCRL(t, pki.intermediate, pki.intermediateKey, now, nil, func(list *x509.RevocationList) {
		list.ThisUpdate = now.Add(time.Minute)
		list.NextUpdate = now.Add(time.Hour)
	})
	if status, err := evaluateRevocation(chain, []*x509.RevocationList{future}, now, now); err != nil || status != RevocationStale {
		t.Fatalf("future CRL = status=%s err=%v", status, err)
	}
}

func addTestTimestamp(t *testing.T, signed *pkcs7.SignedData, trust *X509TrustSet, tokenTime, now time.Time, changeImprint bool, mutateTSA func(*x509.Certificate), admitRoot bool) {
	t.Helper()
	tsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tsaRootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tsaRootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "test TSA root"},
		NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	tsaRootDER, err := x509.CreateCertificate(rand.Reader, tsaRootTemplate, tsaRootTemplate, &tsaRootKey.PublicKey, tsaRootKey)
	if err != nil {
		t.Fatal(err)
	}
	tsaRoot, err := x509.ParseCertificate(tsaRootDER)
	if err != nil {
		t.Fatal(err)
	}
	tsaTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "test TSA"},
		NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if mutateTSA != nil {
		mutateTSA(tsaTemplate)
	}
	tsaDER, err := x509.CreateCertificate(rand.Reader, tsaTemplate, tsaRoot, &tsaKey.PublicKey, tsaRootKey)
	if err != nil {
		t.Fatal(err)
	}
	tsa, err := x509.ParseCertificate(tsaDER)
	if err != nil {
		t.Fatal(err)
	}
	signatureValue := signed.GetSignedData().SignerInfos[0].EncryptedDigest
	imprint := sha256.Sum256(signatureValue)
	if changeImprint {
		imprint[0] ^= 1
	}
	stamp := timestamp.Timestamp{
		HashAlgorithm: crypto.SHA256, HashedMessage: imprint[:], Time: tokenTime,
		SerialNumber: big.NewInt(1), Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1},
		Certificates: []*x509.Certificate{tsaRoot}, AddTSACertificate: true,
	}
	response, err := stamp.CreateResponseWithOpts(tsa, tsaKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := timestamp.ParseResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.GetSignedData().SignerInfos[0].SetUnauthenticatedAttributes([]pkcs7.Attribute{{
		Type: oidSignatureTimestampToken, Value: asn1.RawValue{FullBytes: parsed.RawToken},
	}}); err != nil {
		t.Fatal(err)
	}
	if admitRoot {
		trust.TimestampRoots.AddCert(tsaRoot)
		fingerprint := fingerprintOf(tsaRoot)
		trust.Roots[fingerprint] = X509Root{
			Certificate: tsaRoot, Fingerprint: fingerprint, Source: RootSourceLocal,
			Purposes: map[string]bool{RootPurposeTimestamping: true},
		}
	}
}

func timestampedCMS(t *testing.T, state State, pki cmsTestPKI, tokenTime, now time.Time, changeImprint bool) []byte {
	t.Helper()
	canonical, err := state.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(canonical)
	if err != nil {
		t.Fatal(err)
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := signed.AddSignerChain(pki.leaf, pki.leafKey, []*x509.Certificate{pki.intermediate}, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	addTestTimestamp(t, signed, pki.trust, tokenTime, now, changeImprint, nil, true)
	signed.Detach()
	der, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func timestampedCMSWithTSAOptions(t *testing.T, state State, pki cmsTestPKI, tokenTime, now time.Time, mutateTSA func(*x509.Certificate), admitRoot bool) []byte {
	t.Helper()
	canonical, err := state.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(canonical)
	if err != nil {
		t.Fatal(err)
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := signed.AddSignerChain(pki.leaf, pki.leafKey, []*x509.Certificate{pki.intermediate}, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	addTestTimestamp(t, signed, pki.trust, tokenTime, now, false, mutateTSA, admitRoot)
	signed.Detach()
	der, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestRFC3161TimestampPreservesAnExpiredPublisherCertificate(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, func(cert *x509.Certificate) {
		cert.NotBefore = now.Add(-48 * time.Hour)
		cert.NotAfter = now.Add(-time.Hour)
	})
	der := timestampedCMS(t, testX509State(), pki, now.Add(-2*time.Hour), now, false)
	result := verifyTestCMS(t, testX509State(), der, pki.trust, now)
	if result.Cryptographic != CryptographicVerified || result.SigningTime != SigningTimeTimestamped {
		t.Fatalf("timestamped verification = %+v", result)
	}
}

func TestRFC3161MessageImprintMismatchFails(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(t, now, nil, func(cert *x509.Certificate) {
		cert.NotBefore = now.Add(-48 * time.Hour)
		cert.NotAfter = now.Add(-time.Hour)
	})
	der := timestampedCMS(t, testX509State(), pki, now.Add(-2*time.Hour), now, true)
	result := verifyTestCMS(t, testX509State(), der, pki.trust, now)
	if result.Cryptographic != CryptographicInvalid || result.ReasonCode != "invalid-rfc3161-timestamp" {
		t.Fatalf("bad timestamp imprint = %+v", result)
	}
}

func TestRFC3161RejectsUntrustedAndWrongEKUTSAs(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	newExpiredPublisher := func(t *testing.T) cmsTestPKI {
		return newCMSTestPKI(t, now, nil, func(cert *x509.Certificate) {
			cert.NotBefore = now.Add(-48 * time.Hour)
			cert.NotAfter = now.Add(-time.Hour)
		})
	}
	t.Run("untrusted TSA", func(t *testing.T) {
		pki := newExpiredPublisher(t)
		der := timestampedCMSWithTSAOptions(t, testX509State(), pki, now.Add(-2*time.Hour), now, nil, false)
		if result := verifyTestCMS(t, testX509State(), der, pki.trust, now); result.Cryptographic != CryptographicInvalid || result.ReasonCode != "invalid-rfc3161-timestamp" {
			t.Fatalf("untrusted TSA = %+v", result)
		}
	})
	t.Run("wrong TSA EKU", func(t *testing.T) {
		pki := newExpiredPublisher(t)
		der := timestampedCMSWithTSAOptions(t, testX509State(), pki, now.Add(-2*time.Hour), now, func(cert *x509.Certificate) {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		}, true)
		if result := verifyTestCMS(t, testX509State(), der, pki.trust, now); result.Cryptographic != CryptographicInvalid || result.ReasonCode != "invalid-rfc3161-timestamp" {
			t.Fatalf("wrong-EKU TSA = %+v", result)
		}
	})
}

func fmtHex(value []byte) string        { return fmt.Sprintf("%x", value) }
func strings64(character string) string { return strings.Repeat(character, 64) }
