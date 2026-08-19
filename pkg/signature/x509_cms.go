/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/digitorus/pkcs7"
)

var (
	oidCMSData                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidCMSSignedData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSignatureTimestampToken  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	oidSHA256                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidRSAEncryption            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256          = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384          = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512          = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidCRLNumber                = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidAuthorityKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidFreshestCRL              = asn1.ObjectIdentifier{2, 5, 29, 46}
)

type cmsContentInfo struct {
	Raw         asn1.RawContent
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type cmsRawCertificates struct{ Raw asn1.RawContent }

type cmsIssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type cmsAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type cmsSignerInfo struct {
	Version                   int
	IssuerAndSerialNumber     cmsIssuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []cmsAttribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []cmsAttribute `asn1:"optional,omitempty,tag:1"`
}

type cmsSignedData struct {
	Version                    int
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                cmsContentInfo
	Certificates               cmsRawCertificates     `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []cmsSignerInfo        `asn1:"set"`
}

type rfc3161MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type rfc3161Accuracy struct {
	Seconds      int64 `asn1:"optional"`
	Milliseconds int64 `asn1:"tag:0,optional"`
	Microseconds int64 `asn1:"tag:1,optional"`
}

type rfc3161Info struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint rfc3161MessageImprint
	SerialNumber   *big.Int
	Time           time.Time        `asn1:"generalized"`
	Accuracy       rfc3161Accuracy  `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

type strictCMS struct {
	signedData cmsSignedData
	signer     cmsSignerInfo
	payload    *pkcs7.PKCS7
}

type X509CMSVerifier struct{}

func (X509CMSVerifier) Kind() EvidenceKind { return EvidenceX509CMS }

func (X509CMSVerifier) Verify(evidence SignatureEvidence, material TrustMaterial, now time.Time) (VerificationResult, error) {
	result := VerificationResult{
		EvidenceKind: evidence.Kind, Cryptographic: CryptographicInvalid, Chain: ChainUntrusted,
		SigningTime: SigningTimeInvalid, Revocation: RevocationUnknown,
		OriginAuthorization: string(OriginUnsupported),
	}
	digest, _ := evidence.State.Digest()
	result.StateDigest = digest
	if evidence.Kind != EvidenceX509CMS {
		result.Cryptographic = CryptographicUnsupported
		return invalidX509Result(result, "unsupported-evidence-kind", errors.New("X.509 verifier received another evidence kind")), nil
	}
	if err := evidence.ValidateEnvelope(); err != nil {
		return invalidX509Result(result, evidenceReason(err), err), nil
	}
	trust, err := x509TrustMaterial(material)
	if err != nil {
		return result, err
	}
	canonical, err := evidence.State.Canonical()
	if err != nil {
		return invalidX509Result(result, "invalid-signed-state", err), nil
	}
	parsed, err := parseStrictCMS(evidence.Payload, true, oidCMSData)
	if err != nil {
		return invalidX509Result(result, "invalid-cms", err), nil
	}
	parsed.payload.Content = canonical
	leaf := parsed.payload.GetOnlySigner()
	if leaf == nil {
		return invalidX509Result(result, "invalid-cms-signer", errors.New("CMS signer certificate is missing or ambiguous")), nil
	}
	if err := validateCodeSigningLeaf(leaf); err != nil {
		return invalidX509Result(result, "invalid-code-signing-certificate", err), nil
	}
	if now.Before(leaf.NotBefore) {
		result.SigningTime = SigningTimeNotYetValid
		return invalidX509Result(result, "certificate-not-yet-valid", errors.New("the code-signing certificate is not yet valid")), nil
	}

	verificationTime := now
	result.SigningTime = SigningTimeCurrent
	timestampToken, timestampPresent, err := parsed.timestampToken()
	if err != nil {
		return invalidX509Result(result, "invalid-timestamp-attribute", err), nil
	}
	if timestampPresent {
		verificationTime, err = verifyTimestamp(timestampToken, parsed.signer.EncryptedDigest, leaf, trust, now)
		if err != nil {
			return invalidX509Result(result, "invalid-rfc3161-timestamp", err), nil
		}
		result.SigningTime = SigningTimeTimestamped
	} else if !now.Before(leaf.NotAfter) {
		result.SigningTime = SigningTimeExpired
		return invalidX509Result(result, "certificate-expired-without-timestamp", errors.New("the code-signing certificate expired without an accepted RFC 3161 timestamp")), nil
	}

	chains, err := verifyCMSAt(parsed.payload, trust.CodeSigningRoots, x509.ExtKeyUsageCodeSigning, verificationTime)
	if err != nil {
		return invalidX509Result(result, "untrusted-code-signing-chain", err), nil
	}
	chain := chains[0]
	result.Chain = ChainTrustedPublic
	result.RootSource = trust.RootSource(chain)
	if result.RootSource == RootSourceLocal {
		result.Chain = ChainTrustedLocal
	}
	if result.RootSource == "" {
		return invalidX509Result(result, "unknown-code-signing-root", errors.New("the verified chain ends at no admitted cpak code-signing root")), nil
	}

	revocation, err := evaluateRevocation(chain, trust.PublisherCRLs, now, verificationTime)
	result.Revocation = revocation
	if err != nil {
		return invalidX509Result(result, "invalid-revocation-evidence", err), nil
	}
	if revocation == RevocationRevoked {
		result.ReasonCode = "certificate-revoked"
		result.Diagnostic = "the publisher certificate chain was revoked at the applicable signing time"
		return result, nil
	}
	if revocation == RevocationStale {
		result.ReasonCode = "stale-revocation-evidence"
		result.Diagnostic = "matching revocation evidence is stale"
		return result, nil
	}

	publisher, err := NormalizeX509Identity(leaf)
	if err != nil {
		return invalidX509Result(result, "invalid-publisher-identity", err), nil
	}
	result.Publisher = publisher
	result.Cryptographic = CryptographicVerified
	result.OriginAuthorization = string(OriginAuthorized)
	result.ReasonCode = "x509-signer-covers-origin"
	result.Diagnostic = "the X.509 publisher signed the exact canonical state containing this origin"
	return result, nil
}

func x509TrustMaterial(material TrustMaterial) (*X509TrustSet, error) {
	if material == nil {
		return LoadDefaultX509Trust()
	}
	trust, ok := material.(*X509TrustSet)
	if !ok || trust == nil || trust.CodeSigningRoots == nil || trust.TimestampRoots == nil || trust.Roots == nil {
		return nil, errors.New("signature: X.509 verifier received invalid trust material")
	}
	return trust, nil
}

func parseStrictCMS(der []byte, detached bool, contentType asn1.ObjectIdentifier) (*strictCMS, error) {
	if len(der) == 0 || len(der) > MaxSignatureEvidenceSize {
		return nil, errors.New("CMS payload has an invalid size")
	}
	var outer cmsContentInfo
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 || !bytes.Equal(outer.Raw, der) {
		return nil, errors.New("CMS payload is not one strict DER ContentInfo value")
	}
	if !outer.ContentType.Equal(oidCMSSignedData) || len(outer.Content.Bytes) == 0 {
		return nil, errors.New("CMS outer content type is not SignedData")
	}
	var signed cmsSignedData
	rest, err = asn1.Unmarshal(outer.Content.Bytes, &signed)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("CMS SignedData is malformed")
	}
	if !signed.ContentInfo.ContentType.Equal(contentType) {
		return nil, errors.New("CMS encapsulated content has the wrong type")
	}
	contentPresent := len(signed.ContentInfo.Content.FullBytes) != 0
	if detached == contentPresent {
		return nil, errors.New("CMS content presence does not match the required profile")
	}
	if len(signed.SignerInfos) != 1 {
		return nil, fmt.Errorf("CMS has %d signers, expected exactly one", len(signed.SignerInfos))
	}
	if len(signed.DigestAlgorithmIdentifiers) != 1 {
		return nil, errors.New("CMS must declare exactly one digest algorithm")
	}
	signer := signed.SignerInfos[0]
	if !algorithmIdentifiersEqual(signed.DigestAlgorithmIdentifiers[0], signer.DigestAlgorithm) {
		return nil, errors.New("CMS signer and SignedData digest algorithms differ")
	}
	hash, err := allowedDigest(signer.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	if err := allowedCMSKeyAlgorithm(signer.DigestEncryptionAlgorithm, hash); err != nil {
		return nil, err
	}
	if err := validateSignedAttributes(signer.AuthenticatedAttributes, contentType); err != nil {
		return nil, err
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, err
	}
	if len(p7.Signers) != 1 {
		return nil, errors.New("CMS parser did not preserve the one-signer profile")
	}
	return &strictCMS{signedData: signed, signer: signer, payload: p7}, nil
}

func validateSignedAttributes(attributes []cmsAttribute, contentType asn1.ObjectIdentifier) error {
	if len(attributes) == 0 {
		return errors.New("CMS signer has no signed attributes")
	}
	seen := make(map[string]bool)
	contentTypes := 0
	digests := 0
	for _, attribute := range attributes {
		key := attribute.Type.String()
		if seen[key] {
			return errors.New("CMS signer repeats a signed attribute")
		}
		seen[key] = true
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(attribute.Value.Bytes, &value)
		if err != nil || len(rest) != 0 || len(value.FullBytes) == 0 {
			return errors.New("CMS signed attribute must contain exactly one value")
		}
		switch {
		case attribute.Type.Equal(oidContentType):
			contentTypes++
			var got asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(attribute.Value.Bytes, &got); err != nil || len(rest) != 0 || !got.Equal(contentType) {
				return errors.New("CMS contentType signed attribute is invalid")
			}
		case attribute.Type.Equal(oidMessageDigest):
			digests++
			var got []byte
			if rest, err := asn1.Unmarshal(attribute.Value.Bytes, &got); err != nil || len(rest) != 0 || len(got) == 0 {
				return errors.New("CMS messageDigest signed attribute is invalid")
			}
		}
	}
	if contentTypes != 1 || digests != 1 {
		return errors.New("CMS signer must contain contentType and messageDigest exactly once")
	}
	return nil
}

func (c *strictCMS) timestampToken() ([]byte, bool, error) {
	var token []byte
	for _, attribute := range c.signer.UnauthenticatedAttributes {
		if !attribute.Type.Equal(oidSignatureTimestampToken) {
			continue
		}
		if token != nil {
			return nil, false, errors.New("CMS signer contains multiple timestamp-token attributes")
		}
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(attribute.Value.Bytes, &value)
		if err != nil || len(rest) != 0 || len(value.FullBytes) == 0 {
			return nil, false, errors.New("timestamp-token attribute must contain exactly one value")
		}
		token = append([]byte(nil), value.FullBytes...)
	}
	return token, token != nil, nil
}

func verifyTimestamp(token, signerSignature []byte, publisher *x509.Certificate, trust *X509TrustSet, now time.Time) (time.Time, error) {
	parsedCMS, err := parseStrictCMS(token, false, oidTSTInfo)
	if err != nil {
		return time.Time{}, err
	}
	stamp, err := parseRFC3161Info(parsedCMS.payload.Content)
	if err != nil {
		return time.Time{}, err
	}
	if stamp.Time.After(now) || stamp.Time.Before(publisher.NotBefore) || !stamp.Time.Before(publisher.NotAfter) {
		return time.Time{}, errors.New("RFC 3161 time is outside the publisher certificate validity period")
	}
	hash, _ := allowedDigest(stamp.MessageImprint.HashAlgorithm)
	hasher := hash.New()
	_, _ = hasher.Write(signerSignature)
	if !bytes.Equal(hasher.Sum(nil), stamp.MessageImprint.HashedMessage) {
		return time.Time{}, errors.New("RFC 3161 message imprint does not cover the CMS signature")
	}
	tsa := parsedCMS.payload.GetOnlySigner()
	if tsa == nil || !onlyExtendedKeyUsage(tsa, x509.ExtKeyUsageTimeStamping) || tsa.IsCA || tsa.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		!allowedPublicKey(tsa.PublicKey) || !allowedCertificateSignature(tsa.SignatureAlgorithm) {
		return time.Time{}, errors.New("RFC 3161 signer is not a dedicated timestamping certificate")
	}
	chains, err := verifyCMSAt(parsedCMS.payload, trust.TimestampRoots, x509.ExtKeyUsageTimeStamping, stamp.Time)
	if err != nil {
		return time.Time{}, fmt.Errorf("verify RFC 3161 TSA chain: %w", err)
	}
	if trust.RootSource(chains[0]) == "" {
		return time.Time{}, errors.New("RFC 3161 chain ends at no admitted cpak timestamping root")
	}
	revocation, err := evaluateRevocation(chains[0], trust.TimestampCRLs, now, stamp.Time)
	if err != nil || revocation == RevocationRevoked || revocation == RevocationStale {
		if err != nil {
			return time.Time{}, err
		}
		return time.Time{}, fmt.Errorf("RFC 3161 revocation status is %s", revocation)
	}
	return stamp.Time, nil
}

func parseRFC3161Info(document []byte) (rfc3161Info, error) {
	var info rfc3161Info
	rest, err := asn1.Unmarshal(document, &info)
	if err != nil || len(rest) != 0 {
		return info, errors.New("RFC 3161 TSTInfo is malformed or has trailing data")
	}
	if info.Version != 1 || len(info.Policy) == 0 || info.SerialNumber == nil || info.SerialNumber.Sign() <= 0 || info.Time.IsZero() {
		return info, errors.New("RFC 3161 TSTInfo has invalid required fields")
	}
	hash, err := allowedDigest(info.MessageImprint.HashAlgorithm)
	if err != nil || !allowedHash(hash) || len(info.MessageImprint.HashedMessage) != hash.Size() {
		return info, errors.New("RFC 3161 TSTInfo has an invalid message imprint")
	}
	for _, extension := range info.Extensions {
		if extension.Critical {
			return info, errors.New("RFC 3161 TSTInfo contains an unsupported critical extension")
		}
	}
	return info, nil
}

func verifyCMSAt(p7 *pkcs7.PKCS7, roots *x509.CertPool, usage x509.ExtKeyUsage, at time.Time) ([][]*x509.Certificate, error) {
	leaf := p7.GetOnlySigner()
	if leaf == nil {
		return nil, errors.New("CMS signer certificate is missing")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		if !cert.Equal(leaf) {
			intermediates.AddCert(cert)
		}
	}
	options := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{usage}}
	chains, err := leaf.Verify(options)
	if err != nil {
		return nil, err
	}
	if err := p7.VerifyWithOpts(options); err != nil {
		return nil, err
	}
	return chains, nil
}

func validateCodeSigningLeaf(cert *x509.Certificate) error {
	if cert.IsCA || !cert.BasicConstraintsValid {
		return errors.New("code-signing leaf must have CA=false and valid basic constraints")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("code-signing leaf lacks digitalSignature key usage")
	}
	if !hasExtendedKeyUsage(cert, x509.ExtKeyUsageCodeSigning) {
		return errors.New("code-signing leaf lacks Code Signing EKU")
	}
	if !allowedPublicKey(cert.PublicKey) || !allowedCertificateSignature(cert.SignatureAlgorithm) {
		return errors.New("code-signing leaf uses an unsupported key or certificate signature algorithm")
	}
	return nil
}

func NormalizeX509Identity(cert *x509.Certificate) (*PublisherIdentity, error) {
	if cert == nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return nil, errors.New("verified X.509 signer has no subject public key information")
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	id := "x509-spki-sha256:" + hex.EncodeToString(sum[:])
	display := ""
	if len(cert.Subject.Organization) == 1 {
		display = safeDisplayName(cert.Subject.Organization[0])
	}
	if display == "" {
		display = safeDisplayName(cert.Subject.CommonName)
	}
	if display == "" {
		display = id
	}
	return &PublisherIdentity{
		Kind: "x509-spki-v1", ID: id, DisplayName: display, Assurance: "x509-code-signing",
		Claims: map[string]string{"subject": safeDisplayName(cert.Subject.String()), "serial": strings.ToLower(cert.SerialNumber.Text(16))},
	}, nil
}

func invalidX509Result(result VerificationResult, reason string, err error) VerificationResult {
	result.ReasonCode = reason
	result.Diagnostic = safeDiagnostic(err.Error())
	return result
}

func allowedDigest(algorithm pkix.AlgorithmIdentifier) (crypto.Hash, error) {
	if !parametersAbsentOrNULL(algorithm.Parameters) {
		return 0, errors.New("CMS digest algorithm has ambiguous parameters")
	}
	switch {
	case algorithm.Algorithm.Equal(oidSHA256):
		return crypto.SHA256, nil
	case algorithm.Algorithm.Equal(oidSHA384):
		return crypto.SHA384, nil
	case algorithm.Algorithm.Equal(oidSHA512):
		return crypto.SHA512, nil
	default:
		return 0, errors.New("CMS digest algorithm is unsupported")
	}
}

func allowedCMSKeyAlgorithm(algorithm pkix.AlgorithmIdentifier, digest crypto.Hash) error {
	if !parametersAbsentOrNULL(algorithm.Parameters) {
		return errors.New("CMS signature algorithm has ambiguous parameters")
	}
	wantRSA := map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA256: oidSHA256WithRSA, crypto.SHA384: oidSHA384WithRSA, crypto.SHA512: oidSHA512WithRSA}
	wantECDSA := map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA256: oidECDSAWithSHA256, crypto.SHA384: oidECDSAWithSHA384, crypto.SHA512: oidECDSAWithSHA512}
	if algorithm.Algorithm.Equal(oidRSAEncryption) || algorithm.Algorithm.Equal(wantRSA[digest]) || algorithm.Algorithm.Equal(wantECDSA[digest]) {
		return nil
	}
	return errors.New("CMS signature and digest algorithms are unsupported or inconsistent")
}

func algorithmIdentifiersEqual(first, second pkix.AlgorithmIdentifier) bool {
	return first.Algorithm.Equal(second.Algorithm) && parametersEquivalent(first.Parameters, second.Parameters)
}

func parametersEquivalent(first, second asn1.RawValue) bool {
	return parametersAbsentOrNULL(first) && parametersAbsentOrNULL(second)
}

func parametersAbsentOrNULL(value asn1.RawValue) bool {
	return len(value.FullBytes) == 0 || bytes.Equal(value.FullBytes, []byte{0x05, 0x00})
}

func allowedHash(hash crypto.Hash) bool {
	return hash == crypto.SHA256 || hash == crypto.SHA384 || hash == crypto.SHA512
}

func allowedPublicKey(key any) bool {
	switch key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return true
	default:
		return false
	}
}

func hasExtendedKeyUsage(cert *x509.Certificate, wanted x509.ExtKeyUsage) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == wanted {
			return true
		}
	}
	return false
}

func onlyExtendedKeyUsage(cert *x509.Certificate, wanted x509.ExtKeyUsage) bool {
	return len(cert.ExtKeyUsage) == 1 && cert.ExtKeyUsage[0] == wanted && len(cert.UnknownExtKeyUsage) == 0
}

func evaluateRevocation(chain []*x509.Certificate, lists []*x509.RevocationList, now, cutoff time.Time) (string, error) {
	if len(chain) < 2 {
		return RevocationUnknown, errors.New("verified certificate chain has no issuer")
	}
	status := RevocationGood
	for index, cert := range chain[:len(chain)-1] {
		issuer := chain[index+1]
		matching := make([]*x509.RevocationList, 0, 1)
		for _, list := range lists {
			if list == nil || !bytes.Equal(list.RawIssuer, issuer.RawSubject) {
				continue
			}
			if err := validateCRL(list, issuer); err != nil {
				return RevocationUnknown, err
			}
			matching = append(matching, list)
		}
		if len(matching) == 0 {
			status = RevocationUnknown
			continue
		}
		var current *x509.RevocationList
		for _, list := range matching {
			if !list.ThisUpdate.After(now) && now.Before(list.NextUpdate) && (current == nil || list.ThisUpdate.After(current.ThisUpdate)) {
				current = list
			}
		}
		if current == nil {
			return RevocationStale, nil
		}
		for _, revoked := range current.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 && !revoked.RevocationTime.After(cutoff) {
				return RevocationRevoked, nil
			}
		}
	}
	return status, nil
}

func validateCRL(list *x509.RevocationList, issuer *x509.Certificate) error {
	if issuer.KeyUsage&x509.KeyUsageCRLSign == 0 || list.NextUpdate.IsZero() || !list.NextUpdate.After(list.ThisUpdate) || list.CheckSignatureFrom(issuer) != nil {
		return errors.New("CRL has an invalid issuer, signature, or validity window")
	}
	if len(list.AuthorityKeyId) != 0 && len(issuer.SubjectKeyId) != 0 && !bytes.Equal(list.AuthorityKeyId, issuer.SubjectKeyId) {
		return errors.New("CRL authority key identifier does not match its issuer")
	}
	for _, extension := range list.Extensions {
		if extension.Id.Equal(oidDeltaCRLIndicator) || extension.Id.Equal(oidIssuingDistributionPoint) || extension.Id.Equal(oidFreshestCRL) {
			return errors.New("delta, indirect, and freshest CRLs are unsupported")
		}
		known := extension.Id.Equal(oidCRLNumber) || extension.Id.Equal(oidAuthorityKeyIdentifier)
		if extension.Critical && !known {
			return errors.New("CRL contains an unknown critical extension")
		}
	}
	return nil
}
