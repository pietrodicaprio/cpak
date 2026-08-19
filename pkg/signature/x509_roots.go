/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	RootBundleABIVersion = 1
	RootBundleMediaType  = "application/vnd.cpak.code-signing-roots.v1+json"
	MaxRootBundleSize    = 8 << 20
	MaxLocalRootSize     = 64 << 10

	RootPurposeCodeSigning  = "code-signing"
	RootPurposeTimestamping = "timestamping"
	RootSourcePublic        = "public"
	RootSourceLocal         = "local"
)

//go:embed x509roots/public-roots-v1.json
var embeddedX509Roots embed.FS

type RootBundleSource struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	RetrievedAt string `json:"retrieved_at"`
	SHA256      string `json:"sha256"`
	License     string `json:"license"`
}

type RootBundleEntry struct {
	SHA256   string   `json:"sha256"`
	Subject  string   `json:"subject"`
	Purposes []string `json:"purposes"`
	DER      []byte   `json:"der"`
}

type RootBundle struct {
	ABI     int                `json:"abi"`
	Sources []RootBundleSource `json:"sources"`
	Roots   []RootBundleEntry  `json:"roots"`
}

type X509Root struct {
	Certificate *x509.Certificate
	Fingerprint string
	Source      string
	Purposes    map[string]bool
}

// X509TrustSet is the complete offline material used by the CMS adapter. The
// two pools are deliberately separate; importing a root for one purpose never
// grants the other. CRLs are caller-supplied cached evidence and never fetched.
type X509TrustSet struct {
	CodeSigningRoots *x509.CertPool
	TimestampRoots   *x509.CertPool
	Roots            map[string]X509Root
	PublisherCRLs    []*x509.RevocationList
	TimestampCRLs    []*x509.RevocationList
}

func EmbeddedRootBundle() ([]byte, error) {
	data, err := embeddedX509Roots.ReadFile("x509roots/public-roots-v1.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded code-signing roots: %w", err)
	}
	if len(data) > MaxRootBundleSize {
		return nil, errors.New("embedded code-signing root bundle exceeds its size limit")
	}
	return data, nil
}

func LoadEmbeddedX509Trust() (*X509TrustSet, error) {
	data, err := EmbeddedRootBundle()
	if err != nil {
		return nil, err
	}
	return ParseRootBundle(data)
}

func ParseRootBundle(document []byte) (*X509TrustSet, error) {
	if len(document) == 0 || len(document) > MaxRootBundleSize {
		return nil, errors.New("code-signing root bundle has an invalid size")
	}
	if err := RejectDuplicateJSONKeys(document); err != nil {
		return nil, fmt.Errorf("decode code-signing root bundle: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var bundle RootBundle
	if err := decoder.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("decode code-signing root bundle: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("code-signing root bundle contains multiple JSON values")
	}
	if bundle.ABI != RootBundleABIVersion {
		return nil, fmt.Errorf("code-signing root bundle has unsupported ABI %d", bundle.ABI)
	}
	if err := validateRootSources(bundle.Sources); err != nil {
		return nil, err
	}
	trust := &X509TrustSet{
		CodeSigningRoots: x509.NewCertPool(),
		TimestampRoots:   x509.NewCertPool(),
		Roots:            make(map[string]X509Root),
	}
	previous := ""
	for _, entry := range bundle.Roots {
		if previous != "" && entry.SHA256 <= previous {
			return nil, errors.New("code-signing root entries are not strictly sorted by fingerprint")
		}
		previous = entry.SHA256
		root, err := validateRootEntry(entry, RootSourcePublic)
		if err != nil {
			return nil, err
		}
		if _, duplicate := trust.Roots[root.Fingerprint]; duplicate {
			return nil, fmt.Errorf("code-signing root bundle repeats fingerprint %s", root.Fingerprint)
		}
		trust.addRoot(root)
	}
	return trust, nil
}

func validateRootSources(sources []RootBundleSource) error {
	if len(sources) == 0 {
		return errors.New("code-signing root bundle names no provenance source")
	}
	seen := make(map[string]bool)
	for _, source := range sources {
		parsed, err := url.Parse(source.URL)
		if source.Name == "" || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return errors.New("code-signing root bundle contains an invalid provenance source")
		}
		when, err := time.Parse(time.RFC3339, source.RetrievedAt)
		if err != nil || when.Format(time.RFC3339) != source.RetrievedAt {
			return errors.New("code-signing root bundle contains an invalid retrieval time")
		}
		if source.License == "" || source.SHA256 == "" {
			return errors.New("code-signing root bundle contains incomplete provenance")
		}
		if !validLowerSHA256(source.SHA256) {
			return errors.New("code-signing root bundle contains an invalid source fingerprint")
		}
		if seen[source.URL] {
			return errors.New("code-signing root bundle repeats a provenance URL")
		}
		seen[source.URL] = true
	}
	return nil
}

func validateRootEntry(entry RootBundleEntry, source string) (X509Root, error) {
	if !validLowerSHA256(entry.SHA256) || len(entry.DER) == 0 || len(entry.DER) > MaxLocalRootSize {
		return X509Root{}, errors.New("code-signing root bundle contains an invalid root entry")
	}
	cert, err := x509.ParseCertificate(entry.DER)
	if err != nil {
		return X509Root{}, fmt.Errorf("parse code-signing root %s: %w", entry.SHA256, err)
	}
	if !bytes.Equal(cert.Raw, entry.DER) {
		return X509Root{}, fmt.Errorf("code-signing root %s contains trailing certificate data", entry.SHA256)
	}
	if entry.Subject == "" || safeDisplayName(entry.Subject) != entry.Subject {
		return X509Root{}, fmt.Errorf("code-signing root %s has an unsafe declared subject", entry.SHA256)
	}
	sum := sha256.Sum256(cert.Raw)
	if hex.EncodeToString(sum[:]) != entry.SHA256 {
		return X509Root{}, fmt.Errorf("code-signing root %s does not match its fingerprint", entry.SHA256)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.CheckSignatureFrom(cert) != nil || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return X509Root{}, fmt.Errorf("code-signing root %s is not a self-signed CA", entry.SHA256)
	}
	if !allowedCertificateSignature(cert.SignatureAlgorithm) {
		return X509Root{}, fmt.Errorf("code-signing root %s uses an unsupported signature algorithm", entry.SHA256)
	}
	purposes := make(map[string]bool)
	for _, purpose := range entry.Purposes {
		if purpose != RootPurposeCodeSigning && purpose != RootPurposeTimestamping {
			return X509Root{}, fmt.Errorf("code-signing root %s has an unsupported purpose", entry.SHA256)
		}
		if purposes[purpose] {
			return X509Root{}, fmt.Errorf("code-signing root %s repeats a purpose", entry.SHA256)
		}
		purposes[purpose] = true
	}
	if len(purposes) == 0 {
		return X509Root{}, fmt.Errorf("code-signing root %s has no purpose", entry.SHA256)
	}
	return X509Root{Certificate: cert, Fingerprint: entry.SHA256, Source: source, Purposes: purposes}, nil
}

func (t *X509TrustSet) addRoot(root X509Root) {
	t.Roots[root.Fingerprint] = root
	if root.Purposes[RootPurposeCodeSigning] {
		t.CodeSigningRoots.AddCert(root.Certificate)
	}
	if root.Purposes[RootPurposeTimestamping] {
		t.TimestampRoots.AddCert(root.Certificate)
	}
}

func (t *X509TrustSet) RootSource(chain []*x509.Certificate) string {
	if t == nil || len(chain) == 0 {
		return ""
	}
	sum := sha256.Sum256(chain[len(chain)-1].Raw)
	if root, ok := t.Roots[hex.EncodeToString(sum[:])]; ok {
		return root.Source
	}
	return ""
}

func allowedCertificateSignature(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return true
	default:
		return false
	}
}

func validLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func SortedRootFingerprints(trust *X509TrustSet) []string {
	if trust == nil {
		return nil
	}
	fingerprints := make([]string, 0, len(trust.Roots))
	for fingerprint := range trust.Roots {
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Strings(fingerprints)
	return fingerprints
}
