/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	EvidenceABIVersion       = 1
	MaxSignatureEvidenceSize = 1 << 20
)

type EvidenceKind string

const (
	EvidenceSigstoreBundle EvidenceKind = "sigstore-bundle-v1"
	EvidenceX509CMS        EvidenceKind = "x509-cms-v1"

	SigstoreArtifactType    = "application/vnd.cpak.signature.v1+json"
	SigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	X509ArtifactType        = "application/vnd.cpak.signature.x509.v1"
	X509CMSMediaType        = "application/pkcs7-signature"
)

// SignatureEvidence is the versioned evidence envelope shared by discovery,
// verification and privileged storage. State always comes from the package
// being installed; Payload cannot select a different state.
type SignatureEvidence struct {
	ABI       int          `json:"abi"`
	Kind      EvidenceKind `json:"kind"`
	State     State        `json:"state"`
	MediaType string       `json:"media_type"`
	Payload   []byte       `json:"payload"`
}

type evidenceProfile struct {
	mediaType string
	text      bool
}

var evidenceProfiles = map[EvidenceKind]evidenceProfile{
	EvidenceSigstoreBundle: {mediaType: SigstoreBundleMediaType, text: true},
	EvidenceX509CMS:        {mediaType: X509CMSMediaType},
}

type PublisherIdentity struct {
	Kind        string            `json:"kind"`
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name"`
	Issuer      string            `json:"issuer,omitempty"`
	Repository  string            `json:"repository,omitempty"`
	Assurance   string            `json:"assurance"`
	Claims      map[string]string `json:"claims,omitempty"`
}

type OriginAuthorizationStatus string

const (
	OriginAuthorized  OriginAuthorizationStatus = "authorized"
	OriginForeign     OriginAuthorizationStatus = "foreign"
	OriginUnsupported OriginAuthorizationStatus = "unsupported"
)

type OriginAuthorization struct {
	Status     OriginAuthorizationStatus
	ReasonCode string
}

const (
	CryptographicVerified    = "verified"
	CryptographicInvalid     = "invalid"
	CryptographicUnsupported = "unsupported"
	ChainNotApplicable       = "not-applicable"
	ChainTrustedPublic       = "trusted-public"
	ChainTrustedLocal        = "trusted-local"
	ChainUntrusted           = "untrusted"
	ChainInvalid             = "invalid"
	SigningTimeCurrent       = "current"
	SigningTimeTimestamped   = "timestamped"
	SigningTimeMissing       = "missing"
	SigningTimeExpired       = "expired"
	SigningTimeNotYetValid   = "not-yet-valid"
	SigningTimeInvalid       = "invalid"
	RevocationGood           = "good"
	RevocationRevoked        = "revoked"
	RevocationUnknown        = "unknown"
	RevocationStale          = "stale"
)

type VerificationResult struct {
	EvidenceKind        EvidenceKind       `json:"evidence_kind"`
	StateDigest         string             `json:"state_digest"`
	Cryptographic       string             `json:"cryptographic"`
	Chain               string             `json:"chain"`
	SigningTime         string             `json:"signing_time"`
	Revocation          string             `json:"revocation"`
	Publisher           *PublisherIdentity `json:"publisher,omitempty"`
	RootSource          string             `json:"root_source,omitempty"`
	OriginAuthorization string             `json:"origin_authorization"`
	ReasonCode          string             `json:"reason_code"`
	Diagnostic          string             `json:"diagnostic,omitempty"`
	legacyIdentity      *Identity
	failure             error
}

// TrustMaterial is deliberately opaque at the common boundary. Each adapter
// accepts only its own typed material; nil asks it for cpak's built-in default.
type TrustMaterial any

type Verifier interface {
	Kind() EvidenceKind
	Verify(SignatureEvidence, TrustMaterial, time.Time) (VerificationResult, error)
}

type InvalidEvidenceError struct {
	Reason string
}

func (e *InvalidEvidenceError) Error() string { return "signature: invalid evidence: " + e.Reason }

func invalidEvidence(reason string) error { return &InvalidEvidenceError{Reason: reason} }

func NewSigstoreEvidence(state State, bundle []byte) SignatureEvidence {
	return SignatureEvidence{
		ABI:       EvidenceABIVersion,
		Kind:      EvidenceSigstoreBundle,
		State:     state,
		MediaType: SigstoreBundleMediaType,
		Payload:   bundle,
	}
}

func (e SignatureEvidence) ValidateEnvelope() error {
	if e.ABI != EvidenceABIVersion {
		return invalidEvidence(fmt.Sprintf("unsupported abi %d", e.ABI))
	}
	if err := e.State.Validate(); err != nil {
		return invalidEvidence(err.Error())
	}
	profile, supported := evidenceProfiles[e.Kind]
	if !supported {
		return invalidEvidence("unsupported evidence kind")
	}
	if e.MediaType != profile.mediaType {
		return invalidEvidence("unsupported media type for evidence kind")
	}
	if profile.text && !utf8.Valid(e.Payload) {
		return invalidEvidence("evidence payload is not text")
	}
	if len(e.Payload) == 0 {
		return invalidEvidence("payload is empty")
	}
	return nil
}

type verifierSet map[EvidenceKind]Verifier

var commonVerifiers = verifierSet{
	EvidenceSigstoreBundle: SigstoreVerifier{},
	EvidenceX509CMS:        X509CMSVerifier{},
}

// VerifyEvidence dispatches only on the tagged kind. An absent adapter is an
// unsupported result, not absence of evidence and not an operational error.
func VerifyEvidence(evidence SignatureEvidence, trust TrustMaterial, now time.Time) (VerificationResult, error) {
	digest, _ := evidence.State.Digest()
	base := VerificationResult{
		EvidenceKind:        evidence.Kind,
		StateDigest:         digest,
		Cryptographic:       CryptographicInvalid,
		Chain:               ChainNotApplicable,
		SigningTime:         SigningTimeInvalid,
		Revocation:          RevocationUnknown,
		OriginAuthorization: string(OriginUnsupported),
	}
	if err := evidence.ValidateEnvelope(); err != nil {
		base.ReasonCode = evidenceReason(err)
		base.Diagnostic = safeDiagnostic(err.Error())
		return base, nil
	}
	verifier, ok := commonVerifiers[evidence.Kind]
	if !ok {
		base.Cryptographic = CryptographicUnsupported
		base.ReasonCode = "unsupported-evidence-kind"
		base.Diagnostic = "this cpak build has no verifier for the evidence kind"
		return base, nil
	}
	return verifier.Verify(evidence, trust, now)
}

func evidenceReason(err error) string {
	var invalid *InvalidEvidenceError
	if errors.As(err, &invalid) {
		switch {
		case strings.Contains(invalid.Reason, "abi"):
			return "unsupported-evidence-abi"
		case strings.Contains(invalid.Reason, "kind"):
			return "unsupported-evidence-kind"
		case strings.Contains(invalid.Reason, "media type"):
			return "unsupported-evidence-media-type"
		case strings.Contains(invalid.Reason, "empty"):
			return "empty-evidence-payload"
		}
	}
	return "invalid-evidence-envelope"
}

func safeDiagnostic(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	encoded := []byte(value)
	if len(encoded) > 512 {
		encoded = encoded[:512]
		for !utf8.Valid(encoded) && len(encoded) > 0 {
			encoded = encoded[:len(encoded)-1]
		}
	}
	return string(encoded)
}

// DecodeStoredEvidence accepts the frozen tagged form and the v2.6.0 nested
// Sigstore form. It rejects duplicate keys before encoding/json can merge them.
func DecodeStoredEvidence(document []byte) (SignatureEvidence, bool, error) {
	if err := RejectDuplicateJSONKeys(document); err != nil {
		return SignatureEvidence{}, false, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		return SignatureEvidence{}, false, fmt.Errorf("decode signature evidence: %w", err)
	}
	_, hasABI := fields["abi"]
	_, hasKind := fields["kind"]
	_, hasMedia := fields["media_type"]
	_, hasPayload := fields["payload"]
	_, hasBundle := fields["bundle"]
	tagged := hasABI || hasKind || hasMedia || hasPayload
	if tagged && hasBundle {
		return SignatureEvidence{}, false, invalidEvidence("legacy and tagged fields are mixed")
	}
	if !tagged {
		if !hasBundle {
			return SignatureEvidence{}, false, invalidEvidence("signature is neither legacy nor tagged evidence")
		}
		var legacy struct {
			State  State  `json:"state"`
			Bundle []byte `json:"bundle"`
		}
		if err := decodeStrict(document, &legacy); err != nil {
			return SignatureEvidence{}, false, fmt.Errorf("decode legacy signature evidence: %w", err)
		}
		evidence := NewSigstoreEvidence(legacy.State, legacy.Bundle)
		if err := evidence.ValidateEnvelope(); err != nil {
			return SignatureEvidence{}, false, err
		}
		return evidence, true, nil
	}
	var evidence SignatureEvidence
	if err := decodeStrict(document, &evidence); err != nil {
		return SignatureEvidence{}, false, fmt.Errorf("decode tagged signature evidence: %w", err)
	}
	if err := evidence.ValidateEnvelope(); err != nil {
		return SignatureEvidence{}, false, err
	}
	return evidence, false, nil
}

func decodeStrict(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("contains multiple JSON values")
	}
	return nil
}

// RejectDuplicateJSONKeys walks a complete JSON document and refuses repeated
// names at every nesting level before encoding/json can merge them.
func RejectDuplicateJSONKeys(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not text")
				}
				if _, duplicate := seen[key]; duplicate {
					return invalidEvidence(fmt.Sprintf("duplicate JSON key %q", key))
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return fmt.Errorf("decode signature evidence: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("signature evidence contains multiple JSON values")
		}
		return fmt.Errorf("decode signature evidence: %w", err)
	}
	return nil
}

// NormalizeOIDCIdentity derives the stable publisher identity only from
// certificate claims already proven by the Sigstore adapter.
func NormalizeOIDCIdentity(identity Identity) (*PublisherIdentity, OriginAuthorization) {
	repo, repoOK := canonicalOrigin(identity.Repo)
	if !repoOK {
		return nil, OriginAuthorization{Status: OriginUnsupported, ReasonCode: "missing-or-invalid-source-repository"}
	}
	preimage := "cpak.publisher.oidc.v1\nissuer=" + identity.Issuer + "\nrepository=" + repo + "\n"
	sum := sha256.Sum256([]byte(preimage))
	publisher := &PublisherIdentity{
		Kind:        "sigstore-oidc-v1",
		ID:          "oidc-v1-sha256:" + hex.EncodeToString(sum[:]),
		DisplayName: repo,
		Issuer:      identity.Issuer,
		Repository:  repo,
		Assurance:   "keyless-oidc",
		Claims:      map[string]string{"subject": identity.Subject},
	}
	if identity.Issuer != githubActionsIssuer {
		return publisher, OriginAuthorization{Status: OriginUnsupported, ReasonCode: "unsupported-oidc-issuer"}
	}
	return publisher, OriginAuthorization{Status: OriginForeign, ReasonCode: "source-repository-does-not-match-origin"}
}

func AuthorizeOIDCOrigin(publisher *PublisherIdentity, origin string) OriginAuthorization {
	if publisher == nil || publisher.Kind != "sigstore-oidc-v1" || publisher.Issuer != githubActionsIssuer {
		return OriginAuthorization{Status: OriginUnsupported, ReasonCode: "unsupported-publisher-identity"}
	}
	want, ok := canonicalOrigin(origin)
	if !ok || want != origin {
		return OriginAuthorization{Status: OriginUnsupported, ReasonCode: "invalid-package-origin"}
	}
	if publisher.Repository != want {
		return OriginAuthorization{Status: OriginForeign, ReasonCode: "source-repository-does-not-match-origin"}
	}
	return OriginAuthorization{Status: OriginAuthorized, ReasonCode: "oidc-repository-matches-origin"}
}

// LegacyVerified projects a common result onto the v2.6.0 public result. It
// exists only for callers whose API has not changed; policy decisions must use
// OriginAuthorization from the common result.
func LegacyVerified(result VerificationResult, state State) (Verified, error) {
	if result.Cryptographic != CryptographicVerified {
		if result.failure != nil {
			return Verified{}, result.failure
		}
		return Verified{}, fmt.Errorf("signature: %s: %s", result.ReasonCode, result.Diagnostic)
	}
	if result.Chain == ChainUntrusted || result.Chain == ChainInvalid {
		return Verified{}, fmt.Errorf("signature: %s: %s", result.ReasonCode, result.Diagnostic)
	}
	if result.SigningTime == SigningTimeMissing || result.SigningTime == SigningTimeExpired ||
		result.SigningTime == SigningTimeNotYetValid || result.SigningTime == SigningTimeInvalid {
		return Verified{}, fmt.Errorf("signature: %s: %s", result.ReasonCode, result.Diagnostic)
	}
	if result.Revocation == RevocationRevoked || result.Revocation == RevocationStale {
		return Verified{}, fmt.Errorf("signature: %s: %s", result.ReasonCode, result.Diagnostic)
	}
	if result.legacyIdentity != nil {
		return Verified{State: state, Identity: *result.legacyIdentity, Publisher: result.Publisher}, nil
	}
	if result.Publisher == nil {
		return Verified{}, errors.New("signature: verified evidence names no usable publisher identity")
	}
	verified := Verified{State: state, Publisher: result.Publisher}
	if result.Publisher.Kind == "sigstore-oidc-v1" {
		verified.Identity = Identity{
			Issuer: result.Publisher.Issuer, Subject: result.Publisher.Claims["subject"], Repo: result.Publisher.Repository,
		}
	}
	return verified, nil
}
