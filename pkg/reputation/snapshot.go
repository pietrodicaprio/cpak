/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package reputation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/mirkobrombin/cpak/pkg/signature"
)

type envelope struct {
	ABI        int             `json:"abi"`
	ProviderID string          `json:"provider_id"`
	KeyID      string          `json:"key_id"`
	Signed     json.RawMessage `json:"signed"`
	Signature  []byte          `json:"signature"`
}

// Verify authenticates a complete snapshot document against one configured
// provider authority. Host freshness is evaluated against the caller's single
// injected time.
func Verify(document []byte, authority Authority, now time.Time) (Snapshot, error) {
	if len(document) == 0 || len(document) > MaxSnapshotSize {
		return Snapshot{}, invalid("document size is outside the supported range")
	}
	if err := authority.Validate(); err != nil {
		return Snapshot{}, fmt.Errorf("configure reputation authority: %w", err)
	}
	parsed, signed, canonical, err := parseEnvelope(document)
	if err != nil {
		return Snapshot{}, err
	}
	if parsed.ABI != SnapshotABIVersion {
		return Snapshot{}, invalid("unsupported abi %d", parsed.ABI)
	}
	if parsed.ProviderID != authority.ProviderID {
		return Snapshot{}, invalid("snapshot provider does not match the configured provider")
	}
	if parsed.KeyID != authority.KeyID {
		return Snapshot{}, invalid("snapshot key does not match the configured provider key")
	}
	if len(parsed.Signature) != ed25519.SignatureSize || !ed25519.Verify(authority.PublicKey, canonical, parsed.Signature) {
		return Snapshot{}, invalid("signature does not verify under the configured provider key")
	}
	issued, expires, err := validateSigned(signed)
	if err != nil {
		return Snapshot{}, err
	}
	if issued.After(now) {
		return Snapshot{}, fmt.Errorf("%w: snapshot was issued in the future", ErrUnavailable)
	}
	if !now.Before(expires) {
		return Snapshot{}, fmt.Errorf("%w: snapshot has expired", ErrUnavailable)
	}
	return Snapshot{
		ProviderID: parsed.ProviderID,
		KeyID:      parsed.KeyID,
		Sequence:   signed.Sequence,
		IssuedAt:   issued,
		ExpiresAt:  expires,
		entries:    append([]Entry(nil), signed.Entries...),
	}, nil
}

// Sign creates the versioned wire envelope. The signed object is canonicalized
// with RFC 8785 before Ed25519 signs it, so independent actors can reproduce
// the exact verification input.
func Sign(providerID string, privateKey ed25519.PrivateKey, signed Signed) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, invalid("provider private key is not Ed25519")
	}
	authority, err := NewAuthority(providerID, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	if _, _, err := validateSigned(signed); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return nil, fmt.Errorf("encode reputation snapshot: %w", err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize reputation snapshot: %w", err)
	}
	document, err := json.MarshalIndent(envelope{
		ABI:        SnapshotABIVersion,
		ProviderID: authority.ProviderID,
		KeyID:      authority.KeyID,
		Signed:     canonical,
		Signature:  ed25519.Sign(privateKey, canonical),
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode signed reputation snapshot: %w", err)
	}
	return append(document, '\n'), nil
}

func parseEnvelope(document []byte) (envelope, Signed, []byte, error) {
	if err := signature.RejectDuplicateJSONKeys(document); err != nil {
		return envelope{}, Signed{}, nil, invalid("duplicate or malformed JSON: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	parsed := envelope{}
	if err := decoder.Decode(&parsed); err != nil {
		return envelope{}, Signed{}, nil, invalid("decode envelope: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return envelope{}, Signed{}, nil, invalid("document contains multiple JSON values")
	}
	if len(parsed.Signed) == 0 || bytes.Equal(parsed.Signed, []byte("null")) {
		return envelope{}, Signed{}, nil, invalid("signed object is missing")
	}
	signedDecoder := json.NewDecoder(bytes.NewReader(parsed.Signed))
	signedDecoder.DisallowUnknownFields()
	signed := Signed{}
	if err := signedDecoder.Decode(&signed); err != nil {
		return envelope{}, Signed{}, nil, invalid("decode signed object: %v", err)
	}
	if err := signedDecoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return envelope{}, Signed{}, nil, invalid("signed object contains multiple JSON values")
	}
	canonical, err := jsoncanonicalizer.Transform(parsed.Signed)
	if err != nil {
		return envelope{}, Signed{}, nil, invalid("canonicalize signed object: %v", err)
	}
	return parsed, signed, canonical, nil
}
