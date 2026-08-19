/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

// Package reputation verifies and serves authenticated publisher-reputation
// snapshots. It has no network or filesystem path: callers decide where an
// authority and its latest snapshot come from.
package reputation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
)

const (
	SnapshotABIVersion = 1
	SnapshotMediaType  = "application/vnd.cpak.publisher-reputation.snapshot.v1+json"
	MaxSnapshotSize    = 16 << 20
	MaxEntries         = 100_000
	MaxSequence        = 1<<53 - 1
	MaxReasonCode      = 64
	MaxAuthoritySize   = 64 << 10
)

type Status string

const (
	Unknown     Status = "unknown"
	Established Status = "established"
	Caution     Status = "caution"
	Blocked     Status = "blocked"
	Unavailable Status = "unavailable"
)

var (
	ErrInvalidSnapshot = errors.New("reputation: snapshot is not valid")
	ErrUnavailable     = errors.New("reputation: provider is unavailable")
	namePattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	publisherPattern   = regexp.MustCompile(`^(oidc-v1-sha256|x509-spki-sha256):[0-9a-f]{64}$`)
)

// Authority is configured independently from code-signing roots and
// publisher certificates. The private half never belongs in this type.
type Authority struct {
	ProviderID string
	KeyID      string
	PublicKey  ed25519.PublicKey
}

type authorityDocument struct {
	ABI        int    `json:"abi"`
	ProviderID string `json:"provider_id"`
	KeyID      string `json:"key_id"`
	PublicKey  []byte `json:"public_key"`
}

func NewAuthority(providerID string, publicKey ed25519.PublicKey) (Authority, error) {
	authority := Authority{
		ProviderID: providerID,
		KeyID:      KeyID(publicKey),
		PublicKey:  append(ed25519.PublicKey(nil), publicKey...),
	}
	if err := authority.Validate(); err != nil {
		return Authority{}, err
	}
	return authority, nil
}

func (a Authority) Validate() error {
	if !namePattern.MatchString(a.ProviderID) {
		return invalid("provider id is not a bounded lowercase identifier")
	}
	if len(a.PublicKey) != ed25519.PublicKeySize {
		return invalid("provider public key is not Ed25519")
	}
	if a.KeyID != KeyID(a.PublicKey) {
		return invalid("provider key id does not match its public key")
	}
	return nil
}

func KeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "ed25519-sha256:" + hex.EncodeToString(digest[:])
}

func MarshalAuthority(authority Authority) ([]byte, error) {
	if err := authority.Validate(); err != nil {
		return nil, err
	}
	document, err := json.MarshalIndent(authorityDocument{
		ABI: SnapshotABIVersion, ProviderID: authority.ProviderID,
		KeyID: authority.KeyID, PublicKey: authority.PublicKey,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode reputation authority: %w", err)
	}
	return append(document, '\n'), nil
}

func ParseAuthority(document []byte) (Authority, error) {
	if len(document) == 0 || len(document) > MaxAuthoritySize {
		return Authority{}, invalid("authority document size is outside the supported range")
	}
	if err := rejectDuplicateKeys(document); err != nil {
		return Authority{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	wire := authorityDocument{}
	if err := decoder.Decode(&wire); err != nil {
		return Authority{}, invalid("decode authority: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Authority{}, invalid("authority contains multiple JSON values")
	}
	if wire.ABI != SnapshotABIVersion {
		return Authority{}, invalid("unsupported authority abi %d", wire.ABI)
	}
	authority := Authority{ProviderID: wire.ProviderID, KeyID: wire.KeyID, PublicKey: ed25519.PublicKey(wire.PublicKey)}
	if err := authority.Validate(); err != nil {
		return Authority{}, err
	}
	return authority, nil
}

type Entry struct {
	PublisherID string `json:"publisher_id"`
	Status      Status `json:"status"`
	ReasonCode  string `json:"reason_code"`
}

type Signed struct {
	Sequence  uint64  `json:"sequence"`
	IssuedAt  string  `json:"issued_at"`
	ExpiresAt string  `json:"expires_at"`
	Entries   []Entry `json:"entries"`
}

// Snapshot is returned only after its schema, authority, signature, time, and
// contents have all been verified.
type Snapshot struct {
	ProviderID string
	KeyID      string
	Sequence   uint64
	IssuedAt   time.Time
	ExpiresAt  time.Time
	entries    []Entry
}

func (s Snapshot) EntryCount() int { return len(s.entries) }

type Result struct {
	ProviderID  string    `json:"provider_id"`
	PublisherID string    `json:"publisher_id"`
	Status      Status    `json:"status"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Sequence    uint64    `json:"sequence"`
	ReasonCode  string    `json:"reason_code"`
}

type Provider interface {
	Lookup(publisherID string) Result
}

type OfflineProvider struct {
	snapshot Snapshot
}

func NewOfflineProvider(snapshot Snapshot) OfflineProvider {
	return OfflineProvider{snapshot: snapshot}
}

func (p OfflineProvider) Lookup(publisherID string) Result {
	result := Result{
		ProviderID:  p.snapshot.ProviderID,
		PublisherID: publisherID,
		Status:      Unknown,
		IssuedAt:    p.snapshot.IssuedAt,
		ExpiresAt:   p.snapshot.ExpiresAt,
		Sequence:    p.snapshot.Sequence,
		ReasonCode:  "publisher-not-listed",
	}
	index := sort.Search(len(p.snapshot.entries), func(index int) bool {
		return p.snapshot.entries[index].PublisherID >= publisherID
	})
	if index < len(p.snapshot.entries) && p.snapshot.entries[index].PublisherID == publisherID {
		entry := p.snapshot.entries[index]
		result.Status = entry.Status
		result.ReasonCode = entry.ReasonCode
	}
	return result
}

func UnavailableResult(providerID, publisherID, reasonCode string) Result {
	return Result{
		ProviderID:  providerID,
		PublisherID: publisherID,
		Status:      Unavailable,
		ReasonCode:  reasonCode,
	}
}

func ValidPublisherID(value string) bool {
	return publisherPattern.MatchString(value)
}

func (r Result) Validate() error {
	if r.ProviderID != "" && !namePattern.MatchString(r.ProviderID) {
		return errors.New("reputation result has an invalid provider id")
	}
	if !ValidPublisherID(r.PublisherID) {
		return errors.New("reputation result has an invalid publisher id")
	}
	if r.Status != Unavailable && !validEntryStatus(r.Status) {
		return errors.New("reputation result has an invalid status")
	}
	if !namePattern.MatchString(r.ReasonCode) {
		return errors.New("reputation result has an invalid reason code")
	}
	if r.Status == Unavailable {
		if !r.IssuedAt.IsZero() || !r.ExpiresAt.IsZero() || r.Sequence != 0 {
			return errors.New("unavailable reputation result claims snapshot metadata")
		}
		return nil
	}
	if r.ProviderID == "" || r.Sequence == 0 || r.Sequence > MaxSequence || r.IssuedAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) {
		return errors.New("reputation result is missing authenticated snapshot metadata")
	}
	return nil
}

func validEntryStatus(status Status) bool {
	switch status {
	case Unknown, Established, Caution, Blocked:
		return true
	default:
		return false
	}
}

func parseTimestamp(field, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != value {
		return time.Time{}, invalid("%s is not a canonical UTC whole-second RFC 3339 timestamp", field)
	}
	return parsed, nil
}

func validateSigned(signed Signed) (time.Time, time.Time, error) {
	if signed.Sequence == 0 || signed.Sequence > MaxSequence {
		return time.Time{}, time.Time{}, invalid("sequence is outside the supported range")
	}
	issued, err := parseTimestamp("issued_at", signed.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expires, err := parseTimestamp("expires_at", signed.ExpiresAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !expires.After(issued) {
		return time.Time{}, time.Time{}, invalid("expires_at is not after issued_at")
	}
	if len(signed.Entries) > MaxEntries {
		return time.Time{}, time.Time{}, invalid("snapshot has too many entries")
	}
	previous := ""
	for index, entry := range signed.Entries {
		if !publisherPattern.MatchString(entry.PublisherID) {
			return time.Time{}, time.Time{}, invalid("entry %d has an unsupported publisher id", index)
		}
		if !validEntryStatus(entry.Status) {
			return time.Time{}, time.Time{}, invalid("entry %d has an unsupported status", index)
		}
		if !namePattern.MatchString(entry.ReasonCode) || len(entry.ReasonCode) > MaxReasonCode {
			return time.Time{}, time.Time{}, invalid("entry %d has an unsafe reason code", index)
		}
		if previous != "" && entry.PublisherID <= previous {
			return time.Time{}, time.Time{}, invalid("entries are not uniquely sorted by publisher id")
		}
		previous = entry.PublisherID
	}
	return issued, expires, nil
}

func invalid(message string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSnapshot, fmt.Sprintf(message, args...))
}
