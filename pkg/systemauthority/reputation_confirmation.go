/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package systemauthority

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/mirkobrombin/cpak/pkg/reputation"
	"github.com/mirkobrombin/cpak/pkg/trustpolicy"
)

const (
	reputationConfirmationTTL   = 5 * time.Minute
	reputationConfirmationLimit = 1024
)

type reputationConfirmationChallenge struct {
	ExpiresAt      time.Time
	UID            uint32
	Origin         string
	Generation     uint64
	LaunchRoot     string
	StateDigest    string
	ProviderID     string
	PublisherID    string
	Status         reputation.Status
	Sequence       uint64
	ProviderReason string
	PolicyReason   string
}

type reputationConfirmationStore struct {
	mu      sync.Mutex
	entries map[string]reputationConfirmationChallenge
	random  func([]byte) (int, error)
}

var defaultReputationConfirmations = &reputationConfirmationStore{}

func (s *reputationConfirmationStore) Issue(enrolment Enrolment, result reputation.Result, decision trustpolicy.ReputationDecision, now time.Time) (string, error) {
	challenge, err := newReputationConfirmationChallenge(enrolment, result, decision, now)
	if err != nil {
		return "", err
	}
	random := s.random
	if random == nil {
		random = rand.Read
	}
	bytes := make([]byte, 32)
	if count, err := random(bytes); err != nil || count != len(bytes) {
		return "", errors.New("create reputation confirmation challenge")
	}
	token := base64.RawURLEncoding.EncodeToString(bytes)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = make(map[string]reputationConfirmationChallenge)
	}
	s.prune(now)
	if len(s.entries) >= reputationConfirmationLimit {
		var oldestToken string
		var oldest time.Time
		for candidate, entry := range s.entries {
			if oldestToken == "" || entry.ExpiresAt.Before(oldest) {
				oldestToken, oldest = candidate, entry.ExpiresAt
			}
		}
		delete(s.entries, oldestToken)
	}
	s.entries[token] = challenge
	return token, nil
}

func (s *reputationConfirmationStore) Consume(token string, enrolment Enrolment, now time.Time) (reputationConfirmationChallenge, bool) {
	if token == "" || len(token) > 64 {
		return reputationConfirmationChallenge{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	challenge, found := s.entries[token]
	if found {
		delete(s.entries, token)
	}
	if !found || !challenge.MatchesEnrolment(enrolment) {
		return reputationConfirmationChallenge{}, false
	}
	return challenge, true
}

func (s *reputationConfirmationStore) prune(now time.Time) {
	for token, entry := range s.entries {
		if !now.Before(entry.ExpiresAt) {
			delete(s.entries, token)
		}
	}
}

func newReputationConfirmationChallenge(enrolment Enrolment, result reputation.Result, decision trustpolicy.ReputationDecision, now time.Time) (reputationConfirmationChallenge, error) {
	if enrolment.Signature == nil {
		return reputationConfirmationChallenge{}, errors.New("reputation confirmation requires a signed enrolment")
	}
	digest, err := enrolment.Signature.State.Digest()
	if err != nil {
		return reputationConfirmationChallenge{}, err
	}
	return reputationConfirmationChallenge{
		ExpiresAt: now.Add(reputationConfirmationTTL), UID: enrolment.UID, Origin: enrolment.Origin,
		Generation: enrolment.Generation, LaunchRoot: enrolment.LaunchRoot, StateDigest: digest,
		ProviderID: result.ProviderID, PublisherID: result.PublisherID, Status: result.Status,
		Sequence: result.Sequence, ProviderReason: result.ReasonCode, PolicyReason: decision.ReasonCode,
	}, nil
}

func (c reputationConfirmationChallenge) MatchesEnrolment(enrolment Enrolment) bool {
	if enrolment.Signature == nil {
		return false
	}
	digest, err := enrolment.Signature.State.Digest()
	return err == nil && c.UID == enrolment.UID && c.Origin == enrolment.Origin &&
		c.Generation == enrolment.Generation && c.LaunchRoot == enrolment.LaunchRoot && c.StateDigest == digest
}

func (c reputationConfirmationChallenge) MatchesWarning(result reputation.Result, decision trustpolicy.ReputationDecision) bool {
	return c.ProviderID == result.ProviderID && c.PublisherID == result.PublisherID && c.Status == result.Status &&
		c.Sequence == result.Sequence && c.ProviderReason == result.ReasonCode && c.PolicyReason == decision.ReasonCode
}
