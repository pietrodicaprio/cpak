/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package systemauthority

import (
	"errors"
	"testing"
	"time"

	"github.com/mirkobrombin/cpak/pkg/reputation"
	"github.com/mirkobrombin/cpak/pkg/signature"
	"github.com/mirkobrombin/cpak/pkg/trustpolicy"
)

func testNormalizedPublisher(t *testing.T) *signature.PublisherIdentity {
	t.Helper()
	publisher, authorization := signature.NormalizeOIDCIdentity(testSignatureIdentity(testAnchor().Origin))
	if publisher == nil || authorization.Status != signature.OriginForeign {
		// Normalization cannot authorize without an origin argument; the adapter
		// performs that separate exact comparison after this step.
		if publisher == nil {
			t.Fatal("test identity did not normalize")
		}
	}
	return publisher
}

func testReputationTrustPolicy(t *testing.T, ledger AnchorLedger, mode trustpolicy.ReputationMode, publisherID string) {
	t.Helper()
	providerID := "cpak-poc"
	if mode == trustpolicy.ReputationOff {
		providerID = ""
	}
	policy := trustpolicy.Policy{
		ABI:                  trustpolicy.CurrentABIVersion,
		X509:                 &trustpolicy.X509Policy{Revocation: "allow-unknown"},
		Reputation:           &trustpolicy.ReputationPolicy{Mode: mode, ProviderID: providerID},
		RequirePublisher:     true,
		ApprovedPublisherIDs: []string{publisherID},
	}
	store := TrustStore{Directory: ledger.Directory, OwnerUID: ledger.OwnerUID}
	if err := store.Set(policy); err != nil {
		t.Fatal(err)
	}
}

func authorityReputationResult(publisherID string, status reputation.Status) reputation.Result {
	return reputation.Result{
		ProviderID: "cpak-poc", PublisherID: publisherID, Status: status,
		IssuedAt: reputationNow.Add(-time.Hour), ExpiresAt: reputationNow.Add(time.Hour), Sequence: 5, ReasonCode: "provider-result",
	}
}

func TestAuthorityAppliesReputationOnlyAfterSignatureAndAdministratorPolicy(t *testing.T) {
	for name, test := range map[string]struct {
		prepare     func(*testing.T, AnchorLedger, string)
		wantLookups int
	}{
		"invalid signature": {
			prepare: func(t *testing.T, ledger AnchorLedger, publisherID string) {
				testReputationTrustPolicy(t, ledger, trustpolicy.ReputationRequireEstablished, publisherID)
				useBundleVerifier(t, func([]byte, signature.State) (signature.Verified, error) {
					return signature.Verified{}, errors.New("invalid signature")
				})
			},
		},
		"administrator origin denial": {
			prepare: func(t *testing.T, ledger AnchorLedger, publisherID string) {
				policy := trustpolicy.Policy{
					ABI: trustpolicy.CurrentABIVersion, X509: &trustpolicy.X509Policy{Revocation: "allow-unknown"},
					Reputation:       &trustpolicy.ReputationPolicy{Mode: trustpolicy.ReputationRequireEstablished, ProviderID: "cpak-poc"},
					RequirePublisher: true, ApprovedPublisherIDs: []string{publisherID}, ApprovedOrigins: []string{"github.com/example/allowed"},
				}
				if err := (TrustStore{Directory: ledger.Directory, OwnerUID: ledger.OwnerUID}).Set(policy); err != nil {
					t.Fatal(err)
				}
				acceptSignaturesOf(t, testAnchor().Origin)
			},
		},
		"accepted prerequisites": {
			prepare: func(t *testing.T, ledger AnchorLedger, publisherID string) {
				testReputationTrustPolicy(t, ledger, trustpolicy.ReputationRequireEstablished, publisherID)
				acceptSignaturesOf(t, testAnchor().Origin)
			},
			wantLookups: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			ledger := testAnchorLedger(t)
			publisher := testNormalizedPublisher(t)
			test.prepare(t, ledger, publisher.ID)
			lookups := 0
			ledger.Now = func() time.Time { return reputationNow }
			ledger.ReputationLookup = func(publisherID string, _ time.Time) (reputation.Result, error) {
				lookups++
				return authorityReputationResult(publisherID, reputation.Established), nil
			}
			_ = ledger.Record(Enrolment{Anchor: testAnchor(), Signature: testSignedState(1)})
			if lookups != test.wantLookups {
				t.Fatalf("provider consulted %d times, want %d", lookups, test.wantLookups)
			}
		})
	}
}

func TestAuthorityReputationModesControlEnrolmentAndRecordedEvidence(t *testing.T) {
	cases := []struct {
		name       string
		mode       trustpolicy.ReputationMode
		status     reputation.Status
		wantRecord bool
	}{
		{"audit blocked", trustpolicy.ReputationAudit, reputation.Blocked, true},
		{"warn established", trustpolicy.ReputationWarn, reputation.Established, true},
		{"warn blocked", trustpolicy.ReputationWarn, reputation.Blocked, false},
		{"require established", trustpolicy.ReputationRequireEstablished, reputation.Established, true},
		{"require unknown", trustpolicy.ReputationRequireEstablished, reputation.Unknown, false},
		{"require caution", trustpolicy.ReputationRequireEstablished, reputation.Caution, false},
		{"require blocked", trustpolicy.ReputationRequireEstablished, reputation.Blocked, false},
		{"require unavailable", trustpolicy.ReputationRequireEstablished, reputation.Unavailable, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ledger := testAnchorLedger(t)
			publisher := testNormalizedPublisher(t)
			testReputationTrustPolicy(t, ledger, test.mode, publisher.ID)
			acceptSignaturesOf(t, testAnchor().Origin)
			ledger.Now = func() time.Time { return reputationNow }
			ledger.ReputationLookup = func(publisherID string, _ time.Time) (reputation.Result, error) {
				if test.status == reputation.Unavailable {
					return reputation.UnavailableResult("cpak-poc", publisherID, "snapshot-unavailable"), errors.New("snapshot expired")
				}
				return authorityReputationResult(publisherID, test.status), nil
			}
			err := ledger.Record(Enrolment{Anchor: testAnchor(), Signature: testSignedState(1)})
			if test.wantRecord && err != nil {
				t.Fatalf("enrolment was refused: %v", err)
			}
			if !test.wantRecord && !errors.Is(err, ErrTrustRefused) {
				t.Fatalf("got %v, want policy refusal", err)
			}
			recorded, found, readErr := ledger.Recorded(testAnchor().UID, testAnchor().Origin)
			if readErr != nil || found != test.wantRecord {
				t.Fatalf("recorded=%v err=%v", found, readErr)
			}
			if test.wantRecord {
				if recorded.Verification == nil || recorded.Verification.Publisher == nil || recorded.Verification.StateDigest == "" {
					t.Fatalf("record dropped authority verification: %+v", recorded.Verification)
				}
				if recorded.Reputation == nil || recorded.ReputationDecision == nil || recorded.Reputation.Status != test.status {
					t.Fatalf("record dropped reputation evidence: %+v", recorded)
				}
				if recorded.SignatureMode != SignaturesOptional || recorded.ReputationMode != test.mode {
					t.Fatalf("recorded policy modes = %s/%s", recorded.SignatureMode, recorded.ReputationMode)
				}
			}
		})
	}
}

func TestAuthorityRecordsAWarningOnlyAfterTheExactSingleUseConfirmation(t *testing.T) {
	ledger := testAnchorLedger(t)
	ledger.ReputationConfirmations = &reputationConfirmationStore{}
	publisher := testNormalizedPublisher(t)
	testReputationTrustPolicy(t, ledger, trustpolicy.ReputationWarn, publisher.ID)
	acceptSignaturesOf(t, testAnchor().Origin)
	ledger.Now = func() time.Time { return reputationNow }
	status := reputation.Unknown
	lookups := 0
	ledger.ReputationLookup = func(publisherID string, _ time.Time) (reputation.Result, error) {
		lookups++
		return authorityReputationResult(publisherID, status), nil
	}
	enrolment := Enrolment{Anchor: testAnchor(), Signature: testSignedState(1)}

	err := ledger.Record(enrolment)
	var confirmation *ReputationConfirmationRequiredError
	if !errors.As(err, &confirmation) || confirmation.Token == "" || confirmation.Decision.Action != trustpolicy.ActionWarn ||
		confirmation.SignatureMode != SignaturesOptional || confirmation.ReputationMode != trustpolicy.ReputationWarn {
		t.Fatalf("first decision = %v", err)
	}
	if _, found, readErr := ledger.Recorded(enrolment.UID, enrolment.Origin); readErr != nil || found {
		t.Fatalf("warning was recorded before confirmation: found=%v err=%v", found, readErr)
	}

	status = reputation.Blocked
	if err := ledger.RecordConfirmed(enrolment, confirmation.Token); !errors.Is(err, ErrTrustRefused) {
		t.Fatalf("confirmation overrode a changed block: %v", err)
	}
	status = reputation.Unknown
	err = ledger.Record(enrolment)
	if !errors.As(err, &confirmation) || confirmation.Token == "" {
		t.Fatalf("fresh warning did not issue a fresh confirmation: %v", err)
	}
	if err := ledger.RecordConfirmed(enrolment, confirmation.Token); err != nil {
		t.Fatalf("exact warning confirmation was refused: %v", err)
	}
	if err := ledger.RecordConfirmed(enrolment, confirmation.Token); err == nil || !errors.Is(err, ErrReputationConfirmationRequired) {
		t.Fatalf("single-use confirmation was replayed: %v", err)
	}
	recorded, found, err := ledger.Recorded(enrolment.UID, enrolment.Origin)
	if err != nil || !found || recorded.ReputationDecision == nil || recorded.ReputationDecision.Action != trustpolicy.ActionWarn {
		t.Fatalf("recorded warning = %+v found=%v err=%v", recorded, found, err)
	}
	if lookups != 5 {
		t.Fatalf("provider consulted %d times, want 5 fresh decisions", lookups)
	}
}

func TestReputationOffDoesNotConsultAProvider(t *testing.T) {
	ledger := testAnchorLedger(t)
	publisher := testNormalizedPublisher(t)
	testReputationTrustPolicy(t, ledger, trustpolicy.ReputationOff, publisher.ID)
	acceptSignaturesOf(t, testAnchor().Origin)
	ledger.ReputationLookup = func(string, time.Time) (reputation.Result, error) {
		t.Fatal("reputation provider was consulted in off mode")
		return reputation.Result{}, nil
	}
	if err := ledger.Record(Enrolment{Anchor: testAnchor(), Signature: testSignedState(1)}); err != nil {
		t.Fatal(err)
	}
	recorded, _, err := ledger.Recorded(testAnchor().UID, testAnchor().Origin)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.Reputation != nil || recorded.ReputationDecision != nil {
		t.Fatal("off mode recorded a reputation verdict")
	}
	if recorded.SignatureMode != SignaturesOptional || recorded.ReputationMode != trustpolicy.ReputationOff {
		t.Fatalf("recorded policy modes = %s/%s", recorded.SignatureMode, recorded.ReputationMode)
	}
}

func TestRecordedAndLaunchAnchorReadsNeverConsultReputationAgain(t *testing.T) {
	ledger := testAnchorLedger(t)
	publisher := testNormalizedPublisher(t)
	testReputationTrustPolicy(t, ledger, trustpolicy.ReputationAudit, publisher.ID)
	acceptSignaturesOf(t, testAnchor().Origin)
	ledger.Now = func() time.Time { return reputationNow }
	lookups := 0
	ledger.ReputationLookup = func(publisherID string, _ time.Time) (reputation.Result, error) {
		lookups++
		return authorityReputationResult(publisherID, reputation.Established), nil
	}
	if err := ledger.Record(Enrolment{Anchor: testAnchor(), Signature: testSignedState(1)}); err != nil {
		t.Fatal(err)
	}
	if lookups != 1 {
		t.Fatalf("enrolment consulted reputation %d times", lookups)
	}
	ledger.ReputationLookup = func(string, time.Time) (reputation.Result, error) {
		t.Fatal("a recorded or launch-anchor read consulted reputation")
		return reputation.Result{}, nil
	}
	if _, found, err := ledger.Recorded(testAnchor().UID, testAnchor().Origin); err != nil || !found {
		t.Fatalf("recorded read found=%v err=%v", found, err)
	}
	if _, found, err := ledger.Load(testAnchor().UID, testAnchor().Origin); err != nil || !found {
		t.Fatalf("launch-anchor read found=%v err=%v", found, err)
	}
}
