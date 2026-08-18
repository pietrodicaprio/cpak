/*
 * Copyright (c) 2025 Fabricators and Mirko Brombin <brombin94@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package systemauthority

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mirkobrombin/cpak/pkg/signature"
)

func probeState() signature.State {
	return signature.State{
		ABI:            1,
		Origin:         "github.com/containerpak/demo",
		ManifestSHA256: strings.Repeat("ab", 32),
		ImageDigest:    "sha256:" + strings.Repeat("cd", 32),
		Generation:     3,
	}
}

func probeEvidence() signature.SignatureEvidence {
	return signature.NewSigstoreEvidence(probeState(), []byte("the bundle"))
}

func useDirectVerifier(t *testing.T, verify func(signature.SignatureEvidence, signature.TrustMaterial, time.Time) (signature.VerificationResult, error)) {
	t.Helper()
	saved := verifyEvidenceDirect
	t.Cleanup(func() { verifyEvidenceDirect = saved })
	verifyEvidenceDirect = verify
}

func TestTheChildAnswersWhoSignedWhenTheBundleStands(t *testing.T) {
	evidence := probeEvidence()
	now := time.Unix(42, 0).UTC()
	useDirectVerifier(t, func(given signature.SignatureEvidence, trust signature.TrustMaterial, at time.Time) (signature.VerificationResult, error) {
		if string(given.Payload) != "the bundle" {
			t.Fatalf("the child was given %q", given.Payload)
		}
		if given.State != evidence.State || trust != nil || !at.Equal(now) {
			t.Fatalf("the child was given another request: %+v %v %s", given, trust, at)
		}
		return signature.VerificationResult{
			EvidenceKind: given.Kind, Cryptographic: signature.CryptographicVerified,
			Publisher: &signature.PublisherIdentity{Repository: "github.com/containerpak/demo"},
		}, nil
	})

	request, err := json.Marshal(verifierRequest{Evidence: evidence, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := RunVerifier(bytes.NewReader(request), &out); err != nil {
		t.Fatal(err)
	}
	var answer verifierResponse
	if err := json.Unmarshal(out.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Error != "" || answer.Result == nil {
		t.Fatalf("evidence that stands came back as %+v", answer)
	}
	if answer.Result.Publisher == nil || answer.Result.Publisher.Repository != "github.com/containerpak/demo" {
		t.Fatalf("the child named another signer: %+v", answer.Result)
	}
}

// A bundle that does not stand is the ordinary case, not a broken child, so it
// has to travel back as a reason the parent can report.
func TestTheChildReportsARefusalInsteadOfDying(t *testing.T) {
	useDirectVerifier(t, func(signature.SignatureEvidence, signature.TrustMaterial, time.Time) (signature.VerificationResult, error) {
		return signature.VerificationResult{}, errors.New("no transparency log holds this")
	})
	request, err := json.Marshal(verifierRequest{Evidence: probeEvidence(), Now: time.Unix(42, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := RunVerifier(bytes.NewReader(request), &out); err != nil {
		t.Fatalf("a refused bundle failed the child itself: %v", err)
	}
	var answer verifierResponse
	if err := json.Unmarshal(out.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Result != nil || !strings.Contains(answer.Error, "transparency log") {
		t.Fatalf("the refusal did not come back as a reason: %+v", answer)
	}
}

// The request is the one place the child reads bytes it did not choose, so a
// request it cannot name exactly is refused rather than guessed at.
func TestTheChildRefusesARequestItCannotName(t *testing.T) {
	for name, request := range map[string]string{
		"a field no request has": `{"evidence":{},"now":"2026-01-01T00:00:00Z","extra":true}`,
		"not an object at all":   `["bundle"]`,
		"multiple values":        `{} {}`,
		"nothing":                ``,
	} {
		var out bytes.Buffer
		if err := RunVerifier(strings.NewReader(request), &out); err == nil {
			t.Fatalf("%s was accepted as a request", name)
		}
	}
}

func TestARequestPastTheLimitIsRefused(t *testing.T) {
	var out bytes.Buffer
	oversized := strings.Repeat("a", verifierRequestLimit+1)
	if err := RunVerifier(strings.NewReader(oversized), &out); err == nil {
		t.Fatal("a request past the limit was read")
	}
}

// An authority with no privileges has nothing to separate, and forking there
// would only make the same check slower and harder to test.
func TestAnUnprivilegedAuthorityChecksInPlace(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this case is about a process that is not root")
	}
	called := false
	useDirectVerifier(t, func(signature.SignatureEvidence, signature.TrustMaterial, time.Time) (signature.VerificationResult, error) {
		called = true
		return signature.VerificationResult{Cryptographic: signature.CryptographicInvalid, ReasonCode: "test-refusal"}, nil
	})
	if _, err := separatedVerifyEvidence(probeEvidence(), nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("the check never reached pkg/signature")
	}
}

func TestSeparatedVerifierRefusesOpaqueCallerTrustMaterial(t *testing.T) {
	if _, err := separatedVerifyEvidence(probeEvidence(), struct{}{}, time.Now()); err == nil {
		t.Fatal("opaque trust material crossed the verifier process boundary")
	}
}

// The verifier failing to run is not a bundle failing to verify, and a caller
// that reads one as the other would enrol on a check that never happened.
func TestAVerifierThatCannotRunIsNotARefusedSignature(t *testing.T) {
	if !errors.Is(ErrVerifierUnavailable, ErrVerifierUnavailable) {
		t.Fatal("the sentinel does not match itself")
	}
	wrapped := errWrap(ErrVerifierUnavailable)
	if !errors.Is(wrapped, ErrVerifierUnavailable) {
		t.Fatal("a wrapped unavailability stops being recognisable")
	}
	if errors.Is(wrapped, ErrUnsigned) {
		t.Fatal("a verifier that could not run reads as a package nobody signed")
	}
}

func errWrap(err error) error {
	return &wrapped{err}
}

type wrapped struct{ err error }

func (w *wrapped) Error() string { return "wrapped: " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }
