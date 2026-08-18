/*
 * Copyright (c) 2025 Fabricators and Mirko Brombin <brombin94@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package systemauthority

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mirkobrombin/cpak/pkg/signature"
)

const legacyTrustFixtureDirectory = "../../testdata/application-trust-v2.6.0"

func readLegacyTrustFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(legacyTrustFixtureDirectory, name))
	if err != nil {
		t.Fatalf("read legacy fixture %s: %v", name, err)
	}
	return content
}

func TestLegacyAnchorLedgerFixtureStillDecodesStrictly(t *testing.T) {
	document := readLegacyTrustFixture(t, "anchor-ledger-v1.json")
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	enrolment := Enrolment{}
	if err := decoder.Decode(&enrolment); err != nil {
		t.Fatalf("decode legacy anchor ledger record: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("legacy anchor ledger record contains trailing data: %v", err)
	}
	if err := validateEnrolment(enrolment); err != nil {
		t.Fatalf("legacy anchor ledger record is no longer valid: %v", err)
	}
	if enrolment.Signature == nil || enrolment.Signature.State.Origin != enrolment.Origin {
		t.Fatalf("legacy anchor ledger record lost its signed state: %+v", enrolment.Signature)
	}
	var gotBundle any
	if err := json.Unmarshal(enrolment.Signature.Bundle, &gotBundle); err != nil {
		t.Fatalf("decode ledger Sigstore bundle: %v", err)
	}
	var wantBundle any
	if err := json.Unmarshal(readLegacyTrustFixture(t, "sigstore-bundle-v0.3.json"), &wantBundle); err != nil {
		t.Fatalf("decode standalone Sigstore bundle: %v", err)
	}
	if !reflect.DeepEqual(gotBundle, wantBundle) {
		t.Fatal("legacy anchor ledger record no longer carries the captured Sigstore bundle")
	}
	evidence := enrolment.Signature.Evidence()
	if evidence.ABI != 1 || evidence.Kind != "sigstore-bundle-v1" || evidence.MediaType != "application/vnd.dev.sigstore.bundle.v0.3+json" {
		t.Fatalf("legacy fields did not migrate to the frozen common evidence: %+v", evidence)
	}
	useBundleVerifier(t, func(_ []byte, state signature.State) (signature.Verified, error) {
		return signature.Verified{State: state, Identity: testSignatureIdentity(state.Origin)}, nil
	})
	if _, err := enrolment.Signer(); err != nil {
		t.Fatalf("legacy ledger evidence no longer re-verifies through the common verifier: %v", err)
	}
}

func TestReadingALegacyLedgerRecordDoesNotRewriteIt(t *testing.T) {
	ledger := testAnchorLedger(t)
	document := readLegacyTrustFixture(t, "anchor-ledger-v1.json")
	path := writeAnchorFile(t, ledger, 1000, "github.com/acme/cpak", document)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := ledger.Recorded(1000, "github.com/acme/cpak"); err != nil || !found {
		t.Fatalf("read legacy ledger record: found=%v err=%v", found, err)
	}
	afterDocument, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterDocument, document) || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("reading the legacy ledger record rewrote it")
	}
}

func TestLedgerRejectsDuplicateKeysBeforeJSONCanMergeThem(t *testing.T) {
	ledger := testAnchorLedger(t)
	document := readLegacyTrustFixture(t, "anchor-ledger-v1.json")
	document = bytes.Replace(document, []byte(`"uid": 1000`), []byte(`"uid": 1000, "uid": 1000`), 1)
	writeAnchorFile(t, ledger, 1000, "github.com/acme/cpak", document)
	if _, _, err := ledger.Recorded(1000, "github.com/acme/cpak"); err == nil {
		t.Fatal("a ledger record with a duplicate key was accepted")
	}
}

func TestValidUpdateRewritesLegacySignatureAsTaggedEvidence(t *testing.T) {
	ledger := testAnchorLedger(t)
	document := readLegacyTrustFixture(t, "anchor-ledger-v1.json")
	path := writeAnchorFile(t, ledger, 1000, "github.com/acme/cpak", document)
	recorded, found, err := ledger.Recorded(1000, "github.com/acme/cpak")
	if err != nil || !found {
		t.Fatalf("read legacy ledger record: found=%v err=%v", found, err)
	}
	useBundleVerifier(t, func(_ []byte, state signature.State) (signature.Verified, error) {
		return signature.Verified{State: state, Identity: testSignatureIdentity(state.Origin)}, nil
	})
	recorded.Generation++
	recorded.Signature.State.Generation++
	if err := ledger.Record(recorded); err != nil {
		t.Fatalf("record valid update over legacy evidence: %v", err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	for _, field := range []string{`"abi": 1`, `"kind": "sigstore-bundle-v1"`, `"media_type": "application/vnd.dev.sigstore.bundle.v0.3+json"`, `"payload":`} {
		if !strings.Contains(text, field) {
			t.Fatalf("updated ledger lacks tagged evidence field %s:\n%s", field, text)
		}
	}
	if strings.Contains(text, `"bundle":`) {
		t.Fatalf("updated ledger retained the legacy bundle field:\n%s", text)
	}
}
