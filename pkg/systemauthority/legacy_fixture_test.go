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
	"testing"
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
}
