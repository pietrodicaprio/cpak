/*
 * Copyright (c) 2025 Fabricators and Mirko Brombin <brombin94@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package trustpolicy

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyTrustPolicyFixtureStillDecodesStrictly(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("../../testdata/application-trust-v2.6.0", "trust-policy-v1.json"))
	if err != nil {
		t.Fatalf("read legacy trust policy fixture: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	policy := Policy{}
	if err := decoder.Decode(&policy); err != nil {
		t.Fatalf("decode legacy trust policy: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("legacy trust policy contains trailing data: %v", err)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("legacy trust policy is no longer valid: %v", err)
	}
	if policy.ABI != 1 || !policy.RequirePublisher || !policy.RequireApproval {
		t.Fatalf("legacy trust policy lost its decisions: %+v", policy)
	}
	if len(policy.ApprovedSigners) != 1 || policy.ApprovedSigners[0].Repo != "github.com/acme/cpak" {
		t.Fatalf("legacy trust policy lost its publisher selector: %+v", policy.ApprovedSigners)
	}
}
