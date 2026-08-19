/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func evidenceTestState() State {
	return State{
		ABI:            ABIVersion,
		Origin:         "github.com/owner/repository",
		ManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImageDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Generation:     7,
	}
}

func TestLegacyAndTaggedEvidenceDecodeEquivalently(t *testing.T) {
	state := evidenceTestState()
	bundle := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)
	legacy, err := json.Marshal(struct {
		State  State  `json:"state"`
		Bundle []byte `json:"bundle"`
	}{state, bundle})
	if err != nil {
		t.Fatal(err)
	}
	tagged, err := json.Marshal(NewSigstoreEvidence(state, bundle))
	if err != nil {
		t.Fatal(err)
	}
	gotLegacy, wasLegacy, err := DecodeStoredEvidence(legacy)
	if err != nil || !wasLegacy {
		t.Fatalf("decode legacy evidence: legacy=%v err=%v", wasLegacy, err)
	}
	gotTagged, wasLegacy, err := DecodeStoredEvidence(tagged)
	if err != nil || wasLegacy {
		t.Fatalf("decode tagged evidence: legacy=%v err=%v", wasLegacy, err)
	}
	if string(gotLegacy.Payload) != string(gotTagged.Payload) || gotLegacy.State != gotTagged.State || gotLegacy.Kind != gotTagged.Kind || gotLegacy.MediaType != gotTagged.MediaType {
		t.Fatalf("legacy and tagged evidence differ:\nlegacy=%+v\ntagged=%+v", gotLegacy, gotTagged)
	}
}

func TestStoredEvidenceDecoderFailsClosed(t *testing.T) {
	state, err := json.Marshal(evidenceTestState())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"mixed legacy and tagged fields": `{"abi":1,"kind":"sigstore-bundle-v1","state":` + string(state) + `,"media_type":"application/vnd.dev.sigstore.bundle.v0.3+json","payload":"e30=","bundle":"e30="}`,
		"unsupported abi":                `{"abi":2,"kind":"sigstore-bundle-v1","state":` + string(state) + `,"media_type":"application/vnd.dev.sigstore.bundle.v0.3+json","payload":"e30="}`,
		"unsupported kind":               `{"abi":1,"kind":"future-signature-v9","state":` + string(state) + `,"media_type":"application/octet-stream","payload":"e30="}`,
		"unsupported media type":         `{"abi":1,"kind":"sigstore-bundle-v1","state":` + string(state) + `,"media_type":"application/octet-stream","payload":"e30="}`,
		"empty payload":                  `{"abi":1,"kind":"sigstore-bundle-v1","state":` + string(state) + `,"media_type":"application/vnd.dev.sigstore.bundle.v0.3+json","payload":""}`,
		"unknown field":                  `{"abi":1,"kind":"sigstore-bundle-v1","state":` + string(state) + `,"media_type":"application/vnd.dev.sigstore.bundle.v0.3+json","payload":"e30=","future":true}`,
		"duplicate outer key":            `{"abi":1,"abi":1,"kind":"sigstore-bundle-v1","state":` + string(state) + `,"media_type":"application/vnd.dev.sigstore.bundle.v0.3+json","payload":"e30="}`,
		"duplicate nested key":           `{"abi":1,"kind":"sigstore-bundle-v1","state":{"abi":1,"abi":1,"origin":"github.com/owner/repository"},"media_type":"application/vnd.dev.sigstore.bundle.v0.3+json","payload":"e30="}`,
		"trailing value":                 `{"state":` + string(state) + `,"bundle":"e30="} {}`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := DecodeStoredEvidence([]byte(document)); err == nil {
				t.Fatal("ambiguous or unsupported evidence was accepted")
			}
		})
	}
}

func TestMalformedX509EvidenceIsInvalidNotUnsigned(t *testing.T) {
	evidence := SignatureEvidence{
		ABI: EvidenceABIVersion, Kind: EvidenceX509CMS, State: evidenceTestState(),
		MediaType: X509CMSMediaType, Payload: []byte{1, 2, 3},
	}
	result, err := VerifyEvidence(evidence, nil, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if result.Cryptographic != CryptographicInvalid || result.ReasonCode != "invalid-cms" {
		t.Fatalf("got %+v, want a typed invalid result", result)
	}
}

func TestOIDCPublisherIDUsesTheFrozenPreimage(t *testing.T) {
	identity := Identity{
		Issuer: githubActionsIssuer, Repo: "github.com/OWNER/Repository",
		Subject: "https://github.com/owner/repository/.github/workflows/release.yml@refs/heads/main",
	}
	publisher, preliminary := NormalizeOIDCIdentity(identity)
	if preliminary.Status != OriginForeign {
		t.Fatalf("unexpected preliminary authorization: %+v", preliminary)
	}
	want := "oidc-v1-sha256:de38d594ff0ad4e137a88d13dae03f70409174df586295e6bb2d4d42d952b274"
	if publisher == nil || publisher.ID != want {
		t.Fatalf("got publisher id %v, want %s", publisher, want)
	}
	if authorization := AuthorizeOIDCOrigin(publisher, evidenceTestState().Origin); authorization.Status != OriginAuthorized {
		t.Fatalf("the exact repository was not authorized: %+v", authorization)
	}
}

func TestTypedOIDCAuthorizationRejectsUnsupportedAndForeignIdentities(t *testing.T) {
	unsupported, preliminary := NormalizeOIDCIdentity(Identity{Issuer: "https://token.actions.githubusercontent.example.com", Repo: evidenceTestState().Origin})
	if unsupported == nil || preliminary.Status != OriginUnsupported {
		t.Fatalf("unsupported issuer was not preserved and rejected: publisher=%+v authorization=%+v", unsupported, preliminary)
	}
	if got := AuthorizeOIDCOrigin(unsupported, evidenceTestState().Origin); got.Status != OriginUnsupported {
		t.Fatalf("unsupported issuer was authorized: %+v", got)
	}
	publisher, _ := NormalizeOIDCIdentity(Identity{Issuer: githubActionsIssuer, Repo: "github.com/owner/repository-evil"})
	if got := AuthorizeOIDCOrigin(publisher, evidenceTestState().Origin); got.Status != OriginForeign {
		t.Fatalf("lookalike repository was not foreign: %+v", got)
	}
	if publisher, reason := NormalizeOIDCIdentity(Identity{Issuer: githubActionsIssuer}); publisher != nil || reason.ReasonCode != "missing-or-invalid-source-repository" {
		t.Fatalf("missing repository produced %+v, %+v", publisher, reason)
	}
	var invalid *InvalidEvidenceError
	if _, _, err := DecodeStoredEvidence([]byte(`{"abi":2}`)); !errors.As(err, &invalid) {
		t.Fatalf("unsupported ABI did not produce the typed invalid-evidence error: %v", err)
	}
}

func TestTypedOIDCAuthorizationRefusesEveryLookalike(t *testing.T) {
	lookalikes := map[string]Identity{
		"owner prefix":       {Issuer: githubActionsIssuer, Repo: "github.com/owner-inc/repository"},
		"owner suffix":       {Issuer: githubActionsIssuer, Repo: "github.com/notowner/repository"},
		"repository prefix":  {Issuer: githubActionsIssuer, Repo: "github.com/owner/repository-evil"},
		"repository suffix":  {Issuer: githubActionsIssuer, Repo: "github.com/owner/not-repository"},
		"extra path":         {Issuer: githubActionsIssuer, Repo: "github.com/owner/repository/extra"},
		"wrong host":         {Issuer: githubActionsIssuer, Repo: "evilgithub.com/owner/repository"},
		"issuer prefix":      {Issuer: "https://token.actions.githubusercontent.co", Repo: evidenceTestState().Origin},
		"issuer suffix":      {Issuer: "https://token.actions.githubusercontent.com.evil", Repo: evidenceTestState().Origin},
		"missing issuer":     {Repo: evidenceTestState().Origin},
		"missing repository": {Issuer: githubActionsIssuer},
		"unicode folding":    {Issuer: githubActionsIssuer, Repo: "github.com/owner/repositor\u212a"},
	}
	for name, identity := range lookalikes {
		t.Run(name, func(t *testing.T) {
			publisher, preliminary := NormalizeOIDCIdentity(identity)
			if preliminary.Status == OriginUnsupported {
				return
			}
			if got := AuthorizeOIDCOrigin(publisher, evidenceTestState().Origin); got.Status == OriginAuthorized {
				t.Fatalf("lookalike identity was authorized: publisher=%+v result=%+v", publisher, got)
			}
		})
	}
}
