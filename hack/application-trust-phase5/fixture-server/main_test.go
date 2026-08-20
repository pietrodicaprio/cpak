/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestEndpointServesOnlyTheFixtureManifest(t *testing.T) {
	directory := t.TempDir()
	want := []byte(`{"manifest_version":"2.0"}`)
	if err := os.WriteFile(filepath.Join(directory, "cpak.json"), want, 0600); err != nil {
		t.Fatal(err)
	}
	server, err := newFixture(directory)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://phase5.invalid/containerpak/phase5-fixture/raw/main/cpak.json", nil)
	recorder := httptest.NewRecorder()
	server.serveManifest(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != string(want) {
		t.Fatalf("manifest response = %d %q", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "https://phase5.invalid/other", nil)
	recorder = httptest.NewRecorder()
	server.serveManifest(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unexpected path status = %d", recorder.Code)
	}
}

func TestRegistryPublishesImageAndCurrentEvidence(t *testing.T) {
	directory := t.TempDir()
	evidence := []byte("disposable CMS evidence")
	if err := os.WriteFile(filepath.Join(directory, "generation"), []byte("7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "state-7.cms"), evidence, 0600); err != nil {
		t.Fatal(err)
	}
	server, err := newFixture(directory)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/referrers/"+server.imageDigest+"?artifactType="+x509ArtifactType, nil)
	recorder := httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("referrers status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var index struct {
		Manifests []descriptor `json:"manifests"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 1 || index.Manifests[0].Annotations[generationAnnotation] != "7" {
		t.Fatalf("unexpected referrers index: %#v", index)
	}

	request = httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/blobs/"+digest(evidence), nil)
	recorder = httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != string(evidence) {
		t.Fatalf("evidence response = %d %q", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/manifests/main", nil)
	recorder = httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Docker-Content-Digest") != server.imageDigest {
		t.Fatalf("image response = %d digest %q", recorder.Code, recorder.Header().Get("Docker-Content-Digest"))
	}
}

func TestEvidenceRejectsInvalidGenerationAndOversizedPayload(t *testing.T) {
	directory := t.TempDir()
	server, err := newFixture(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "generation"), []byte("../1"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.evidence(); err == nil {
		t.Fatal("invalid generation was accepted")
	}
	if err := os.WriteFile(filepath.Join(directory, "generation"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(directory, "state-1.cms"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.CopyN(file, zeroReader{}, maximumEvidenceSize+1); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.evidence(); err == nil {
		t.Fatal("oversized evidence was accepted")
	}
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 0
	}
	return len(buffer), nil
}
