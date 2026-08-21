/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestFixtureLayerContainsExecutableHeadlessCommand(t *testing.T) {
	payload := []byte("static fixture payload")
	layer, diffID, err := fixtureLayer(payload)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		t.Fatal(err)
	}
	uncompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	if digest(uncompressed) != diffID {
		t.Fatalf("diff ID = %q, want %q", diffID, digest(uncompressed))
	}
	tarReader := tar.NewReader(bytes.NewReader(uncompressed))
	header, err := tarReader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if header.Name != "usr/bin/phase5-fixture" || header.Mode != 0755 {
		t.Fatalf("fixture entry = %q mode %#o", header.Name, header.Mode)
	}
	content, err := io.ReadAll(tarReader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, payload) {
		t.Fatalf("unexpected fixture command: %q", content)
	}
}

func TestReadPayloadRequiresABoundedExecutableELF(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "payload")
	if err := os.WriteFile(path, append([]byte{0x7f, 'E', 'L', 'F'}, []byte("fixture")...), 0755); err != nil {
		t.Fatal(err)
	}
	payload, err := readPayload(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, append([]byte{0x7f, 'E', 'L', 'F'}, []byte("fixture")...)) {
		t.Fatalf("payload = %q", payload)
	}
	if err = os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = readPayload(path); err == nil {
		t.Fatal("a script payload was accepted")
	}
}

func TestManifestEndpointServesOnlyTheFixtureManifest(t *testing.T) {
	directory := t.TempDir()
	want := []byte(`{"manifest_version":"2.0"}`)
	if err := os.WriteFile(filepath.Join(directory, "cpak.json"), want, 0600); err != nil {
		t.Fatal(err)
	}
	server, err := newFixture(directory, []byte("fixture executable"))
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

func TestFixtureConfigurationBindsOriginAndEvidenceProfile(t *testing.T) {
	server, err := newFixture(t.TempDir(), []byte("fixture executable"))
	if err != nil {
		t.Fatal(err)
	}
	if err = server.configure("GitHub.com/Example/Project", "sigstore"); err != nil {
		t.Fatal(err)
	}
	if server.origin != "github.com/example/project" || server.serverName != "github.com" ||
		server.manifestPath != "/example/project/raw/main/cpak.json" {
		t.Fatalf("unexpected configured origin: %+v", server)
	}
	if server.evidenceProfile.artifactType != sigstoreArtifactType ||
		server.evidenceProfile.mediaType != sigstoreBundleMediaType || server.evidenceProfile.extension != ".sigstore.json" {
		t.Fatalf("unexpected Sigstore profile: %+v", server.evidenceProfile)
	}
	for _, invalid := range []string{
		"gitlab.com/example/project", "github.com/example", "github.com/example/project/extra",
		"github.com/example/../project", "github.com/example/project?other=true",
	} {
		if err = server.configure(invalid, "sigstore"); err == nil {
			t.Fatalf("invalid origin %q was accepted", invalid)
		}
	}
	if err = server.configure("github.com/example/project", "unknown"); err == nil {
		t.Fatal("unknown evidence profile was accepted")
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
	server, err := newFixture(directory, []byte("fixture executable"))
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
	if server.updatedDigest == server.imageDigest {
		t.Fatal("updated fixture image retained the original digest")
	}
	marker := filepath.Join(directory, updatedImageMarker)
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/manifests/main", nil)
	recorder = httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Docker-Content-Digest") != server.updatedDigest {
		t.Fatalf("updated image response = %d digest %q", recorder.Code, recorder.Header().Get("Docker-Content-Digest"))
	}
	request = httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/referrers/"+server.updatedDigest+"?artifactType="+x509ArtifactType, nil)
	recorder = httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("updated image referrers response = %d %q", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/referrers/"+server.imageDigest+"?artifactType="+x509ArtifactType, nil)
	recorder = httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("inactive image referrers response = %d %q", recorder.Code, recorder.Body.String())
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(marker, 0700); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/manifests/main", nil)
	recorder = httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid image control did not fail closed: %d %q", recorder.Code, recorder.Body.String())
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	request = httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/blobs/"+server.layerDigest, nil)
	recorder = httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
		t.Fatalf("layer response = %d with %d bytes", recorder.Code, recorder.Body.Len())
	}
}

func TestRegistryPublishesOnlyTheSelectedSigstoreProfile(t *testing.T) {
	directory := t.TempDir()
	bundle := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)
	if err := os.WriteFile(filepath.Join(directory, "generation"), []byte("2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "state-2.sigstore.json"), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	server, err := newFixture(directory, []byte("fixture executable"))
	if err != nil {
		t.Fatal(err)
	}
	if err = server.configure("github.com/example/project", "sigstore"); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/referrers/"+server.imageDigest+"?artifactType="+url.QueryEscape(sigstoreArtifactType), nil)
	recorder := httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	var index struct {
		Manifests []descriptor `json:"manifests"`
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("Sigstore referrers response = %d %q", recorder.Code, recorder.Body.String())
	}
	if err = json.Unmarshal(recorder.Body.Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 1 {
		t.Fatalf("Sigstore referrers response = %d %q", recorder.Code, recorder.Body.String())
	}
	if index.Manifests[0].ArtifactType != sigstoreArtifactType {
		t.Fatalf("Sigstore referrer profile = %+v", index.Manifests[0])
	}

	request = httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/referrers/"+server.imageDigest+"?artifactType="+x509ArtifactType, nil)
	recorder = httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	if err = json.Unmarshal(recorder.Body.Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 0 {
		t.Fatalf("X.509 fallback was exposed in Sigstore mode: %+v", index.Manifests)
	}

	request = httptest.NewRequest(http.MethodGet, "/v2/"+repository+"/blobs/"+digest(bundle), nil)
	recorder = httptest.NewRecorder()
	server.serveRegistry(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != sigstoreBundleMediaType || recorder.Body.String() != string(bundle) {
		t.Fatalf("Sigstore bundle response = %d %q %q", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
	}
}

func TestRegistryUnsignedControlIsImmediateAndFailsClosed(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "generation"), []byte("3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "state-3.cms"), []byte("CMS evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	server, err := newFixture(directory, []byte("fixture executable"))
	if err != nil {
		t.Fatal(err)
	}
	request := func(artifactType string) *httptest.ResponseRecorder {
		t.Helper()
		recorder := httptest.NewRecorder()
		server.serveRegistry(recorder, httptest.NewRequest(
			http.MethodGet,
			"/v2/"+repository+"/referrers/"+server.imageDigest+"?artifactType="+url.QueryEscape(artifactType),
			nil,
		))
		return recorder
	}
	manifestCount := func(recorder *httptest.ResponseRecorder) int {
		t.Helper()
		var index struct {
			Manifests []descriptor `json:"manifests"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &index); err != nil {
			t.Fatal(err)
		}
		return len(index.Manifests)
	}

	marker := filepath.Join(directory, unsignedMarker)
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if recorder := request(x509ArtifactType); recorder.Code != http.StatusOK || manifestCount(recorder) != 0 {
		t.Fatalf("unsigned referrers response = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder := request(sigstoreArtifactType); recorder.Code != http.StatusOK || manifestCount(recorder) != 0 {
		t.Fatalf("unselected profile changed under unsigned control = %d %q", recorder.Code, recorder.Body.String())
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if recorder := request(x509ArtifactType); recorder.Code != http.StatusOK || manifestCount(recorder) != 1 {
		t.Fatalf("restored referrers response = %d %q", recorder.Code, recorder.Body.String())
	}
	if err := os.Mkdir(marker, 0700); err != nil {
		t.Fatal(err)
	}
	if recorder := request(x509ArtifactType); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid unsigned control did not fail closed: %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestEvidenceRejectsInvalidGenerationAndOversizedPayload(t *testing.T) {
	directory := t.TempDir()
	server, err := newFixture(directory, []byte("fixture executable"))
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
