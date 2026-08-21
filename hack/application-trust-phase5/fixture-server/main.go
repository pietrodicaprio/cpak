/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

// fixture-server exposes one disposable package repository and OCI registry
// for the Phase 5 process-level Linux lifecycle. It is deliberately loopback
// only and reads the manifest and signed evidence from its private directory.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	origin                        = "phase5.invalid/containerpak/phase5-fixture"
	repository                    = "example/app"
	imageManifestMediaType        = "application/vnd.oci.image.manifest.v1+json"
	imageIndexMediaType           = "application/vnd.oci.image.index.v1+json"
	emptyConfigMediaType          = "application/vnd.oci.empty.v1+json"
	imageLayerMediaType           = "application/vnd.oci.image.layer.v1.tar+gzip"
	x509ArtifactType              = "application/vnd.cpak.signature.x509.v1"
	x509CMSMediaType              = "application/pkcs7-signature"
	sigstoreArtifactType          = "application/vnd.cpak.signature.v1+json"
	sigstoreBundleMediaType       = "application/vnd.dev.sigstore.bundle.v0.3+json"
	generationAnnotation          = "dev.cpak.signature.generation"
	unsignedMarker                = "serve-unsigned"
	updatedImageMarker            = "serve-updated-image"
	maximumEvidenceSize     int64 = 1 << 20
	maximumPayloadSize            = 32 << 20
)

type metadata struct {
	Origin             string `json:"origin"`
	Image              string `json:"image"`
	ImageDigest        string `json:"image_digest"`
	UpdatedImageDigest string `json:"updated_image_digest"`
	TLSRoot            string `json:"tls_root"`
}

type descriptor struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Digest       string            `json:"digest"`
	Size         int               `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

type fixture struct {
	directory       string
	origin          string
	manifestPath    string
	serverName      string
	evidenceProfile evidenceProfile
	config          []byte
	configDigest    string
	layer           []byte
	layerDigest     string
	imageManifest   []byte
	imageDigest     string
	updatedManifest []byte
	updatedDigest   string
	emptyConfig     []byte
	emptyConfigHash string
}

type evidenceProfile struct {
	artifactType string
	mediaType    string
	extension    string
}

func main() {
	directory := flag.String("directory", "", "private fixture directory")
	payloadPath := flag.String("payload", "", "static Linux executable to place in the OCI layer")
	packageOrigin := flag.String("origin", origin, "package origin served by the fixture")
	evidenceKind := flag.String("evidence-kind", "x509-cms", "evidence profile: x509-cms or sigstore")
	flag.Parse()
	if *directory == "" || !filepath.IsAbs(*directory) {
		log.Fatal("--directory must be an absolute path")
	}
	payload, err := readPayload(*payloadPath)
	if err != nil {
		log.Fatal(err)
	}
	server, err := newFixture(*directory, payload)
	if err != nil {
		log.Fatal(err)
	}
	if err = server.configure(*packageOrigin, *evidenceKind); err != nil {
		log.Fatal(err)
	}
	certificate, rootPath, err := server.serverCertificate()
	if err != nil {
		log.Fatal(err)
	}

	manifestListener, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		log.Fatalf("listen for the package repository: %v", err)
	}
	registryListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		manifestListener.Close()
		log.Fatalf("listen for the OCI registry: %v", err)
	}

	manifestHTTP := &http.Server{Handler: http.HandlerFunc(server.serveManifest)}
	registryHTTP := &http.Server{Handler: http.HandlerFunc(server.serveRegistry)}
	tlsListener := tlsListener(manifestListener, certificate)

	if err = writeMetadata(*directory, metadata{
		Origin: server.origin, Image: registryListener.Addr().String() + "/" + repository + ":main",
		ImageDigest: server.imageDigest, UpdatedImageDigest: server.updatedDigest, TLSRoot: rootPath,
	}); err != nil {
		manifestListener.Close()
		registryListener.Close()
		log.Fatal(err)
	}

	failures := make(chan error, 2)
	go func() { failures <- manifestHTTP.Serve(tlsListener) }()
	go func() { failures <- registryHTTP.Serve(registryListener) }()
	log.Printf("phase5 fixture serves %s and %s", server.origin, registryListener.Addr())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case signal := <-stop:
		log.Printf("stopping after %s", signal)
	case serveErr := <-failures:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			log.Fatalf("serve fixture: %v", serveErr)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = manifestHTTP.Shutdown(ctx)
	_ = registryHTTP.Shutdown(ctx)
}

func newFixture(directory string, payload []byte) (*fixture, error) {
	layer, diffID, err := fixtureLayer(payload)
	if err != nil {
		return nil, err
	}
	config, err := json.Marshal(map[string]any{
		"architecture": "amd64", "os": "linux", "config": map[string]any{},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{diffID}},
	})
	if err != nil {
		return nil, fmt.Errorf("encode image config: %w", err)
	}
	configDigest := digest(config)
	layerDigest := digest(layer)
	image := map[string]any{
		"schemaVersion": 2,
		"mediaType":     imageManifestMediaType,
		"config":        descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: configDigest, Size: len(config)},
		"layers":        []descriptor{{MediaType: imageLayerMediaType, Digest: layerDigest, Size: len(layer)}},
	}
	manifest, err := json.Marshal(image)
	if err != nil {
		return nil, fmt.Errorf("encode image manifest: %w", err)
	}
	image["annotations"] = map[string]string{"dev.cpak.fixture.revision": "2"}
	updatedManifest, err := json.Marshal(image)
	if err != nil {
		return nil, fmt.Errorf("encode updated image manifest: %w", err)
	}
	empty := []byte("{}")
	return &fixture{
		directory: directory, origin: origin,
		manifestPath: "/containerpak/phase5-fixture/raw/main/cpak.json", serverName: "phase5.invalid",
		evidenceProfile: evidenceProfile{artifactType: x509ArtifactType, mediaType: x509CMSMediaType, extension: ".cms"},
		config:          config, configDigest: configDigest,
		layer: layer, layerDigest: layerDigest,
		imageManifest: manifest, imageDigest: digest(manifest),
		updatedManifest: updatedManifest, updatedDigest: digest(updatedManifest),
		emptyConfig: empty, emptyConfigHash: digest(empty),
	}, nil
}

func (f *fixture) configure(packageOrigin, evidenceKind string) error {
	packageOrigin = strings.ToLower(strings.TrimSpace(packageOrigin))
	parts := strings.Split(packageOrigin, "/")
	if len(parts) != 3 || (parts[0] != "phase5.invalid" && parts[0] != "github.com") ||
		!validOriginPart(parts[1]) || !validOriginPart(parts[2]) {
		return errors.New("--origin must be phase5.invalid or github.com followed by one owner and repository")
	}
	profile := evidenceProfile{}
	switch evidenceKind {
	case "x509-cms":
		profile = evidenceProfile{artifactType: x509ArtifactType, mediaType: x509CMSMediaType, extension: ".cms"}
	case "sigstore":
		profile = evidenceProfile{artifactType: sigstoreArtifactType, mediaType: sigstoreBundleMediaType, extension: ".sigstore.json"}
	default:
		return errors.New("--evidence-kind must be x509-cms or sigstore")
	}
	f.origin = packageOrigin
	f.serverName = parts[0]
	f.manifestPath = "/" + parts[1] + "/" + parts[2] + "/raw/main/cpak.json"
	f.evidenceProfile = profile
	return nil
}

func validOriginPart(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 100 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func (f *fixture) serveManifest(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.Path != f.manifestPath {
		http.NotFound(writer, request)
		return
	}
	content, err := os.ReadFile(filepath.Join(f.directory, "cpak.json"))
	if err != nil {
		http.Error(writer, "manifest unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(content)
}

func (f *fixture) serveRegistry(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if request.URL.Path == "/v2/" || request.URL.Path == "/v2" {
		writer.WriteHeader(http.StatusOK)
		return
	}
	prefix := "/v2/" + repository + "/"
	if !strings.HasPrefix(request.URL.Path, prefix) {
		http.NotFound(writer, request)
		return
	}
	path := strings.TrimPrefix(request.URL.Path, prefix)
	switch {
	case strings.HasPrefix(path, "referrers/"):
		f.serveReferrers(writer, request, strings.TrimPrefix(path, "referrers/"))
	case strings.HasPrefix(path, "manifests/"):
		f.serveOCIManifest(writer, strings.TrimPrefix(path, "manifests/"))
	case strings.HasPrefix(path, "blobs/"):
		f.serveBlob(writer, strings.TrimPrefix(path, "blobs/"))
	default:
		http.NotFound(writer, request)
	}
}

func (f *fixture) serveReferrers(writer http.ResponseWriter, request *http.Request, subject string) {
	imageManifest, imageDigest, err := f.selectedImage()
	if err != nil {
		http.Error(writer, "image control unavailable", http.StatusServiceUnavailable)
		return
	}
	if subject != imageDigest {
		http.NotFound(writer, request)
		return
	}
	manifests := []descriptor{}
	if request.URL.Query().Get("artifactType") == f.evidenceProfile.artifactType {
		unsigned, err := f.serveUnsigned()
		if err != nil {
			http.Error(writer, "evidence control unavailable", http.StatusServiceUnavailable)
			return
		}
		if unsigned {
			writeJSON(writer, imageIndexMediaType, map[string]any{
				"schemaVersion": 2, "mediaType": imageIndexMediaType, "manifests": manifests,
			})
			return
		}
		artifact, generation, err := f.artifactManifest(imageManifest, imageDigest)
		if err != nil {
			http.Error(writer, "evidence unavailable", http.StatusServiceUnavailable)
			return
		}
		manifests = append(manifests, descriptor{
			MediaType: imageManifestMediaType, ArtifactType: f.evidenceProfile.artifactType,
			Digest: digest(artifact), Size: len(artifact),
			Annotations: map[string]string{generationAnnotation: strconv.FormatUint(generation, 10)},
		})
	}
	writeJSON(writer, imageIndexMediaType, map[string]any{
		"schemaVersion": 2, "mediaType": imageIndexMediaType, "manifests": manifests,
	})
}

func (f *fixture) serveUnsigned() (bool, error) {
	info, err := os.Lstat(filepath.Join(f.directory, unsignedMarker))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("unsigned fixture marker is not a regular file")
	}
	return true, nil
}

func (f *fixture) serveOCIManifest(writer http.ResponseWriter, identifier string) {
	if identifier == "main" {
		manifest, manifestDigest, err := f.selectedImage()
		if err != nil {
			http.Error(writer, "image control unavailable", http.StatusServiceUnavailable)
			return
		}
		writeManifest(writer, manifest, manifestDigest)
		return
	}
	if identifier == f.imageDigest {
		writeManifest(writer, f.imageManifest, f.imageDigest)
		return
	}
	if identifier == f.updatedDigest {
		writeManifest(writer, f.updatedManifest, f.updatedDigest)
		return
	}
	imageManifest, imageDigest, err := f.selectedImage()
	if err != nil {
		http.Error(writer, "image control unavailable", http.StatusServiceUnavailable)
		return
	}
	artifact, _, err := f.artifactManifest(imageManifest, imageDigest)
	if err == nil && identifier == digest(artifact) {
		writeManifest(writer, artifact, identifier)
		return
	}
	http.Error(writer, "not found", http.StatusNotFound)
}

func (f *fixture) serveBlob(writer http.ResponseWriter, identifier string) {
	switch identifier {
	case f.configDigest:
		_, _ = writer.Write(f.config)
		return
	case f.emptyConfigHash:
		_, _ = writer.Write(f.emptyConfig)
		return
	case f.layerDigest:
		writer.Header().Set("Content-Type", imageLayerMediaType)
		_, _ = writer.Write(f.layer)
		return
	}
	payload, _, err := f.evidence()
	if err == nil && identifier == digest(payload) {
		writer.Header().Set("Content-Type", f.evidenceProfile.mediaType)
		_, _ = writer.Write(payload)
		return
	}
	http.Error(writer, "not found", http.StatusNotFound)
}

func (f *fixture) artifactManifest(imageManifest []byte, imageDigest string) ([]byte, uint64, error) {
	payload, generation, err := f.evidence()
	if err != nil {
		return nil, 0, err
	}
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": imageManifestMediaType, "artifactType": f.evidenceProfile.artifactType,
		"config":  descriptor{MediaType: emptyConfigMediaType, Digest: f.emptyConfigHash, Size: len(f.emptyConfig)},
		"layers":  []descriptor{{MediaType: f.evidenceProfile.mediaType, Digest: digest(payload), Size: len(payload)}},
		"subject": descriptor{MediaType: imageManifestMediaType, Digest: imageDigest, Size: len(imageManifest)},
	})
	return manifest, generation, err
}

func (f *fixture) selectedImage() ([]byte, string, error) {
	info, err := os.Lstat(filepath.Join(f.directory, updatedImageMarker))
	if errors.Is(err, os.ErrNotExist) {
		return f.imageManifest, f.imageDigest, nil
	}
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() {
		return nil, "", errors.New("updated image fixture marker is not a regular file")
	}
	return f.updatedManifest, f.updatedDigest, nil
}

func (f *fixture) evidence() ([]byte, uint64, error) {
	generationData, err := os.ReadFile(filepath.Join(f.directory, "generation"))
	if err != nil {
		return nil, 0, err
	}
	generation, err := strconv.ParseUint(strings.TrimSpace(string(generationData)), 10, 64)
	if err != nil || generation == 0 {
		return nil, 0, errors.New("invalid fixture generation")
	}
	path := filepath.Join(f.directory, fmt.Sprintf("state-%d%s", generation, f.evidenceProfile.extension))
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximumEvidenceSize+1))
	if err != nil || int64(len(payload)) > maximumEvidenceSize {
		return nil, 0, errors.New("invalid fixture evidence")
	}
	return payload, generation, nil
}

func (f *fixture) serverCertificate() (tls.Certificate, string, error) {
	now := time.Now().UTC()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cpak Phase 5 fixture root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: f.serverName},
		DNSNames: []string{f.serverName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, root, serverPublic, rootPrivate)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	rootPath := filepath.Join(f.directory, "fixture-tls-root.pem")
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	if err = os.WriteFile(rootPath, rootPEM, 0644); err != nil {
		return tls.Certificate{}, "", err
	}
	return tls.Certificate{Certificate: [][]byte{serverDER, rootDER}, PrivateKey: serverPrivate}, rootPath, nil
}

func tlsListener(listener net.Listener, certificate tls.Certificate) net.Listener {
	return tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
}

func writeMetadata(directory string, value metadata) error {
	content, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := filepath.Join(directory, ".fixture.json.tmp")
	final := filepath.Join(directory, "fixture.json")
	if err = os.WriteFile(temporary, append(content, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(temporary, final)
}

func writeManifest(writer http.ResponseWriter, content []byte, contentDigest string) {
	writer.Header().Set("Content-Type", imageManifestMediaType)
	writer.Header().Set("Docker-Content-Digest", contentDigest)
	writer.Header().Set("Content-Length", strconv.Itoa(len(content)))
	_, _ = writer.Write(content)
}

func writeJSON(writer http.ResponseWriter, mediaType string, value any) {
	writer.Header().Set("Content-Type", mediaType)
	_ = json.NewEncoder(writer).Encode(value)
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readPayload(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("--payload must be an absolute path")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open fixture payload: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect fixture payload: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() <= 0 || info.Size() > maximumPayloadSize {
		return nil, errors.New("fixture payload must be a non-empty executable regular file within the size limit")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximumPayloadSize+1))
	if err != nil || len(payload) > maximumPayloadSize {
		return nil, errors.New("read fixture payload within the size limit")
	}
	if len(payload) < 4 || !bytes.Equal(payload[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return nil, errors.New("fixture payload is not an ELF executable")
	}
	return payload, nil
}

func fixtureLayer(content []byte) ([]byte, string, error) {
	if len(content) == 0 || len(content) > maximumPayloadSize {
		return nil, "", errors.New("fixture layer payload is outside the size limit")
	}
	var archive bytes.Buffer
	tarWriter := tar.NewWriter(&archive)
	header := &tar.Header{
		Name: "usr/bin/phase5-fixture", Mode: 0755, Size: int64(len(content)),
		Typeflag: tar.TypeReg,
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		return nil, "", fmt.Errorf("write fixture layer header: %w", err)
	}
	if _, err := tarWriter.Write(content); err != nil {
		return nil, "", fmt.Errorf("write fixture layer content: %w", err)
	}
	if err := tarWriter.Close(); err != nil {
		return nil, "", fmt.Errorf("close fixture layer: %w", err)
	}

	var compressed bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return nil, "", fmt.Errorf("create fixture layer compressor: %w", err)
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	gzipWriter.Header.OS = 255
	if _, err = gzipWriter.Write(archive.Bytes()); err != nil {
		return nil, "", fmt.Errorf("compress fixture layer: %w", err)
	}
	if err = gzipWriter.Close(); err != nil {
		return nil, "", fmt.Errorf("close fixture layer compressor: %w", err)
	}
	return compressed.Bytes(), digest(archive.Bytes()), nil
}
