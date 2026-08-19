/*
 * Copyright (c) 2025 Fabricators and Mirko Brombin <brombin94@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mirkobrombin/cpak/pkg/oci"
	"github.com/mirkobrombin/cpak/pkg/signature"
)

const (
	// Legacy aliases keep the default Sigstore publication profile explicit.
	signatureArtifactType = signature.SigstoreArtifactType
	bundleMediaType       = signature.SigstoreBundleMediaType
	defaultBundlePath     = "cpak-state.sigstore.json"
	bundleLimit           = 1 << 20
	stateLimit            = 64 << 10

	// generationAnnotation carries the one field of a signed state that the
	// installing machine cannot derive from what it installed. It is a hint and
	// never evidence: a wrong value produces a state the bundle does not cover,
	// which is a refusal, so nothing can be gained by writing a false one.
	generationAnnotation = "dev.cpak.signature.generation"
)

// verifyState is the gate an attach passes before a byte is pushed. A bundle
// that does not cover the state, or one signed by an identity that cannot speak
// for the origin, is a bundle every user would reject, and it is better
// rejected here than in front of them. It is a variable so that a test can hold
// one that fails; nothing in cpak-sign replaces it.
var verifyState = signature.VerifyEvidence

func checkStateEvidence(evidence signature.SignatureEvidence, trust signature.TrustMaterial) (signature.VerificationResult, signature.Verified, error) {
	result, err := verifyState(evidence, trust, time.Now())
	if err != nil {
		return result, signature.Verified{}, err
	}
	verified, err := signature.LegacyVerified(result, evidence.State)
	return result, verified, err
}

// referrer is the artifact manifest a signature is published as. The subject is
// the image manifest the state was signed over, which is what makes the
// registry index it beside the image instead of beside a tag.
type referrer struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        descriptor        `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Subject       descriptor        `json:"subject"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

func attachSignature(arguments []string) error {
	flags := flag.NewFlagSet("attach", flag.ContinueOnError)
	image := flags.String("image", "", "image repository the signature is attached to")
	statePath := flags.String("state", defaultStatePath, "path to the payload that was signed")
	bundlePath := flags.String("bundle", "", "path to the Sigstore bundle or detached CMS evidence")
	evidenceKind := flags.String("evidence-kind", "sigstore", "evidence format: sigstore or x509-cms")
	trustRootPath := flags.String("trust-root", "", "publication-time X.509 root used to validate the CMS before upload; does not import trust")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *image == "" {
		return errors.New("image is required, and names the repository the signed image lives in")
	}
	reference, err := oci.ParseReference(*image)
	if err != nil {
		return err
	}
	state, err := readSignedState(*statePath)
	if err != nil {
		return err
	}
	selectedBundlePath := *bundlePath
	if selectedBundlePath == "" {
		if strings.EqualFold(strings.TrimSpace(*evidenceKind), "x509") || strings.EqualFold(strings.TrimSpace(*evidenceKind), "x509-cms") {
			selectedBundlePath = defaultCMSPath
		} else {
			selectedBundlePath = defaultBundlePath
		}
	}
	bundle, err := readFile(selectedBundlePath, bundleLimit)
	if err != nil {
		return fmt.Errorf("read the bundle: %w", err)
	}
	evidence, artifactType, layerMediaType, _, err := publicationEvidence(*evidenceKind, state, bundle)
	if err != nil {
		return err
	}
	trust, err := publicationTrust(*trustRootPath, evidence.Kind)
	if err != nil {
		return err
	}
	result, verified, err := checkStateEvidence(evidence, trust)
	if err != nil {
		return fmt.Errorf("the evidence in %s does not cover the state in %s: %w", selectedBundlePath, *statePath, err)
	}
	if result.OriginAuthorization != string(signature.OriginAuthorized) {
		return fmt.Errorf("the state was signed by %s from %s, which cannot speak for %s", verified.Identity.Subject, verified.Identity.Issuer, state.Origin)
	}
	return attachBundle(context.Background(), reference, state, bundle, artifactType, layerMediaType)
}

func publicationEvidence(kind string, state signature.State, payload []byte) (signature.SignatureEvidence, string, string, string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "sigstore":
		return signature.NewSigstoreEvidence(state, payload), signature.SigstoreArtifactType, signature.SigstoreBundleMediaType, defaultBundlePath, nil
	case "x509", "x509-cms":
		return signature.NewX509CMSEvidence(state, payload), signature.X509ArtifactType, signature.X509CMSMediaType, defaultCMSPath, nil
	default:
		return signature.SignatureEvidence{}, "", "", "", fmt.Errorf("unsupported evidence kind %q: use sigstore or x509-cms", kind)
	}
}

func publicationTrust(path string, kind signature.EvidenceKind) (signature.TrustMaterial, error) {
	if kind != signature.EvidenceX509CMS {
		if path != "" {
			return nil, errors.New("--trust-root applies only to x509-cms evidence")
		}
		return nil, nil
	}
	if path == "" {
		return nil, nil
	}
	certificates, err := readCertificates(path)
	if err != nil {
		return nil, fmt.Errorf("read publication trust root: %w", err)
	}
	if len(certificates) != 1 {
		return nil, fmt.Errorf("publication trust root contains %d certificates, expected exactly one", len(certificates))
	}
	root := certificates[0]
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return nil, errors.New("publication trust root is not a self-signed CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	sum := sha256.Sum256(root.Raw)
	fingerprint := hex.EncodeToString(sum[:])
	return &signature.X509TrustSet{
		CodeSigningRoots: pool, TimestampRoots: x509.NewCertPool(),
		Roots: map[string]signature.X509Root{fingerprint: {
			Certificate: root, Fingerprint: fingerprint, Source: signature.RootSourceLocal,
			Purposes: map[string]bool{signature.RootPurposeCodeSigning: true},
		}},
	}, nil
}

func attachBundle(ctx context.Context, reference oci.Reference, state signature.State, bundle []byte, artifactType, layerMediaType string) error {
	client := newRegistry(reference)
	if err := client.authorize(ctx); err != nil {
		return err
	}
	subject, err := client.subjectDescriptor(ctx, state.ImageDigest)
	if err != nil {
		return err
	}
	config, err := client.pushBlob(ctx, emptyConfigMediaType, emptyConfig)
	if err != nil {
		return err
	}
	layer, err := client.pushBlob(ctx, layerMediaType, bundle)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(referrer{
		SchemaVersion: 2,
		MediaType:     manifestMediaType,
		ArtifactType:  artifactType,
		Config:        config,
		Layers:        []descriptor{layer},
		Subject:       subject,
		Annotations:   map[string]string{generationAnnotation: strconv.FormatUint(state.Generation, 10)},
	})
	if err != nil {
		return fmt.Errorf("encode the signature manifest: %w", err)
	}
	indexed, err := client.pushManifest(ctx, encoded)
	if err != nil {
		return err
	}
	// A registry that stores the manifest without indexing it has answered
	// nothing, and a signature nobody is served is not published. The
	// specification's own way out is to keep the index under a tag, which is
	// what registries without referrers support expect a client to do.
	if indexed == "" {
		// The referrers API answers with the artifact's annotations, and a
		// reader takes the publisher generation from them. An index written by
		// hand has to carry the same thing or the signature is found and then
		// skipped for naming no generation.
		fallback := descriptor{
			MediaType:   manifestMediaType,
			Digest:      digestOf(encoded),
			Size:        int64(len(encoded)),
			Annotations: map[string]string{generationAnnotation: strconv.FormatUint(state.Generation, 10)},
		}
		if err := publishFallbackIndex(ctx, client, state.ImageDigest, fallback, signatureArtifactType); err != nil {
			return fmt.Errorf("%s does not index referrers and the fallback tag could not be written: %w", reference.Registry, err)
		}
		return nil
	}
	if indexed != state.ImageDigest {
		return fmt.Errorf("%s indexed the signature under %s and not %s", reference.Registry, indexed, state.ImageDigest)
	}
	fmt.Fprintf(os.Stderr, "attached %s to %s@%s\n", digestOf(encoded), reference.ContextName(), state.ImageDigest)
	return nil
}

// readSignedState reads back the payload that was signed. A payload that is not
// the canonical encoding of the state it carries is refused: the signature
// covers those exact bytes, so a file that says one thing and encodes another
// would publish a signature no installation can reproduce.
func readSignedState(path string) (signature.State, error) {
	content, err := readFile(path, stateLimit)
	if err != nil {
		return signature.State{}, fmt.Errorf("read the state: %w", err)
	}
	state, err := parseCanonicalState(content)
	if err != nil {
		return signature.State{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if err = state.Validate(); err != nil {
		return signature.State{}, fmt.Errorf("the state in %s is not complete: %w", path, err)
	}
	canonical, err := state.Canonical()
	if err != nil {
		return signature.State{}, fmt.Errorf("encode the state in %s: %w", path, err)
	}
	if !bytes.Equal(canonical, content) {
		return signature.State{}, fmt.Errorf("%s is not the canonical encoding of the state it carries: sign the payload cpak-sign state wrote, byte for byte", path)
	}
	if !digestPattern.MatchString(state.ImageDigest) {
		return signature.State{}, fmt.Errorf("the state in %s names %q, which is not an image digest", path, state.ImageDigest)
	}
	return state, nil
}

// parseCanonicalState reads a payload back into the state it encodes. It is a
// reader for the canonical format and never a second definition of it: what it
// produces is put through Canonical again by the caller and refused unless it
// comes back as the same bytes, so a reading that differs from the one in
// pkg/signature cannot be published.
func parseCanonicalState(content []byte) (signature.State, error) {
	return signature.ParseCanonicalState(content)
}

func readFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBounded(file, limit)
}
