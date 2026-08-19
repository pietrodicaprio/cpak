/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/digitorus/pkcs7"
)

// SignX509CMS produces the detached CMS evidence consumed by X509CMSVerifier.
// The signer boundary intentionally accepts crypto.Signer so a later PKCS#11
// backend cannot change either the state or evidence format.
func SignX509CMS(state State, leaf *x509.Certificate, chain []*x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, fmt.Errorf("sign X.509 state: %w", err)
	}
	if leaf == nil || signer == nil {
		return nil, errors.New("sign X.509 state: certificate and signer are required")
	}
	if len(chain) == 0 {
		return nil, errors.New("sign X.509 state: an intermediate certificate is required")
	}
	if err := validateCodeSigningLeaf(leaf); err != nil {
		return nil, fmt.Errorf("sign X.509 state: %w", err)
	}
	if !publicKeysEqual(leaf.PublicKey, signer.Public()) {
		return nil, errors.New("sign X.509 state: private key does not match the publisher certificate")
	}
	canonical, err := state.Canonical()
	if err != nil {
		return nil, fmt.Errorf("sign X.509 state: %w", err)
	}
	signed, err := pkcs7.NewSignedData(canonical)
	if err != nil {
		return nil, fmt.Errorf("sign X.509 state: %w", err)
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err = signed.AddSignerChain(leaf, signer, chain, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("sign X.509 state: %w", err)
	}
	signed.Detach()
	der, err := signed.Finish()
	if err != nil {
		return nil, fmt.Errorf("sign X.509 state: %w", err)
	}
	if len(der) == 0 || len(der) > MaxSignatureEvidenceSize {
		return nil, errors.New("sign X.509 state: CMS output has an invalid size")
	}
	return der, nil
}

func publicKeysEqual(left, right any) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return string(leftDER) == string(rightDER)
}

func NewX509CMSEvidence(state State, payload []byte) SignatureEvidence {
	return SignatureEvidence{
		ABI: EvidenceABIVersion, Kind: EvidenceX509CMS, State: state,
		MediaType: X509CMSMediaType, Payload: payload,
	}
}
