/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

// Command poc-ca creates disposable private-PKI material for the cpak
// application-trust demonstration. It is development tooling, not part of the
// cpak runtime or a remotely operated certificate authority.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/youmark/pkcs8"
)

var experimentalPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1, 1}

var pocKeyEncryption = &pkcs8.Opts{
	Cipher: pkcs8.AES256GCM,
	KDFOpts: pkcs8.ScryptOpts{
		SaltSize: 16, CostParameter: 32768, BlockSize: 8, ParallelizationParameter: 1,
	},
}

type issued struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

type manifest struct {
	Assurance    string            `json:"assurance"`
	GeneratedAt  string            `json:"generated_at"`
	PolicyOID    string            `json:"policy_oid"`
	Fingerprints map[string]string `json:"sha256_fingerprints"`
}

func main() {
	if err := run(os.Args[1:], time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, now time.Time) error {
	flags := flag.NewFlagSet("poc-ca", flag.ContinueOnError)
	output := flags.String("output", "", "new empty directory for disposable CA material")
	passphraseFile := flags.String("key-passphrase-file", "", "0600 file containing the passphrase used to encrypt generated private keys")
	publisherName := flags.String("publisher", "Example Publisher", "bounded display name for the test publisher certificate")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *output == "" || *passphraseFile == "" {
		return errors.New("--output and --key-passphrase-file are required")
	}
	if err := validatePublisherName(*publisherName); err != nil {
		return err
	}
	passphrase, err := readPassphrase(*passphraseFile)
	if err != nil {
		return err
	}
	defer func() {
		for index := range passphrase {
			passphrase[index] = 0
		}
	}()
	if err = os.Mkdir(*output, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	root, err := selfSignedCA(now, "cpak Experimental POC Root", 1, 10*365*24*time.Hour)
	if err != nil {
		return err
	}
	codeCA, err := subordinateCA(now, "cpak Experimental Code Signing Intermediate", root, 5*365*24*time.Hour)
	if err != nil {
		return err
	}
	timestampCA, err := subordinateCA(now, "cpak Experimental Timestamping Intermediate", root, 5*365*24*time.Hour)
	if err != nil {
		return err
	}
	publisher, err := endEntity(now, *publisherName, codeCA, x509.ExtKeyUsageCodeSigning, 90*24*time.Hour)
	if err != nil {
		return err
	}
	publisherRotated, err := endEntity(now, *publisherName, codeCA, x509.ExtKeyUsageCodeSigning, 90*24*time.Hour)
	if err != nil {
		return err
	}
	tsa, err := endEntity(now, "cpak Experimental POC TSA", timestampCA, x509.ExtKeyUsageTimeStamping, 365*24*time.Hour)
	if err != nil {
		return err
	}

	certificates := map[string]*x509.Certificate{
		"root.pem":                      root.certificate,
		"code-signing-intermediate.pem": codeCA.certificate,
		"timestamping-intermediate.pem": timestampCA.certificate,
		"publisher.pem":                 publisher.certificate,
		"publisher-rotated.pem":         publisherRotated.certificate,
		"tsa.pem":                       tsa.certificate,
	}
	for name, certificate := range certificates {
		if err = writePEM(filepath.Join(*output, name), "CERTIFICATE", certificate.Raw, 0o644); err != nil {
			return err
		}
	}
	keys := map[string]crypto.PrivateKey{
		"root-key.pem":                      root.key,
		"code-signing-intermediate-key.pem": codeCA.key,
		"timestamping-intermediate-key.pem": timestampCA.key,
		"publisher-key.pem":                 publisher.key,
		"publisher-rotated-key.pem":         publisherRotated.key,
		"tsa-key.pem":                       tsa.key,
	}
	for name, key := range keys {
		der, marshalErr := pkcs8.MarshalPrivateKey(key, passphrase, pocKeyEncryption)
		if marshalErr != nil {
			return fmt.Errorf("encrypt %s: %w", name, marshalErr)
		}
		if err = writePEM(filepath.Join(*output, name), "ENCRYPTED PRIVATE KEY", der, 0o600); err != nil {
			return err
		}
	}
	if err = writePEM(filepath.Join(*output, "publisher-chain.pem"), "CERTIFICATE", codeCA.certificate.Raw, 0o644); err != nil {
		return err
	}
	if err = writePEM(filepath.Join(*output, "publisher-rotated-chain.pem"), "CERTIFICATE", codeCA.certificate.Raw, 0o644); err != nil {
		return err
	}
	crl, err := emptyCRL(now, codeCA)
	if err != nil {
		return err
	}
	if err = writePEM(filepath.Join(*output, "publisher.crl.pem"), "X509 CRL", crl, 0o644); err != nil {
		return err
	}
	revokedCRL, err := revokedPublisherCRL(now, codeCA, publisher.certificate)
	if err != nil {
		return err
	}
	if err = writePEM(filepath.Join(*output, "publisher-revoked.crl.pem"), "X509 CRL", revokedCRL, 0o644); err != nil {
		return err
	}

	fingerprints := make(map[string]string, len(certificates))
	for name, certificate := range certificates {
		sum := sha256.Sum256(certificate.Raw)
		fingerprints[name] = hex.EncodeToString(sum[:])
	}
	encoded, err := json.MarshalIndent(manifest{
		Assurance: "experimental-private-pki", GeneratedAt: now.Format(time.RFC3339),
		PolicyOID: experimentalPolicy.String(), Fingerprints: fingerprints,
	}, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile(filepath.Join(*output, "manifest.json"), encoded, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "generated disposable experimental CA material in %s\n", *output)
	fmt.Fprintln(os.Stderr, "do not commit or reuse any *-key.pem file")
	return nil
}

func selfSignedCA(now time.Time, commonName string, maxPath int, lifetime time.Duration) (issued, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issued{}, err
	}
	template, err := caTemplate(now, commonName, lifetime)
	if err != nil {
		return issued{}, err
	}
	template.MaxPathLen = maxPath
	template.MaxPathLenZero = maxPath == 0
	created, err := create(template, template, &key.PublicKey, key)
	created.key = key
	return created, err
}

func subordinateCA(now time.Time, commonName string, parent issued, lifetime time.Duration) (issued, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issued{}, err
	}
	template, err := caTemplate(now, commonName, lifetime)
	if err != nil {
		return issued{}, err
	}
	template.MaxPathLen = 0
	template.MaxPathLenZero = true
	created, err := create(template, parent.certificate, &key.PublicKey, parent.key)
	created.key = key
	return created, err
}

func caTemplate(now time.Time, commonName string, lifetime time.Duration) (*x509.Certificate, error) {
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"cpak Experimental POC"}, CommonName: commonName},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.Add(lifetime),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:          x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PolicyIdentifiers: []asn1.ObjectIdentifier{experimentalPolicy},
	}, nil
}

func endEntity(now time.Time, commonName string, parent issued, usage x509.ExtKeyUsage, lifetime time.Duration) (issued, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issued{}, err
	}
	serial, err := serialNumber()
	if err != nil {
		return issued{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{commonName}, CommonName: commonName},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.Add(lifetime),
		BasicConstraintsValid: true, IsCA: false,
		KeyUsage:          x509.KeyUsageDigitalSignature,
		ExtKeyUsage:       []x509.ExtKeyUsage{usage},
		PolicyIdentifiers: []asn1.ObjectIdentifier{experimentalPolicy},
	}
	created, err := create(template, parent.certificate, &key.PublicKey, parent.key)
	created.key = key
	return created, err
}

func create(template, parent *x509.Certificate, public any, signer crypto.Signer) (issued, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		return issued{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return issued{}, err
	}
	return issued{certificate: certificate}, nil
}

// reasonKeyCompromise is the RFC 5280 CRL entry reason code marking a revoked
// certificate's key as compromised.
const reasonKeyCompromise = 1

func signCRL(now time.Time, issuer issued, number *big.Int, entries []x509.RevocationListEntry) ([]byte, error) {
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:        issuer.certificate.SignatureAlgorithm,
		Number:                    number,
		ThisUpdate:                now.Add(-5 * time.Minute),
		NextUpdate:                now.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, issuer.certificate, issuer.key)
}

func emptyCRL(now time.Time, issuer issued) ([]byte, error) {
	return signCRL(now, issuer, big.NewInt(1), nil)
}

func revokedPublisherCRL(now time.Time, issuer issued, publisher *x509.Certificate) ([]byte, error) {
	return signCRL(now, issuer, big.NewInt(2), []x509.RevocationListEntry{{
		SerialNumber:   publisher.SerialNumber,
		RevocationTime: now.Add(-1 * time.Minute),
		ReasonCode:     reasonKeyCompromise,
	}})
}

func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return serial, nil
}

func writePEM(path, kind string, der []byte, mode os.FileMode) error {
	encoded := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
	if encoded == nil {
		return fmt.Errorf("encode %s", filepath.Base(path))
	}
	if err := os.WriteFile(path, encoded, mode); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

func readPassphrase(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect passphrase file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("passphrase must come from a regular file readable only by its owner")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content = bytes.TrimSuffix(content, []byte{'\n'})
	if len(content) < 12 || len(content) > 4096 {
		return nil, errors.New("passphrase must contain between 12 and 4096 bytes")
	}
	return content, nil
}

func validatePublisherName(value string) error {
	if value != strings.TrimSpace(value) || len(value) < 1 || len(value) > 96 {
		return errors.New("publisher name must contain 1 to 96 trimmed bytes")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return errors.New("publisher name contains a control character")
		}
	}
	return nil
}
