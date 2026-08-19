/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mirkobrombin/cpak/pkg/signature"
	"github.com/youmark/pkcs8"
)

const (
	defaultCMSPath   = "cpak-state.x509.cms"
	keyLimit         = 128 << 10
	certificateLimit = 256 << 10
	passphraseLimit  = 4 << 10
)

func signX509(arguments []string) error {
	flags := flag.NewFlagSet("x509-sign", flag.ContinueOnError)
	statePath := flags.String("state", defaultStatePath, "path to the canonical state produced by cpak-sign state")
	certificatePath := flags.String("certificate", "", "publisher Code Signing certificate in PEM or DER")
	chainPath := flags.String("chain", "", "intermediate certificate chain in PEM or DER, leaf issuer first")
	keyPath := flags.String("key", "", "encrypted PKCS#8 publisher private key")
	passphrasePath := flags.String("key-passphrase-file", "", "0600 file or inherited file descriptor containing the key passphrase")
	outputPath := flags.String("output", defaultCMSPath, "path for detached CMS evidence")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *certificatePath == "" || *chainPath == "" || *keyPath == "" || *passphrasePath == "" {
		return errors.New("--certificate, --chain, --key, and --key-passphrase-file are required")
	}
	state, err := readSignedState(*statePath)
	if err != nil {
		return err
	}
	leafs, err := readCertificates(*certificatePath)
	if err != nil {
		return fmt.Errorf("read publisher certificate: %w", err)
	}
	if len(leafs) != 1 {
		return fmt.Errorf("publisher certificate file contains %d certificates, expected exactly one", len(leafs))
	}
	chain, err := readCertificates(*chainPath)
	if err != nil {
		return fmt.Errorf("read publisher chain: %w", err)
	}
	if len(chain) == 0 {
		return errors.New("publisher chain contains no intermediate certificate")
	}
	signer, err := readEncryptedSigner(*keyPath, *passphrasePath)
	if err != nil {
		return err
	}
	der, err := signature.SignX509CMS(state, leafs[0], chain, signer)
	if err != nil {
		return err
	}
	if err = os.WriteFile(*outputPath, der, 0o644); err != nil {
		return fmt.Errorf("write detached CMS evidence: %w", err)
	}
	fingerprint := sha256.Sum256(leafs[0].RawSubjectPublicKeyInfo)
	fmt.Fprintf(os.Stderr, "signed state as %s with experimental private-PKI publisher x509-spki-sha256:%s\n", *outputPath, hex.EncodeToString(fingerprint[:]))
	fmt.Fprintln(os.Stderr, "assurance: experimental; this signature has no public trust or publisher reputation unless an administrator explicitly grants it")
	return nil
}

func readCertificates(path string) ([]*x509.Certificate, error) {
	content, err := readFile(path, certificateLimit)
	if err != nil {
		return nil, err
	}
	var certificates []*x509.Certificate
	remainder := content
	for {
		block, rest := pem.Decode(remainder)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("certificate PEM contains an unsupported block")
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, parseErr
		}
		certificates = append(certificates, certificate)
		remainder = rest
	}
	if len(certificates) > 0 {
		if strings.TrimSpace(string(remainder)) != "" {
			return nil, errors.New("certificate PEM contains trailing data")
		}
		return certificates, nil
	}
	certificate, err := x509.ParseCertificate(content)
	if err != nil {
		return nil, err
	}
	if len(certificate.Raw) != len(content) {
		return nil, errors.New("certificate DER contains trailing data")
	}
	return []*x509.Certificate{certificate}, nil
}

func readEncryptedSigner(keyPath, passphrasePath string) (crypto.Signer, error) {
	if err := requirePrivateFile(keyPath, "private key"); err != nil {
		return nil, err
	}
	if err := requirePrivateFileOrDescriptor(passphrasePath); err != nil {
		return nil, err
	}
	encoded, err := readFile(keyPath, keyLimit)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("private key must be exactly one encrypted PKCS#8 PEM block")
	}
	passphrase, err := readFile(passphrasePath, passphraseLimit)
	if err != nil {
		return nil, fmt.Errorf("read key passphrase: %w", err)
	}
	passphrase = bytes.TrimSuffix(passphrase, []byte{'\n'})
	if len(passphrase) == 0 || bytes.IndexByte(passphrase, 0) >= 0 {
		return nil, errors.New("key passphrase is empty or invalid")
	}
	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, passphrase)
	for index := range passphrase {
		passphrase[index] = 0
	}
	if err != nil {
		return nil, errors.New("decrypt private key: passphrase or PKCS#8 data is invalid")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("decrypted private key cannot sign")
	}
	return signer, nil
}

func requirePrivateFile(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be a regular file readable only by its owner (mode 0600 or stricter)", label)
	}
	return nil
}

func requirePrivateFileOrDescriptor(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect key passphrase file: %w", err)
	}
	if info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if info.Mode()&os.ModeNamedPipe != 0 || strings.HasPrefix(path, "/proc/self/fd/") || strings.HasPrefix(path, "/dev/fd/") {
		return nil
	}
	return errors.New("key passphrase must come from a 0600 file, named pipe, or inherited file descriptor")
}
