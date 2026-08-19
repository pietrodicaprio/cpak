/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/mirkobrombin/cpak/pkg/reputation"
	"github.com/youmark/pkcs8"
)

var reputationKeyEncryption = &pkcs8.Opts{
	Cipher: pkcs8.AES256GCM,
	KDFOpts: pkcs8.ScryptOpts{
		SaltSize: 16, CostParameter: 32768, BlockSize: 8, ParallelizationParameter: 1,
	},
}

func generateReputationKey(arguments []string) error {
	flags := flag.NewFlagSet("reputation-keygen", flag.ContinueOnError)
	providerID := flags.String("provider", "cpak-poc", "bounded lowercase provider identifier")
	keyPath := flags.String("output-key", "reputation-provider-key.pem", "new encrypted Ed25519 private-key file")
	authorityPath := flags.String("output-authority", "reputation-provider.json", "new public provider-authority document")
	passphrasePath := flags.String("key-passphrase-file", "", "0600 file or inherited descriptor containing the key passphrase")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *passphrasePath == "" {
		return errors.New("--key-passphrase-file is required")
	}
	if err := requirePrivateFileOrDescriptor(*passphrasePath); err != nil {
		return err
	}
	passphrase, err := readFile(*passphrasePath, passphraseLimit)
	if err != nil {
		return fmt.Errorf("read key passphrase: %w", err)
	}
	passphrase = bytes.TrimSuffix(passphrase, []byte{'\n'})
	if len(passphrase) == 0 || bytes.IndexByte(passphrase, 0) >= 0 {
		return errors.New("key passphrase is empty or invalid")
	}
	defer func() {
		for index := range passphrase {
			passphrase[index] = 0
		}
	}()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate reputation provider key: %w", err)
	}
	authority, err := reputation.NewAuthority(*providerID, publicKey)
	if err != nil {
		return err
	}
	privateDER, err := pkcs8.MarshalPrivateKey(privateKey, passphrase, reputationKeyEncryption)
	if err != nil {
		return fmt.Errorf("encrypt reputation provider key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: privateDER})
	if privatePEM == nil {
		return errors.New("encode reputation provider key")
	}
	authorityDocument, err := reputation.MarshalAuthority(authority)
	if err != nil {
		return err
	}
	if err := writeNewFile(*keyPath, privatePEM, 0o600); err != nil {
		return fmt.Errorf("write reputation provider key: %w", err)
	}
	if err := writeNewFile(*authorityPath, authorityDocument, 0o644); err != nil {
		_ = os.Remove(*keyPath)
		return fmt.Errorf("write reputation provider authority: %w", err)
	}
	fmt.Fprintf(os.Stderr, "generated experimental reputation provider %s with %s\n", authority.ProviderID, authority.KeyID)
	fmt.Fprintln(os.Stderr, "assurance: development key; keep the encrypted private key outside the repository and production trust boundary")
	return nil
}

func signReputation(arguments []string) error {
	flags := flag.NewFlagSet("reputation-sign", flag.ContinueOnError)
	authorityPath := flags.String("authority", "reputation-provider.json", "public provider-authority document")
	keyPath := flags.String("key", "reputation-provider-key.pem", "encrypted Ed25519 provider private key")
	passphrasePath := flags.String("key-passphrase-file", "", "0600 file or inherited descriptor containing the key passphrase")
	payloadPath := flags.String("payload", "reputation-payload.json", "unsigned sequence, validity, and entries JSON object")
	outputPath := flags.String("output", "reputation-snapshot.json", "new signed snapshot envelope")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *passphrasePath == "" {
		return errors.New("--key-passphrase-file is required")
	}
	authorityDocument, err := readFile(*authorityPath, reputation.MaxAuthoritySize)
	if err != nil {
		return fmt.Errorf("read reputation provider authority: %w", err)
	}
	authority, err := reputation.ParseAuthority(authorityDocument)
	if err != nil {
		return err
	}
	payloadDocument, err := readFile(*payloadPath, reputation.MaxSnapshotSize)
	if err != nil {
		return fmt.Errorf("read reputation payload: %w", err)
	}
	signed, err := reputation.ParseSigned(payloadDocument)
	if err != nil {
		return err
	}
	signer, err := readEncryptedSigner(*keyPath, *passphrasePath)
	if err != nil {
		return err
	}
	privateKey, ok := signer.(ed25519.PrivateKey)
	if !ok {
		return errors.New("reputation provider key must be Ed25519")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return fmt.Errorf("encode reputation provider public key: %w", err)
	}
	authorityDER, err := x509.MarshalPKIXPublicKey(authority.PublicKey)
	if err != nil {
		return fmt.Errorf("encode configured reputation provider key: %w", err)
	}
	if !bytes.Equal(publicDER, authorityDER) {
		return errors.New("private key does not match the reputation provider authority")
	}
	document, err := reputation.Sign(authority.ProviderID, privateKey, signed)
	if err != nil {
		return err
	}
	if err := writeNewFile(*outputPath, document, 0o644); err != nil {
		return fmt.Errorf("write signed reputation snapshot: %w", err)
	}
	fmt.Fprintf(os.Stderr, "signed reputation snapshot %d for %s; expires %s\n", signed.Sequence, authority.ProviderID, signed.ExpiresAt)
	return nil
}

func writeNewFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
