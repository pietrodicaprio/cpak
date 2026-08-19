/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratedProfilesSeparateRootIntermediatePublisherAndTSA(t *testing.T) {
	base := t.TempDir()
	passphrase := filepath.Join(base, "passphrase")
	if err := os.WriteFile(passphrase, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(base, "material")
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	if err := run([]string{"--output", output, "--key-passphrase-file", passphrase, "--publisher", "Example Publisher"}, now); err != nil {
		t.Fatal(err)
	}
	root := readCertificate(t, filepath.Join(output, "root.pem"))
	codeCA := readCertificate(t, filepath.Join(output, "code-signing-intermediate.pem"))
	publisher := readCertificate(t, filepath.Join(output, "publisher.pem"))
	timestampCA := readCertificate(t, filepath.Join(output, "timestamping-intermediate.pem"))
	tsa := readCertificate(t, filepath.Join(output, "tsa.pem"))

	if !root.IsCA || root.MaxPathLen != 1 || root.KeyUsage&x509.KeyUsageCertSign == 0 || root.CheckSignatureFrom(root) != nil {
		t.Fatalf("root profile = %+v", root)
	}
	if !codeCA.IsCA || !codeCA.MaxPathLenZero || codeCA.MaxPathLen != 0 || codeCA.CheckSignatureFrom(root) != nil {
		t.Fatalf("code-signing intermediate profile = %+v", codeCA)
	}
	if !timestampCA.IsCA || !timestampCA.MaxPathLenZero || timestampCA.CheckSignatureFrom(root) != nil {
		t.Fatalf("timestamping intermediate profile = %+v", timestampCA)
	}
	if publisher.IsCA || publisher.KeyUsage != x509.KeyUsageDigitalSignature || len(publisher.ExtKeyUsage) != 1 || publisher.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning || publisher.CheckSignatureFrom(codeCA) != nil {
		t.Fatalf("publisher profile = %+v", publisher)
	}
	if tsa.IsCA || tsa.KeyUsage != x509.KeyUsageDigitalSignature || len(tsa.ExtKeyUsage) != 1 || tsa.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || tsa.CheckSignatureFrom(timestampCA) != nil {
		t.Fatalf("TSA profile = %+v", tsa)
	}
	if publisher.CheckSignatureFrom(root) == nil {
		t.Fatal("publisher was signed directly by the root")
	}
	for _, name := range []string{"root-key.pem", "code-signing-intermediate-key.pem", "timestamping-intermediate-key.pem", "publisher-key.pem", "tsa-key.pem"} {
		info, err := os.Stat(filepath.Join(output, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", name, info.Mode().Perm())
		}
		encoded, err := os.ReadFile(filepath.Join(output, name))
		if err != nil {
			t.Fatal(err)
		}
		block, rest := pem.Decode(encoded)
		if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" || len(rest) != 0 {
			t.Fatalf("%s is not one encrypted PKCS#8 key", name)
		}
	}
	if _, err := x509.ParseRevocationList(readPEM(t, filepath.Join(output, "publisher.crl.pem"), "X509 CRL")); err != nil {
		t.Fatalf("parse generated CRL: %v", err)
	}
}

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(readPEM(t, path, "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func readPEM(t *testing.T, path, kind string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != kind || len(rest) != 0 {
		t.Fatalf("%s is not one %s PEM block", path, kind)
	}
	return block.Bytes
}
