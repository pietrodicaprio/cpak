/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
)

func FuzzStrictCMSParser(f *testing.F) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	pki := newCMSTestPKI(f, now, nil, nil)
	valid := signTestCMS(f, testX509State(), pki, pkcs7.OIDDigestAlgorithmSHA256, nil)
	f.Add(valid)
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte("not CMS"))
	f.Fuzz(func(t *testing.T, document []byte) {
		_, _ = parseStrictCMS(document, true, oidCMSData)
	})
}

func FuzzRootBundleParser(f *testing.F) {
	valid, err := EmbeddedRootBundle()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"abi":1,"sources":[],"roots":[]}`))
	f.Add([]byte("not JSON"))
	f.Fuzz(func(t *testing.T, document []byte) {
		_, _ = ParseRootBundle(document)
	})
}
