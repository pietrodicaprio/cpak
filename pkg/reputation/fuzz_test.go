/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package reputation

import "testing"

func FuzzSnapshotParsers(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		[]byte(`{}`),
		[]byte(`{"abi":1,"signed":{},"key_id":"sha256:00","signature":""}`),
		[]byte(`{"abi":1,"abi":1}`),
		[]byte("null{}"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, document []byte) {
		if len(document) > MaxSnapshotSize+1 {
			document = document[:MaxSnapshotSize+1]
		}
		_, _ = ParseSigned(document)
	})
}

func FuzzAuthorityParser(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		[]byte(`{}`),
		[]byte(`{"abi":1,"provider_id":"cpak-poc","key_id":"sha256:00","public_key":""}`),
		[]byte(`{"abi":1,"abi":1}`),
		[]byte("null{}"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, document []byte) {
		if len(document) > MaxAuthoritySize+1 {
			document = document[:MaxAuthoritySize+1]
		}
		_, _ = ParseAuthority(document)
	})
}
