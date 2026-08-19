/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package signature

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	DefaultX509TrustBoundary        = "/etc/cpak/trust"
	DefaultCodeSigningRootDirectory = "/etc/cpak/trust/code-signing.d"
	DefaultTimestampRootDirectory   = "/etc/cpak/trust/timestamping.d"
	DefaultPublisherCRLDirectory    = "/etc/cpak/trust/revocation/code-signing.d"
	DefaultTimestampCRLDirectory    = "/etc/cpak/trust/revocation/timestamping.d"
	MaxLocalCRLSize                 = 1 << 20
)

var (
	linkRootFile      = os.Link
	syncTrustRootPath = syncDirectory
)

type LocalRootStore struct {
	Boundary              string
	CodeSigningDirectory  string
	TimestampingDirectory string
	PublisherCRLDirectory string
	TimestampCRLDirectory string
	OwnerUID              uint32
}

func DefaultLocalRootStore() LocalRootStore {
	return LocalRootStore{
		Boundary:              DefaultX509TrustBoundary,
		CodeSigningDirectory:  DefaultCodeSigningRootDirectory,
		TimestampingDirectory: DefaultTimestampRootDirectory,
		PublisherCRLDirectory: DefaultPublisherCRLDirectory,
		TimestampCRLDirectory: DefaultTimestampCRLDirectory,
		OwnerUID:              0,
	}
}

type RootPreview struct {
	Fingerprint string
	Subject     string
	NotBefore   string
	NotAfter    string
}

func LoadDefaultX509Trust() (*X509TrustSet, error) {
	return DefaultLocalRootStore().Load()
}

func (s LocalRootStore) Load() (*X509TrustSet, error) {
	trust, err := LoadEmbeddedX509Trust()
	if err != nil {
		return nil, err
	}
	for _, source := range []struct {
		directory string
		purpose   string
	}{
		{s.CodeSigningDirectory, RootPurposeCodeSigning},
		{s.TimestampingDirectory, RootPurposeTimestamping},
	} {
		roots, err := s.loadDirectory(source.directory, source.purpose)
		if err != nil {
			return nil, err
		}
		for _, root := range roots {
			if _, duplicate := trust.Roots[root.Fingerprint]; duplicate {
				return nil, fmt.Errorf("local root %s duplicates another admitted root", root.Fingerprint)
			}
			trust.addRoot(root)
		}
	}
	trust.PublisherCRLs, err = s.loadCRLDirectory(s.PublisherCRLDirectory)
	if err != nil {
		return nil, err
	}
	trust.TimestampCRLs, err = s.loadCRLDirectory(s.TimestampCRLDirectory)
	if err != nil {
		return nil, err
	}
	return trust, nil
}

func (s LocalRootStore) Preview(path string) (RootPreview, error) {
	data, err := readBoundedRegularFile(path, MaxLocalRootSize, false, 0)
	if err != nil {
		return RootPreview{}, err
	}
	cert, err := parseSingleRoot(data)
	if err != nil {
		return RootPreview{}, err
	}
	sum := sha256.Sum256(cert.Raw)
	return RootPreview{
		Fingerprint: hex.EncodeToString(sum[:]),
		Subject:     safeDisplayName(cert.Subject.String()),
		NotBefore:   cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:    cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}, nil
}

// Import admits exactly the root the administrator previewed. The expected
// fingerprint is mandatory so privilege escalation cannot swap the source
// file between an unprivileged preview and the root-owned write.
func (s LocalRootStore) Import(path, purpose, expectedFingerprint string) (RootPreview, error) {
	if !validLowerSHA256(expectedFingerprint) {
		return RootPreview{}, errors.New("import a root only after confirming its lowercase SHA-256 fingerprint")
	}
	preview, err := s.Preview(path)
	if err != nil {
		return RootPreview{}, err
	}
	if preview.Fingerprint != expectedFingerprint {
		return RootPreview{}, errors.New("the root file no longer matches the confirmed fingerprint")
	}
	data, err := readBoundedRegularFile(path, MaxLocalRootSize, false, 0)
	if err != nil {
		return RootPreview{}, err
	}
	cert, err := parseSingleRoot(data)
	if err != nil {
		return RootPreview{}, err
	}
	directory, err := s.directoryFor(purpose)
	if err != nil {
		return RootPreview{}, err
	}
	if err := s.ensureSecureDirectory(directory); err != nil {
		return RootPreview{}, err
	}
	destination := filepath.Join(directory, expectedFingerprint+".der")
	if _, err := os.Lstat(destination); err == nil {
		return RootPreview{}, fmt.Errorf("root %s is already imported for %s", expectedFingerprint, purpose)
	} else if !os.IsNotExist(err) {
		return RootPreview{}, err
	}
	temporary, err := os.CreateTemp(directory, ".cpak-root-*")
	if err != nil {
		return RootPreview{}, fmt.Errorf("create temporary root file: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() {
		temporary.Close()
		_ = os.Remove(temporaryName)
	}()
	// Certificates and revocation lists are public trust material. They stay
	// root-owned and immutable to the verifier, but the unprivileged verifier
	// process must be able to read them.
	if err := temporary.Chmod(0o644); err != nil {
		return RootPreview{}, err
	}
	if err := temporary.Chown(int(s.OwnerUID), -1); err != nil && os.Geteuid() == 0 {
		return RootPreview{}, err
	}
	if _, err := temporary.Write(cert.Raw); err != nil {
		return RootPreview{}, err
	}
	if err := temporary.Sync(); err != nil {
		return RootPreview{}, err
	}
	if err := temporary.Close(); err != nil {
		return RootPreview{}, err
	}
	// A hard link is the commit point: unlike Rename it cannot replace a root
	// imported concurrently under the same fingerprint.
	if err := linkRootFile(temporaryName, destination); err != nil {
		return RootPreview{}, err
	}
	if err := syncTrustRootPath(directory); err != nil {
		return RootPreview{}, err
	}
	if err := os.Remove(temporaryName); err != nil {
		return RootPreview{}, err
	}
	return preview, nil
}

func (s LocalRootStore) Remove(purpose, fingerprint string) error {
	if !validLowerSHA256(fingerprint) {
		return errors.New("remove a root by its lowercase SHA-256 fingerprint")
	}
	directory, err := s.directoryFor(purpose)
	if err != nil {
		return err
	}
	if err := s.validateDirectory(directory); err != nil {
		return err
	}
	path := filepath.Join(directory, fingerprint+".der")
	data, err := readBoundedRegularFile(path, MaxLocalRootSize, true, s.OwnerUID)
	if err != nil {
		return err
	}
	cert, err := parseSingleRoot(data)
	if err != nil {
		return fmt.Errorf("refuse to remove an invalid admitted root: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	if hex.EncodeToString(sum[:]) != fingerprint {
		return errors.New("refuse to remove a root whose content does not match its filename")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncTrustRootPath(directory)
}

func (s LocalRootStore) List() ([]X509Root, error) {
	var roots []X509Root
	for _, source := range []struct{ directory, purpose string }{
		{s.CodeSigningDirectory, RootPurposeCodeSigning},
		{s.TimestampingDirectory, RootPurposeTimestamping},
	} {
		found, err := s.loadDirectory(source.directory, source.purpose)
		if err != nil {
			return nil, err
		}
		roots = append(roots, found...)
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Fingerprint < roots[j].Fingerprint })
	return roots, nil
}

func (s LocalRootStore) loadDirectory(directory, purpose string) ([]X509Root, error) {
	if directory == "" {
		return nil, nil
	}
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := s.validateDirectory(directory); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	roots := make([]X509Root, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, fmt.Errorf("local root directory contains a subdirectory %q", entry.Name())
		}
		path := filepath.Join(directory, entry.Name())
		data, err := readBoundedRegularFile(path, MaxLocalRootSize, true, s.OwnerUID)
		if err != nil {
			return nil, err
		}
		cert, err := parseSingleRoot(data)
		if err != nil {
			return nil, fmt.Errorf("read local root %q: %w", entry.Name(), err)
		}
		sum := sha256.Sum256(cert.Raw)
		fingerprint := hex.EncodeToString(sum[:])
		root, err := validateRootEntry(RootBundleEntry{
			SHA256: fingerprint, Subject: cert.Subject.String(), Purposes: []string{purpose}, DER: cert.Raw,
		}, RootSourceLocal)
		if err != nil {
			return nil, err
		}
		roots = append(roots, root)
	}
	return roots, nil
}

func (s LocalRootStore) loadCRLDirectory(directory string) ([]*x509.RevocationList, error) {
	if directory == "" {
		return nil, nil
	}
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := s.validateDirectory(directory); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	lists := make([]*x509.RevocationList, 0, len(entries))
	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, fmt.Errorf("local CRL directory contains a subdirectory %q", entry.Name())
		}
		data, err := readBoundedRegularFile(filepath.Join(directory, entry.Name()), MaxLocalCRLSize, true, s.OwnerUID)
		if err != nil {
			return nil, err
		}
		list, err := parseSingleCRL(data)
		if err != nil {
			return nil, fmt.Errorf("read local CRL %q: %w", entry.Name(), err)
		}
		digest := sha256.Sum256(list.Raw)
		fingerprint := hex.EncodeToString(digest[:])
		if seen[fingerprint] {
			return nil, fmt.Errorf("local CRL %s is duplicated", fingerprint)
		}
		seen[fingerprint] = true
		lists = append(lists, list)
	}
	return lists, nil
}

func (s LocalRootStore) directoryFor(purpose string) (string, error) {
	switch purpose {
	case RootPurposeCodeSigning:
		return s.CodeSigningDirectory, nil
	case RootPurposeTimestamping:
		return s.TimestampingDirectory, nil
	default:
		return "", errors.New("root purpose must be code-signing or timestamping")
	}
}

func (s LocalRootStore) ensureSecureDirectory(directory string) error {
	if s.Boundary == "" || directory == "" {
		return errors.New("local root store has no security boundary")
	}
	relative, err := filepath.Rel(filepath.Clean(s.Boundary), filepath.Clean(directory))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("local root directory escapes its security boundary")
	}
	paths, err := s.directoryPaths(directory)
	if err != nil {
		return err
	}
	// Validate every existing ancestor before MkdirAll gets a chance to follow
	// one. Otherwise a symlink inside the boundary could redirect creation
	// outside it before the post-creation validation noticed.
	missing := make(map[string]bool)
	for _, path := range paths {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			missing[path] = true
			continue
		}
		if err != nil {
			return err
		}
		if err := validateLocalRootDirectoryInfo(path, info, s.OwnerUID, false); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		for _, path := range paths {
			if missing[path] {
				if err := os.Chown(path, int(s.OwnerUID), -1); err != nil {
					return err
				}
			}
		}
	}
	if err := s.validateDirectoryAccess(directory, false); err != nil {
		return err
	}
	for _, path := range paths {
		if err := os.Chmod(path, 0o755); err != nil {
			return err
		}
	}
	return s.validateDirectory(directory)
}

// PrepareVerifierAccess upgrades trust material admitted before verification
// moved into an unprivileged process. It changes no owner and grants no write
// access: directories become traversable and public certificates and CRLs
// become readable. Every path is validated before its mode is changed.
func (s LocalRootStore) PrepareVerifierAccess() error {
	seen := make(map[string]bool)
	var files, paths []string
	seenPaths := make(map[string]bool)
	for _, directory := range []string{
		s.CodeSigningDirectory,
		s.TimestampingDirectory,
		s.PublisherCRLDirectory,
		s.TimestampCRLDirectory,
	} {
		directory = filepath.Clean(directory)
		if directory == "." || seen[directory] {
			continue
		}
		seen[directory] = true
		if _, err := os.Lstat(directory); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := s.validateDirectoryAccess(directory, false); err != nil {
			return err
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			path := filepath.Join(directory, entry.Name())
			if err := validateTrustedRegularFile(path, s.OwnerUID, false); err != nil {
				return err
			}
			files = append(files, path)
		}
		directoryPaths, err := s.directoryPaths(directory)
		if err != nil {
			return err
		}
		for _, path := range directoryPaths {
			if !seenPaths[path] {
				paths = append(paths, path)
				seenPaths[path] = true
			}
		}
	}
	for _, path := range files {
		if err := os.Chmod(path, 0o644); err != nil {
			return err
		}
	}
	for _, path := range paths {
		if err := os.Chmod(path, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func (s LocalRootStore) validateDirectory(directory string) error {
	return s.validateDirectoryAccess(directory, true)
}

func (s LocalRootStore) directoryPaths(directory string) ([]string, error) {
	boundary := filepath.Clean(s.Boundary)
	directory = filepath.Clean(directory)
	relative, err := filepath.Rel(boundary, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("local root directory escapes its security boundary")
	}
	paths := []string{boundary}
	if relative != "." {
		current := boundary
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			current = filepath.Join(current, component)
			paths = append(paths, current)
		}
	}
	return paths, nil
}

func (s LocalRootStore) validateDirectoryAccess(directory string, verifierReadable bool) error {
	paths, err := s.directoryPaths(directory)
	if err != nil {
		return err
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if err := validateLocalRootDirectoryInfo(path, info, s.OwnerUID, verifierReadable); err != nil {
			return err
		}
	}
	return nil
}

func validateLocalRootDirectoryInfo(path string, info os.FileInfo, owner uint32, verifierReadable bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("local root path %q is not a real directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner {
		return fmt.Errorf("local root path %q has an unsafe owner", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("local root path %q is writable by another account", path)
	}
	if verifierReadable && info.Mode().Perm()&0o005 != 0o005 {
		return fmt.Errorf("local root path %q is not accessible to the unprivileged verifier", path)
	}
	return nil
}

func parseSingleRoot(data []byte) (*x509.Certificate, error) {
	der := data
	if block, rest := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("root file must contain exactly one PEM certificate")
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse root certificate: %w", err)
	}
	if !bytes.Equal(cert.Raw, der) {
		return nil, errors.New("root file contains trailing certificate data")
	}
	entry := RootBundleEntry{SHA256: fingerprintOf(cert), Subject: cert.Subject.String(), Purposes: []string{RootPurposeCodeSigning}, DER: cert.Raw}
	if _, err := validateRootEntry(entry, RootSourceLocal); err != nil {
		return nil, err
	}
	return cert, nil
}

func parseSingleCRL(data []byte) (*x509.RevocationList, error) {
	der := data
	if block, rest := pem.Decode(data); block != nil {
		if block.Type != "X509 CRL" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("CRL file must contain exactly one PEM X509 CRL")
		}
		der = block.Bytes
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}
	if !bytes.Equal(list.Raw, der) {
		return nil, errors.New("CRL file contains trailing data")
	}
	return list, nil
}

func readBoundedRegularFile(path string, limit int64, trusted bool, owner uint32) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("root path is not a regular file")
	}
	if info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("root file has an invalid size")
	}
	if trusted {
		if err := validateTrustedRegularFileInfo(info, owner, true); err != nil {
			return nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() || int64(len(data)) > limit {
		return nil, errors.New("root file changed while it was read")
	}
	return data, nil
}

func validateTrustedRegularFile(path string, owner uint32, verifierReadable bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validateTrustedRegularFileInfo(info, owner, verifierReadable)
}

func validateTrustedRegularFileInfo(info os.FileInfo, owner uint32, verifierReadable bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("root path is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner || info.Mode().Perm()&0o022 != 0 {
		return errors.New("root file has unsafe ownership or permissions")
	}
	if verifierReadable && info.Mode().Perm()&0o004 == 0 {
		return errors.New("root file is not readable by the unprivileged verifier")
	}
	return nil
}

func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func safeDisplayName(value string) string {
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	encoded := []byte(value)
	if len(encoded) > 200 {
		encoded = encoded[:200]
		for len(encoded) > 0 && !utf8.Valid(encoded) {
			encoded = encoded[:len(encoded)-1]
		}
	}
	return string(encoded)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
