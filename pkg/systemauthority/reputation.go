/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package systemauthority

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mirkobrombin/cpak/pkg/reputation"
)

const (
	DefaultReputationDirectory = "/var/lib/cpak/reputation/v1"
	reputationAuthorityFile    = "provider.json"
	reputationSnapshotFile     = "snapshot.json"
)

var (
	ErrReputationRollback = errors.New("reputation snapshot is not newer than the active snapshot")
	writeReputationFile   = writeAtomic
	syncReputationPath    = syncReputationDirectory
)

// ReputationStore is the root-owned boundary for the configured provider and
// its single active signed snapshot. The sequence stays inside that signed
// snapshot, so an interrupted second-file update cannot split data from its
// anti-rollback state.
type ReputationStore struct {
	Directory string
	OwnerUID  uint32
}

func DefaultReputationStore() ReputationStore {
	return ReputationStore{Directory: DefaultReputationDirectory, OwnerUID: 0}
}

func (s ReputationStore) Authority() (reputation.Authority, bool, error) {
	path, err := s.path(reputationAuthorityFile)
	if err != nil {
		return reputation.Authority{}, false, err
	}
	if err := validateExistingDirectory(s.Directory, s.OwnerUID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return reputation.Authority{}, false, nil
		}
		return reputation.Authority{}, false, err
	}
	document, found, err := readTrusted(path, s.OwnerUID, reputation.MaxAuthoritySize, "reputation provider authority")
	if err != nil || !found {
		return reputation.Authority{}, found, err
	}
	authority, err := reputation.ParseAuthority(document)
	if err != nil {
		return reputation.Authority{}, true, fmt.Errorf("read reputation provider authority: %w", err)
	}
	return authority, true, nil
}

// SetAuthority admits exactly the public key an administrator previewed. A
// provider change invalidates the prior active snapshot instead of carrying a
// sequence or verdict across authorities.
func (s ReputationStore) SetAuthority(document []byte, expectedKeyID string) (reputation.Authority, error) {
	authority, err := reputation.ParseAuthority(document)
	if err != nil {
		return reputation.Authority{}, err
	}
	if expectedKeyID == "" || expectedKeyID != authority.KeyID {
		return reputation.Authority{}, errors.New("configure a reputation provider only after confirming its exact key id")
	}
	if err := ensureDirectory(s.Directory, s.OwnerUID); err != nil {
		return reputation.Authority{}, err
	}
	current, found, err := s.Authority()
	if err == nil && found && current.ProviderID == authority.ProviderID && current.KeyID == authority.KeyID {
		return current, nil
	}
	authorityPath, err := s.path(reputationAuthorityFile)
	if err != nil {
		return reputation.Authority{}, err
	}
	canonical, err := reputation.MarshalAuthority(authority)
	if err != nil {
		return reputation.Authority{}, err
	}
	if err := writeReputationFile(authorityPath, canonical, 0644); err != nil {
		return reputation.Authority{}, fmt.Errorf("write reputation provider authority: %w", err)
	}
	if err := syncReputationPath(s.Directory); err != nil {
		return reputation.Authority{}, fmt.Errorf("sync reputation provider authority: %w", err)
	}
	snapshotPath, err := s.path(reputationSnapshotFile)
	if err != nil {
		return reputation.Authority{}, err
	}
	if err := os.Remove(snapshotPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return reputation.Authority{}, fmt.Errorf("remove snapshot from prior reputation provider: %w", err)
	}
	if err := syncReputationPath(s.Directory); err != nil {
		return reputation.Authority{}, fmt.Errorf("sync reputation provider change: %w", err)
	}
	return authority, nil
}

func (s ReputationStore) Clear() error {
	if _, err := s.path(reputationAuthorityFile); err != nil {
		return err
	}
	if err := validateExistingDirectory(s.Directory, s.OwnerUID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, name := range []string{reputationSnapshotFile, reputationAuthorityFile} {
		path, _ := s.path(name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove reputation %s: %w", name, err)
		}
	}
	return syncReputationPath(s.Directory)
}

// Import authenticates before it compares sequences, then atomically replaces
// the complete envelope. An expired active snapshot still owns its sequence.
func (s ReputationStore) Import(document []byte, now time.Time) (reputation.Snapshot, error) {
	authority, configured, err := s.Authority()
	if err != nil {
		return reputation.Snapshot{}, err
	}
	if !configured {
		return reputation.Snapshot{}, errors.New("no reputation provider is configured")
	}
	candidate, err := reputation.Verify(document, authority, now)
	if err != nil {
		return reputation.Snapshot{}, err
	}
	path, err := s.path(reputationSnapshotFile)
	if err != nil {
		return reputation.Snapshot{}, err
	}
	activeDocument, found, err := readTrusted(path, s.OwnerUID, reputation.MaxSnapshotSize, "active reputation snapshot")
	if err != nil {
		return reputation.Snapshot{}, err
	}
	if found {
		active, err := reputation.Authenticate(activeDocument, authority)
		if err != nil {
			return reputation.Snapshot{}, fmt.Errorf("read active reputation snapshot before replacement: %w", err)
		}
		if candidate.Sequence <= active.Sequence {
			return reputation.Snapshot{}, fmt.Errorf("%w: active %d, offered %d", ErrReputationRollback, active.Sequence, candidate.Sequence)
		}
	}
	if err := writeReputationFile(path, document, 0644); err != nil {
		return reputation.Snapshot{}, fmt.Errorf("write active reputation snapshot: %w", err)
	}
	if err := syncReputationPath(s.Directory); err != nil {
		return reputation.Snapshot{}, fmt.Errorf("sync active reputation snapshot: %w", err)
	}
	return candidate, nil
}

func (s ReputationStore) Current(now time.Time) (reputation.Snapshot, bool, error) {
	authority, configured, err := s.Authority()
	if err != nil || !configured {
		return reputation.Snapshot{}, false, err
	}
	path, err := s.path(reputationSnapshotFile)
	if err != nil {
		return reputation.Snapshot{}, false, err
	}
	document, found, err := readTrusted(path, s.OwnerUID, reputation.MaxSnapshotSize, "active reputation snapshot")
	if err != nil || !found {
		return reputation.Snapshot{}, found, err
	}
	snapshot, err := reputation.Verify(document, authority, now)
	if err != nil {
		return reputation.Snapshot{}, true, err
	}
	return snapshot, true, nil
}

func (s ReputationStore) Lookup(publisherID string, now time.Time) (reputation.Result, error) {
	authority, configured, err := s.Authority()
	if err != nil {
		return reputation.UnavailableResult("", publisherID, "provider-configuration-invalid"), err
	}
	if !configured {
		return reputation.UnavailableResult("", publisherID, "provider-not-configured"), nil
	}
	snapshot, found, err := s.Current(now)
	if err != nil {
		return reputation.UnavailableResult(authority.ProviderID, publisherID, "snapshot-unavailable"), err
	}
	if !found {
		return reputation.UnavailableResult(authority.ProviderID, publisherID, "snapshot-not-installed"), nil
	}
	return reputation.NewOfflineProvider(snapshot).Lookup(publisherID), nil
}

func (s ReputationStore) path(name string) (string, error) {
	if !filepath.IsAbs(s.Directory) {
		return "", errors.New("system authority reputation path must be absolute")
	}
	return filepath.Join(s.Directory, name), nil
}

func syncReputationDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
