/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mirkobrombin/cpak/pkg/reputation"
	"github.com/mirkobrombin/cpak/pkg/systemauthority"
	"github.com/mirkobrombin/cpak/pkg/tools"
)

type reputationAdminStore interface {
	Authority() (reputation.Authority, bool, error)
	SetAuthority([]byte, string) (reputation.Authority, error)
	Clear() error
	Import([]byte, time.Time) (reputation.Snapshot, error)
	Current(time.Time) (reputation.Snapshot, bool, error)
	Lookup(string, time.Time) (reputation.Result, error)
}

var (
	reputationStore    = func() reputationAdminStore { return systemauthority.DefaultReputationStore() }
	reputationEUID     = os.Geteuid
	reputationEscalate = runPrivileged
	confirmReputation  = tools.ConfirmOperation
	reputationClock    = time.Now
)

func (c *SystemCmd) manageReputation(action string) error {
	store := reputationStore()
	switch action {
	case "reputation-provider-preview":
		document, authority, err := readReputationAuthority(c.Target)
		_ = document
		if err != nil {
			return err
		}
		c.reportReputationAuthority(authority)
		return nil
	case "reputation-provider-set":
		document, authority, err := readReputationAuthority(c.Target)
		if err != nil {
			return err
		}
		c.reportReputationAuthority(authority)
		confirmed, err := c.confirmReputationFingerprint(authority.KeyID, "Configure exactly this reputation provider key?")
		if err != nil {
			return err
		}
		if reputationEUID() != 0 {
			return reputationEscalate("system", action, c.Target, "--fingerprint", confirmed, "--yes")
		}
		configured, err := store.SetAuthority(document, confirmed)
		if err != nil {
			return err
		}
		c.Logger.Success("Configured reputation provider %s with %s.", configured.ProviderID, configured.KeyID)
		return nil
	case "reputation-provider-clear":
		authority, found, err := store.Authority()
		if err != nil {
			return err
		}
		if !found {
			c.Logger.Info("No reputation provider is configured.")
			return nil
		}
		c.reportReputationAuthority(authority)
		confirmed, err := c.confirmReputationFingerprint(authority.KeyID, "Remove this provider and its active reputation snapshot?")
		if err != nil {
			return err
		}
		if reputationEUID() != 0 {
			return reputationEscalate("system", action, "--fingerprint", confirmed, "--yes")
		}
		authority, found, err = store.Authority()
		if err != nil {
			return err
		}
		if !found {
			return errors.New("the reputation provider changed before it could be removed")
		}
		if authority.KeyID != confirmed {
			return errors.New("the supplied fingerprint does not match the configured reputation provider")
		}
		if err := store.Clear(); err != nil {
			return err
		}
		c.Logger.Success("Removed the reputation provider and active snapshot.")
		return nil
	case "reputation-import":
		document, err := readReputationInput(c.Target, reputation.MaxSnapshotSize)
		if err != nil {
			return err
		}
		authority, found, err := store.Authority()
		if err != nil {
			return err
		}
		if !found {
			return errors.New("configure a reputation provider before importing a snapshot")
		}
		now := reputationClock().UTC().Truncate(time.Second)
		snapshot, err := reputation.Verify(document, authority, now)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(document)
		fingerprint := hex.EncodeToString(digest[:])
		c.reportReputationSnapshot(snapshot, fingerprint)
		confirmed, err := c.confirmReputationFingerprint(fingerprint, "Import exactly this signed reputation snapshot?")
		if err != nil {
			return err
		}
		if reputationEUID() != 0 {
			return reputationEscalate("system", action, c.Target, "--fingerprint", confirmed, "--yes")
		}
		// The privileged process rereads and verifies the path. The digest binds
		// it to the bytes previewed before escalation.
		document, err = readReputationInput(c.Target, reputation.MaxSnapshotSize)
		if err != nil {
			return err
		}
		digest = sha256.Sum256(document)
		if hex.EncodeToString(digest[:]) != confirmed {
			return errors.New("the supplied fingerprint does not match the reputation snapshot being imported")
		}
		imported, err := store.Import(document, now)
		if err != nil {
			return err
		}
		c.Logger.Success("Imported reputation snapshot %d from %s.", imported.Sequence, imported.ProviderID)
		return nil
	case "reputation-status":
		authority, found, err := store.Authority()
		if err != nil {
			return err
		}
		if !found {
			c.Logger.Info("No reputation provider is configured.")
			return nil
		}
		c.reportReputationAuthority(authority)
		snapshot, present, err := store.Current(reputationClock().UTC().Truncate(time.Second))
		if err != nil {
			return err
		}
		if !present {
			c.Logger.Info("No active reputation snapshot is installed.")
			return nil
		}
		c.reportReputationSnapshot(snapshot, "")
		return nil
	case "reputation-check":
		publisherID := strings.TrimSpace(c.Target)
		if !reputation.ValidPublisherID(publisherID) {
			return errors.New("name one exact normalized publisher id")
		}
		result, err := store.Lookup(publisherID, reputationClock().UTC().Truncate(time.Second))
		c.Logger.Info("Provider:     %s", result.ProviderID)
		c.Logger.Info("Publisher:    %s", result.PublisherID)
		c.Logger.Info("Reputation:   %s", result.Status)
		c.Logger.Info("Reason code:  %s", result.ReasonCode)
		if err != nil {
			return fmt.Errorf("reputation is unavailable: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported reputation action %q", action)
	}
}

func (c *SystemCmd) confirmReputationFingerprint(want, prompt string) (string, error) {
	confirmed := strings.TrimSpace(c.Fingerprint)
	if confirmed != "" {
		if confirmed != want {
			return "", errors.New("the supplied fingerprint does not match the previewed reputation material")
		}
		return confirmed, nil
	}
	if c.Yes {
		return "", errors.New("--yes requires --fingerprint with the exact previewed value")
	}
	if !confirmReputation(prompt) {
		return "", errors.New("reputation administration cancelled")
	}
	return want, nil
}

func readReputationAuthority(path string) ([]byte, reputation.Authority, error) {
	document, err := readReputationInput(path, reputation.MaxAuthoritySize)
	if err != nil {
		return nil, reputation.Authority{}, err
	}
	authority, err := reputation.ParseAuthority(document)
	if err != nil {
		return nil, reputation.Authority{}, err
	}
	return document, authority, nil
}

func readReputationInput(path string, limit int) ([]byte, error) {
	if path == "" {
		return nil, errors.New("name a reputation authority or snapshot file")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > int64(limit) {
		return nil, errors.New("reputation input must be one bounded regular file")
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(document) == 0 || len(document) > limit {
		return nil, errors.New("reputation input size is outside the supported range")
	}
	return document, nil
}

func (c *SystemCmd) reportReputationAuthority(authority reputation.Authority) {
	c.Logger.Info("Provider:        %s", authority.ProviderID)
	c.Logger.Info("Provider key:    %s", authority.KeyID)
}

func (c *SystemCmd) reportReputationSnapshot(snapshot reputation.Snapshot, fingerprint string) {
	c.Logger.Info("Provider:        %s", snapshot.ProviderID)
	c.Logger.Info("Sequence:        %d", snapshot.Sequence)
	c.Logger.Info("Issued at:       %s", snapshot.IssuedAt.Format(time.RFC3339))
	c.Logger.Info("Expires at:      %s", snapshot.ExpiresAt.Format(time.RFC3339))
	c.Logger.Info("Entries:         %d", snapshot.EntryCount())
	if fingerprint != "" {
		c.Logger.Info("SHA-256:         %s", fingerprint)
	}
}
