/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mirkobrombin/cpak/pkg/signature"
	"github.com/mirkobrombin/cpak/pkg/tools"
)

var (
	trustRootStore    = signature.DefaultLocalRootStore
	trustRootEUID     = os.Geteuid
	trustRootEscalate = runPrivileged
	confirmTrustRoot  = tools.ConfirmOperation
)

func (c *SystemCmd) manageTrustRoots(action string) error {
	store := trustRootStore()
	purpose := strings.ToLower(strings.TrimSpace(c.Purpose))
	switch action {
	case "trust-root-preview":
		if c.Target == "" {
			return errors.New("name one DER or PEM root certificate to preview")
		}
		preview, err := store.Preview(c.Target)
		if err != nil {
			return err
		}
		c.reportRootPreview(preview, "candidate")
		return nil
	case "trust-root-status":
		trust, err := store.Load()
		if err != nil {
			return err
		}
		for _, fingerprint := range signature.SortedRootFingerprints(trust) {
			root := trust.Roots[fingerprint]
			purposes := make([]string, 0, 2)
			for _, candidate := range []string{signature.RootPurposeCodeSigning, signature.RootPurposeTimestamping} {
				if root.Purposes[candidate] {
					purposes = append(purposes, candidate)
				}
			}
			c.Logger.Info("%s  %s  %s  %s", root.Source, strings.Join(purposes, ","), fingerprint, root.Certificate.Subject.String())
		}
		return nil
	case "trust-root-add":
		if c.Target == "" {
			return errors.New("name one DER or PEM root certificate to import")
		}
		if purpose != signature.RootPurposeCodeSigning && purpose != signature.RootPurposeTimestamping {
			return errors.New("--purpose must be code-signing or timestamping")
		}
		preview, err := store.Preview(c.Target)
		if err != nil {
			return err
		}
		c.reportRootPreview(preview, purpose)
		confirmed := c.Fingerprint
		if confirmed == "" {
			if !c.Yes && !confirmTrustRoot("Import exactly this root for "+purpose+"?") {
				return errors.New("trust-root import cancelled")
			}
			confirmed = preview.Fingerprint
		}
		if confirmed != preview.Fingerprint {
			return errors.New("the supplied fingerprint does not match the root being previewed")
		}
		if trustRootEUID() != 0 {
			return trustRootEscalate("system", "trust-root-add", c.Target, "--purpose", purpose, "--fingerprint", confirmed, "--yes")
		}
		imported, err := store.Import(c.Target, purpose, confirmed)
		if err != nil {
			return err
		}
		c.Logger.Success("Imported %s for %s.", imported.Fingerprint, purpose)
		return nil
	case "trust-root-remove":
		fingerprint := strings.ToLower(strings.TrimSpace(c.Target))
		if fingerprint == "" {
			fingerprint = strings.ToLower(strings.TrimSpace(c.Fingerprint))
		}
		if purpose != signature.RootPurposeCodeSigning && purpose != signature.RootPurposeTimestamping {
			return errors.New("--purpose must be code-signing or timestamping")
		}
		if len(fingerprint) != 64 {
			return errors.New("name the lowercase SHA-256 fingerprint of the local root to remove")
		}
		c.Logger.Warning("Remove local %s root %s.", purpose, fingerprint)
		if !c.Yes && !confirmTrustRoot("Remove exactly this local root?") {
			return errors.New("trust-root removal cancelled")
		}
		if trustRootEUID() != 0 {
			return trustRootEscalate("system", "trust-root-remove", fingerprint, "--purpose", purpose, "--yes")
		}
		if err := store.Remove(purpose, fingerprint); err != nil {
			return err
		}
		c.Logger.Success("Removed %s from %s.", fingerprint, purpose)
		return nil
	default:
		return fmt.Errorf("unsupported trust-root action %q", action)
	}
}

func (c *SystemCmd) reportRootPreview(preview signature.RootPreview, purpose string) {
	c.Logger.Info("Root purpose:    %s", purpose)
	c.Logger.Info("Subject:         %s", preview.Subject)
	c.Logger.Info("SHA-256:         %s", preview.Fingerprint)
	c.Logger.Info("Valid from:      %s", preview.NotBefore)
	c.Logger.Info("Valid until:     %s", preview.NotAfter)
}
