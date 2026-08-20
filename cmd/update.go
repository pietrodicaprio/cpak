/*
 * Copyright (c) 2025 Fabricators and Mirko Brombin <brombin94@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/mirkobrombin/cpak/pkg/applicationtrust"
	"github.com/mirkobrombin/cpak/pkg/cpak"
	"github.com/mirkobrombin/cpak/pkg/desktopui"
	"github.com/mirkobrombin/cpak/pkg/logger"
	"github.com/mirkobrombin/cpak/pkg/tools"
	"github.com/mirkobrombin/cpak/pkg/types"
	"github.com/mirkobrombin/go-cli-builder/v3/pkg/cli"
	"golang.org/x/term"
)

type UpdateCmd struct {
	Remote         string `arg:"remote" help:"Remote Git repository, all the installed cpak(s) if omitted"`
	JSON           bool   `cli:"json,j" help:"Print output in JSON format"`
	NonInteractive bool   `cli:"non-interactive,n" help:"Reject updates that request additional permissions"`
	Graphical      bool   `cli:"graphical" help:"Use the configured desktop frontend for publisher-reputation confirmation"`
	Verbose        bool   `cli:"verbose,v" help:"Report every cpak, not only the ones that need attention"`

	cli.Base
}

type updateMachineOutput struct {
	SchemaVersion int                       `json:"schema_version"`
	Updates       []types.UpdateResult      `json:"updates"`
	Trust         []applicationtrust.Result `json:"trust"`
}

func (c *UpdateCmd) Run() error {
	if c.JSON {
		logger.MachineMode()
	}
	cp, err := cpak.NewCpak()
	if err != nil {
		return fmt.Errorf("an error occurred while updating cpak(s): %s", err)
	}
	remote := ""
	if c.Remote != "" {
		remote, err = resolveApplicationOrigin(cp, c.Remote)
		if err != nil {
			return fmt.Errorf("an error occurred while updating cpak(s): %s", err)
		}
	}

	if !c.JSON {
		c.announceUpdate(cp, remote)
	}

	context := c.invocationContext()
	enrolments := []cpak.ApplicationEnrolment{}
	options := cpak.UpdateOptions{
		ConfirmPermissions: func(requests []types.UpdateResult) bool {
			if context != applicationtrust.ContextInteractiveTerminal {
				return false
			}
			c.Logger.Info("The following updates request additional permissions:")
			data := make([][]string, 0, len(requests))
			for _, result := range requests {
				data = append(data, []string{result.Name, result.Origin, strings.Join(result.PermissionAdditions, ", ")})
			}
			tools.ShowTable([]string{"Name", "Origin", "Additional permissions"}, data)
			return tools.ConfirmOperation("Approve these permissions and continue?")
		},
		OnEnrolment: func(result cpak.ApplicationEnrolment) {
			enrolments = append(enrolments, result)
		},
	}
	if context == applicationtrust.ContextInteractiveTerminal {
		options.Enrolment.ConfirmReputation = c.confirmReputation
	} else if context == applicationtrust.ContextGraphical {
		options.Enrolment.ConfirmReputation = c.confirmGraphicalReputation
	}
	results, err := cp.UpdateWithOptions(remote, options)
	if err != nil {
		return fmt.Errorf("an error occurred while updating cpak(s): %s", err)
	}
	trustResults, err := applicationTrustResults(applicationtrust.OperationUpdate, context, enrolments)
	if err != nil {
		return err
	}

	if c.JSON {
		jsonBytes, err := json.MarshalIndent(updateMachineOutput{
			SchemaVersion: applicationtrust.SchemaVersion,
			Updates:       results,
			Trust:         trustResults,
		}, "", "  ")
		if err != nil {
			return fmt.Errorf("an error occurred while updating cpak(s): %s", err)
		}
		fmt.Println(string(jsonBytes))
		if err := updateFailures(results); err != nil {
			return err
		}
		return applicationTrustResultExit(trustResults)
	}

	if len(results) == 0 {
		c.Logger.Info("No cpak installed, nothing to update")
		return nil
	}

	c.Logger.Info("%s", summarizeUpdates(results))
	c.showUpdateResults(results)
	reportApplicationTrustResults(c.Logger, trustResults)

	if err := updateFailures(results); err != nil {
		return err
	}
	return applicationTrustResultExit(trustResults)
}

func (c *UpdateCmd) invocationContext() applicationtrust.InvocationContext {
	if c.NonInteractive || c.JSON {
		return applicationtrust.ContextNonInteractive
	}
	if c.Graphical {
		return applicationtrust.ContextGraphical
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return applicationtrust.ContextNonInteractive
	}
	return applicationtrust.ContextInteractiveTerminal
}

func (c *UpdateCmd) confirmGraphicalReputation(warning cpak.ReputationWarning) applicationtrust.ConfirmationResponse {
	accepted, err := desktopui.ConfirmPublisherReputation(context.Background(), desktopui.SelectBackend(""), desktopui.ReputationPrompt{
		Origin: warning.Origin, PublisherName: warning.PublisherName, PublisherID: warning.PublisherID,
		ProviderID: warning.ProviderID, Status: string(warning.Status), ProviderReason: warning.ProviderReason,
		PolicyReason: warning.PolicyReason,
	})
	if err != nil {
		c.Logger.Warning("Publisher reputation confirmation is unavailable; the update remains unenrolled.")
		return applicationtrust.NoConfirmation
	}
	if accepted {
		c.Logger.Info("Checking publisher reputation again")
		return applicationtrust.Confirm
	}
	return applicationtrust.Decline
}

func (c *UpdateCmd) confirmReputation(warning cpak.ReputationWarning) applicationtrust.ConfirmationResponse {
	c.Logger.Warning("Publisher reputation requires confirmation for %s: publisher %s, identity %s, provider %s, status %s, provider reason %s, host policy %s.",
		tools.SanitizeForDisplay(warning.Origin), tools.SanitizeForDisplay(warning.PublisherName), tools.SanitizeForDisplay(warning.PublisherID),
		tools.SanitizeForDisplay(warning.ProviderID), warning.Status, tools.SanitizeForDisplay(warning.ProviderReason), tools.SanitizeForDisplay(warning.PolicyReason))
	if tools.ConfirmOperation("Continue and enrol this update? This does not create a permanent publisher exception.") {
		return applicationtrust.Confirm
	}
	return applicationtrust.Decline
}

// announceUpdate says what the command is about to do, because resolving every
// installed application takes long enough that silence reads as a hang.
func (c *UpdateCmd) announceUpdate(cp cpak.Cpak, remote string) {
	if remote != "" {
		c.Logger.Info("Checking %s for updates..", remote)
		return
	}
	apps, err := cp.GetInstalledApps()
	if err != nil {
		c.Logger.Info("Checking the installed cpak(s) for updates, this can take a while..")
		return
	}
	c.Logger.Info("Checking %d cpak(s) for updates, this can take a while..", len(apps))
}

// showUpdateResults prints the table. By default only what needs attention is
// listed, because the count already reports what went well and forty rows of
// "updated" bury the one row that did not.
func (c *UpdateCmd) showUpdateResults(results []types.UpdateResult) {
	if c.Verbose {
		header := []string{"Name", "Origin", "Source", "Status", "From", "To", "Permissions", "Details"}
		tools.ShowTable(header, verboseUpdateRows(results))
		return
	}

	rows := attentionUpdateRows(results)
	if len(rows) == 0 {
		return
	}
	tools.ShowTable([]string{"Name", "Origin", "Status", "Details"}, rows)
}

func verboseUpdateRows(results []types.UpdateResult) [][]string {
	rows := make([][]string, 0, len(results))
	for _, result := range results {
		from, to := updateVersions(result)
		rows = append(rows, []string{
			result.Name,
			result.Origin,
			result.SourceType,
			string(result.Status),
			from,
			to,
			strings.Join(result.PermissionAdditions, ", "),
			tools.SanitizeForDisplay(shortenDigests(result.Reason)),
		})
	}
	return rows
}

func attentionUpdateRows(results []types.UpdateResult) [][]string {
	rows := [][]string{}
	for _, result := range results {
		if updateSucceeded(result) {
			continue
		}
		rows = append(rows, []string{
			result.Name,
			result.Origin,
			string(result.Status),
			tools.SanitizeForDisplay(shortenDigests(result.Reason)),
		})
	}
	return rows
}

// updateVersions is what the From and To columns carry. An update that did not
// move the version leaves From empty, so that the column drops out of the
// table instead of printing the same value twice on every row.
func updateVersions(result types.UpdateResult) (from, to string) {
	from = shortenDigests(result.OldVersion)
	to = shortenDigests(result.NewVersion)
	if from == to {
		from = ""
	}
	return from, to
}

// updateSucceeded reports whether the application needs nothing from the
// operator: it moved, or it was already where it should be.
func updateSucceeded(result types.UpdateResult) bool {
	return result.Status == types.UpdateStatusUpdated || result.Status == types.UpdateStatusUpToDate
}

// updateStatusOrder reads the summary from what moved to what went wrong.
var updateStatusOrder = []types.UpdateStatus{
	types.UpdateStatusUpdated,
	types.UpdateStatusUpToDate,
	types.UpdateStatusPinned,
	types.UpdateStatusUnsupported,
	types.UpdateStatusPermissionDenied,
	types.UpdateStatusFailed,
}

// summarizeUpdates is the line the default output leads with, so that a run
// over forty applications reports what happened without forty rows.
func summarizeUpdates(results []types.UpdateResult) string {
	counts := map[types.UpdateStatus]int{}
	seen := []types.UpdateStatus{}
	for _, result := range results {
		if _, known := counts[result.Status]; !known {
			seen = append(seen, result.Status)
		}
		counts[result.Status]++
	}
	slices.SortStableFunc(seen, func(a, b types.UpdateStatus) int {
		return updateStatusRank(a) - updateStatusRank(b)
	})

	parts := make([]string, 0, len(seen))
	for _, status := range seen {
		parts = append(parts, fmt.Sprintf("%d %s", counts[status], status))
	}
	if len(parts) == 0 {
		return "Checked 0 cpak(s)"
	}
	return fmt.Sprintf("Checked %d cpak(s): %s", len(results), strings.Join(parts, ", "))
}

// updateStatusRank keeps an outcome the order does not list at the end of the
// summary rather than dropping it.
func updateStatusRank(status types.UpdateStatus) int {
	if rank := slices.Index(updateStatusOrder, status); rank >= 0 {
		return rank
	}
	return len(updateStatusOrder)
}

// digestPattern matches an OCI digest, with or without its algorithm.
var digestPattern = regexp.MustCompile(`(?i)\b(sha256:)?[0-9a-f]{32,}\b`)

// shortenDigests cuts every digest down to the prefix a person compares, since
// the remaining fifty characters cost a column and say nothing more.
func shortenDigests(text string) string {
	return digestPattern.ReplaceAllStringFunc(text, func(digest string) string {
		algorithm := ""
		if separator := strings.IndexByte(digest, ':'); separator >= 0 {
			algorithm = digest[:separator+1]
			digest = digest[separator+1:]
		}
		return algorithm + digest[:12] + ".."
	})
}

// updateFailures returns an error when at least one application could not be
// updated, so that the command exits with a failure.
func updateFailures(results []types.UpdateResult) error {
	failed := []string{}
	for _, result := range results {
		if result.Status == types.UpdateStatusFailed || result.Status == types.UpdateStatusPermissionDenied {
			failed = append(failed, result.Origin)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return fmt.Errorf("failed to update: %s", strings.Join(failed, ", "))
}
