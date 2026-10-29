package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/gate"
)

// exitStatus ends a command with this status and no error message (the command has
// printed its outcome).
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func (a *app) gateCmd() *cobra.Command {
	var platform, policyFile, format, out string
	var noScan bool
	cmd := &cobra.Command{
		Use:   "gate IMAGE",
		Short: "Pass, warn or fail an image on policy, for CI (exit 0 pass/warn, 2 fail, 3 indeterminate, 1 error)",
		Long: `Gate scans the image (as 'shieldmon scan' does) and evaluates the findings of its digest
against the gate policy: the 'gate' section of the configuration, or --policy FILE with the
same schema. A finding is flagged by the strongest action (fail, warn) of the rules it
matches. Findings are exempt only by a decision in force (accept-risk, not-affected, VEX
statements); expired decisions exempt nothing.

The verdict fails closed: with no violation, it is indeterminate when the scan is not
complete, a vulnerability DB is older than max_db_age, or (--no-scan) the stored evidence
is older than max_evidence_age. Exit codes are configurable (gate.exit_codes); errors exit 1.
See docs/processes/ci-gate.md and docs/adr/0021-policy-gate.md.`,
		Example: `  shieldmon gate registry.example.com/app@sha256:…
  shieldmon gate --policy ci/gate-policy.yaml -o sarif --out gate.sarif registry.example.com/app:1.4.2
  shieldmon gate --no-scan registry.example.com/app:prod    # stored evidence, no registry or scanner`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "table" && format != "json" && format != "sarif" {
				return fmt.Errorf("--output %q: want table, json or sarif", format)
			}
			if err := a.setup(cmd); err != nil {
				return err
			}
			policy, source := a.cfg.Gate, "configuration"
			if policyFile != "" {
				var err error
				if policy, err = config.LoadGate(policyFile); err != nil {
					return err
				}
				source = policyFile
			}
			ctx := cmd.Context()
			var digest string
			var scanID int64
			if noScan {
				var err error
				if digest, err = a.resolveDigest(ctx, args[0]); err != nil {
					return err
				}
			} else {
				p, err := a.platform(platform)
				if err != nil {
					return err
				}
				unlock, err := a.lock()
				if err != nil {
					return err
				}
				defer unlock()
				a.preflight(cmd)
				res, err := a.engine.Scan(ctx, args[0], p)
				if err != nil {
					return err
				}
				digest, scanID = res.Resolved.Digest, res.ScanID
			}
			r, err := a.engine.GateDigest(ctx, args[0], digest, policy, source, scanID)
			if err != nil {
				return err
			}
			if err := writeGate(cmd, r, format, out); err != nil {
				return err
			}
			if r.ExitCode != 0 {
				return exitStatus(r.ExitCode)
			}
			return nil
		},
	}
	a.platformFlag(cmd, &platform)
	cmd.Flags().StringVar(&policyFile, "policy", "", "policy file (default: the gate section of the configuration)")
	cmd.Flags().BoolVar(&noScan, "no-scan", false, "evaluate the stored evidence of an image already scanned (target ID, reference or digest prefix)")
	cmd.Flags().StringVarP(&format, "output", "o", "table", "output format: table, json, sarif")
	cmd.Flags().StringVar(&out, "out", "", "write the output to this file (0600) and a summary to stdout")
	return cmd
}

func writeGate(cmd *cobra.Command, r gate.Result, format, out string) error {
	if out == "" && format != "table" {
		return renderGate(cmd.OutOrStdout(), r, format)
	}
	if out != "" {
		w, closeOut, err := reportOutput(cmd, out)
		if err != nil {
			return err
		}
		err = renderGate(w, r, format)
		if cerr := closeOut(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return gateTable(cmd.OutOrStdout(), r)
}

func renderGate(w io.Writer, r gate.Result, format string) error {
	switch format {
	case "json":
		return gate.WriteJSON(w, r)
	case "sarif":
		return gate.WriteSARIF(w, r)
	}
	return gateTable(w, r)
}

func gateTable(w io.Writer, r gate.Result) error {
	fmt.Fprintf(w, "gate %s: %s (%s)\n", strings.ToUpper(string(r.Verdict)), printable(r.Image), r.Digest)
	fmt.Fprintf(w, "policy: %s\n", printable(r.Policy))
	if ev := r.Evidence; ev != nil {
		fmt.Fprintf(w, "evidence: scan #%d %s, finished %s%s\n", ev.ScanID, ev.Status, ev.FinishedAt.Format(time.RFC3339), toolsLine(ev))
	}
	for _, u := range r.Unproven {
		fmt.Fprintf(w, "unproven: %s\n", printable(u))
	}
	if len(r.Flagged) > 0 {
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ACTION\tRULES\tID\tPRIORITY\tSEVERITY\tVULNERABILITY\tPACKAGE\tVERSION\tFIX")
		for _, f := range r.Flagged {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n", f.Action, strings.Join(f.Rules, ","), f.ID, f.Priority,
				f.Severity, printable(f.VulnID), printable(f.Package), printable(f.Version), printable(strings.Join(f.FixVersions, ", ")))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	for _, x := range r.Exempt {
		d := x.Decision
		until := ""
		if !d.ExpiresAt.IsZero() {
			until = " until " + d.ExpiresAt.Format(time.DateOnly)
		}
		fmt.Fprintf(w, "exempt: #%d %s %s, %s by %s%s: %s\n", x.ID, printable(x.VulnID), printable(x.Package), d.State,
			printable(d.Author), until, printable(oneLineText(d.Justification)))
	}
	fails := 0
	for _, f := range r.Flagged {
		if f.Action == config.GateFail {
			fails++
		}
	}
	_, err := fmt.Fprintf(w, "\n%d fail, %d warn, %d exempt, %d not flagged; exit status %d\n",
		fails, len(r.Flagged)-fails, len(r.Exempt), r.Unflagged, r.ExitCode)
	return err
}

func toolsLine(ev *gate.Evidence) string {
	var parts []string
	for _, t := range ev.Tools {
		s := printable(t.Name + " " + t.Version)
		if !t.DBBuilt.IsZero() {
			s += " (DB " + t.DBBuilt.Format(time.DateOnly) + ")"
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return ""
	}
	return "; " + strings.Join(parts, ", ")
}

func oneLineText(s string) string { return strings.Join(strings.Fields(s), " ") }
