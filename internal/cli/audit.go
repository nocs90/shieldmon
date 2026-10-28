package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/store"
)

// maxDigestBytes bounds a digest file read by audit verify.
const maxDigestBytes = 64 << 10

// auditCmd verifies the tamper-evident audit chain (docs/adr/0018-audit-chain.md).
func (a *app) auditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Tamper-evident audit trail: export digests, verify the chain"}
	cmd.AddCommand(a.auditDigestCmd(), a.auditVerifyCmd())
	return cmd
}

func (a *app) auditDigestCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "digest",
		Short: "Print the head of the audit chain, to store outside this machine",
		Long: `Seal pending audit rows and print the head of the audit chain (sequence and hash) as JSON.
Store it where whoever controls this machine cannot change it (object storage with a
retention lock, a ticket, a signed report): 'shieldmon audit verify --digest FILE' later
proves the audit trail was not rewritten since.`,
		Example: "  shieldmon audit digest -o digests/$(date +%F).json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			if err := a.store.SealAudit(cmd.Context()); err != nil {
				return err
			}
			d, err := a.store.AuditHead(cmd.Context())
			if err != nil {
				return err
			}
			b, err := json.MarshalIndent(d, "", "  ")
			if err != nil {
				return err
			}
			b = append(b, '\n')
			if out == "" || out == "-" {
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			return os.WriteFile(out, b, 0o600)
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "file to write (default stdout)")
	return cmd
}

func (a *app) auditVerifyCmd() *cobra.Command {
	var files []string
	var format string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit chain, and that exported digests are still in it",
		Long: `Recompute every audited row and every link of the audit chain, look for rows inserted out
of band, and check that each digest given (exported earlier with 'audit digest' or read from
a report) is still in the chain. Exits 1 on any problem and keeps the audit_chain_broken
health finding in step. Without digests, a rewrite of the whole chain cannot be told apart
from the original: export digests regularly.`,
		Example: "  shieldmon audit verify --digest digests/2026-10-01.json --digest digests/2026-10-28.json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			digests := make([]store.AuditDigest, 0, len(files))
			for _, f := range files {
				d, err := readDigest(cmd, f)
				if err != nil {
					return err
				}
				digests = append(digests, d)
			}
			if err := a.setup(cmd); err != nil {
				return err
			}
			r, err := a.engine.VerifyAudit(cmd.Context(), digests)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if format == "json" {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				if err := enc.Encode(r); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(w, "audit chain: %d entries, head %d %s\n", r.Entries, r.Head.Seq, r.Head.Hash)
				fmt.Fprintf(w, "digests checked: %d\n", r.Digests)
				for _, tbl := range slices.Sorted(maps.Keys(r.Pending)) {
					fmt.Fprintf(w, "pending (written, not sealed yet): %s %d\n", tbl, r.Pending[tbl])
				}
				for _, p := range r.Problems {
					fmt.Fprintf(w, "PROBLEM %s entry %d %s %s %s\n", p.Kind, p.Seq, p.Table, printable(p.Key), printable(p.Detail))
				}
				if r.Count > len(r.Problems) {
					fmt.Fprintf(w, "… %d more problem(s)\n", r.Count-len(r.Problems))
				}
			}
			if !r.OK() {
				return fmt.Errorf("the audit trail does not verify: %d problem(s)", r.Count)
			}
			if format != "json" {
				fmt.Fprintln(w, "OK")
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&files, "digest", nil, "digest file exported earlier (repeatable)")
	cmd.Flags().StringVarP(&format, "output", "o", "text", "output format: text, json")
	return cmd
}

// readDigest reads a digest file, refusing anything but a well-formed digest.
func readDigest(cmd *cobra.Command, path string) (store.AuditDigest, error) {
	var d store.AuditDigest
	data, err := readBounded(cmd.InOrStdin(), path, maxDigestBytes)
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return d, fmt.Errorf("%s: not a digest: %w", path, err)
	}
	if b, err := hex.DecodeString(d.Hash); d.Format != store.DigestFormat || d.Seq < 1 || err != nil || len(b) != 32 {
		return d, fmt.Errorf("%s: not a %s document", path, store.DigestFormat)
	}
	return d, nil
}
