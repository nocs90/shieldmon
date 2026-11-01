package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/export"
)

func (a *app) exportCmd() *cobra.Command {
	var dryRun string
	cmd := &cobra.Command{
		Use:   "export [NAME...]",
		Short: "Send monitoring results to portfolio tools (Dependency-Track, DefectDojo)",
		Long: `Export sends the current state of every monitored target to the exports configured under
'exports' (all, or the NAMEs given): Dependency-Track gets each target's CycloneDX SBOM,
DefectDojo its open and risk-accepted findings, reimported so that findings ShieldMon closed
close there too. Nothing changes in ShieldMon; run it after 'shieldmon monitor'. A failing
export opens an export_failed health finding (docs/adr/0027-exporters.md).`,
		Example: "  shieldmon export\n  shieldmon export defectdojo --dry-run /tmp/payloads",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			exps := a.exports
			if len(args) > 0 {
				exps = slices.DeleteFunc(slices.Clone(exps), func(x export.Instance) bool { return !slices.Contains(args, x.Name) })
				if len(exps) != len(args) {
					return fmt.Errorf("unknown export in %v (configured: %s)", args, exportNames(a.exports))
				}
			}
			if len(exps) == 0 {
				return errors.New("no export configured (exports: in the configuration; docs/processes/exports.md)")
			}
			b, err := a.engine.ExportBatch(cmd.Context(), "shieldmon "+Version)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if dryRun != "" {
				return writePayloads(cmd, exps, b, dryRun)
			}
			results, err := a.engine.Export(cmd.Context(), exps, b)
			failed := 0
			for _, x := range exps {
				r := results[x.Name]
				fmt.Fprintf(w, "%s (%s): %d of %d target(s) sent\n", x.Name, x.Exporter, r.Sent, len(b.Targets))
				refs := make([]string, 0, len(r.Failed))
				for ref := range r.Failed {
					refs = append(refs, ref)
				}
				sort.Strings(refs)
				for _, ref := range refs {
					fmt.Fprintf(w, "  %s: %s\n", printable(ref), printable(r.Failed[ref]))
				}
				failed += len(r.Failed)
			}
			if err != nil {
				return err
			}
			if failed > 0 {
				return fmt.Errorf("%d target export(s) failed (see 'shieldmon health')", failed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dryRun, "dry-run", "", "write what would be sent to this directory (0700, files 0600) instead of sending it")
	return cmd
}

func writePayloads(cmd *cobra.Command, exps []export.Instance, b export.Batch, dir string) error {
	for _, x := range exps {
		p, ok := x.Sender.(export.Payloader)
		if !ok {
			return fmt.Errorf("export %s cannot show its payloads", x.Name)
		}
		docs, err := p.Payloads(b)
		if err != nil {
			return err
		}
		sub := filepath.Join(dir, x.Name)
		if err := os.MkdirAll(sub, 0o700); err != nil {
			return err
		}
		names := make([]string, 0, len(docs))
		for n := range docs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(sub, n), docs[n], 0o600); err != nil {
				return err
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s (%s): %d payload(s) in %s\n", x.Name, x.Exporter, len(names), sub)
	}
	return nil
}

func exportNames(exps []export.Instance) string {
	if len(exps) == 0 {
		return "none"
	}
	var out []string
	for _, x := range exps {
		out = append(out, x.Name)
	}
	return fmt.Sprint(out)
}
