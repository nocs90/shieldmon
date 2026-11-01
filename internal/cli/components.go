package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/sbom"
	"github.com/nocs90/shieldmon/internal/store"
)

// componentsCmd answers what the monitored images contain (#70).
func (a *app) componentsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "components", Short: "Components of the monitored images, from their stored SBOMs"}
	cmd.AddCommand(a.componentsListCmd(), a.componentsWhereCmd())
	return cmd
}

func (a *app) componentsListCmd() *cobra.Command {
	var target, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the components of the images' current digests, with the images containing each",
		Long: `List the components (packages) of every monitored image's current digest, read from the
CycloneDX SBOMs stored at scan time (checked against their recorded SHA-256), merged across
generators and deduplicated by package URL.`,
		Example: "  shieldmon components list --target registry.example.com/app:prod\n  shieldmon components list -o csv > components.csv",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ci, err := a.components(cmd, target)
			if err != nil {
				return err
			}
			return writeComponents(cmd, ci, format)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "only images whose reference is this (all platforms)")
	cmd.Flags().StringVarP(&format, "output", "o", "table", "output format: table, csv, json")
	return cmd
}

func (a *app) componentsWhereCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "where NAME[@VERSION]|PURL",
		Short: "Which monitored images contain a package (exit status 1 when none does)",
		Long: `Find the monitored images whose current digest contains a package: by package URL (exact,
or every version when the PURL has none), by NAME@VERSION, or by NAME (case-insensitive;
GROUP/NAME for grouped components such as Maven).`,
		Example: "  shieldmon components where xz-libs@5.6.0\n  shieldmon components where pkg:apk/alpine/openssl\n  shieldmon components where log4j-core -o json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ci, err := a.components(cmd, "")
			if err != nil {
				return err
			}
			found := ci.Filter(args[0])
			if len(found.Components) == 0 {
				for _, p := range ci.Problems {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", printable(p))
				}
				return fmt.Errorf("no monitored image contains %s", printable(args[0]))
			}
			return writeComponents(cmd, found, format)
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "table", "output format: table, csv, json")
	return cmd
}

func (a *app) components(cmd *cobra.Command, target string) (report.ComponentInventory, error) {
	if err := a.setup(cmd); err != nil {
		return report.ComponentInventory{}, err
	}
	var keep func(store.Target) bool
	if target != "" {
		keep = func(t store.Target) bool { return t.Ref == target }
	}
	read := func(b store.SBOM) ([]byte, error) { return a.engine.ReadSBOM(b, sbom.MaxBytes) }
	return report.BuildComponents(cmd.Context(), a.store, read, keep, time.Now())
}

func writeComponents(cmd *cobra.Command, ci report.ComponentInventory, format string) error {
	w := cmd.OutOrStdout()
	if format != "table" {
		return report.RenderComponents(w, ci, format)
	}
	for _, p := range ci.Problems {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", printable(p))
	}
	return componentTable(w, ci)
}

func componentTable(w io.Writer, ci report.ComponentInventory) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tVERSION\tTYPE\tPURL\tIMAGES")
	for _, c := range ci.Components {
		name := c.Name
		if c.Group != "" {
			name = c.Group + "/" + c.Name
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", printable(name), printable(c.Version), printable(c.Type), printable(c.PURL),
			printable(strings.Join(c.Images, ", ")))
	}
	return tw.Flush()
}
