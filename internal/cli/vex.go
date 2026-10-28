package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/store"
	"github.com/nocs90/shieldmon/internal/vex"
)

// vexCmd imports and exports VEX (docs/adr/0014-vex.md).
func (a *app) vexCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "vex", Short: "Import and export VEX statements (OpenVEX, CycloneDX VEX)"}
	cmd.AddCommand(a.vexImportCmd(), a.vexExportCmd())
	return cmd
}

func (a *app) vexImportCmd() *cobra.Command {
	var author, by string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "import FILE",
		Short: "Record not_affected statements from an OpenVEX or CycloneDX VEX document",
		Long: `Record the not_affected statements of an OpenVEX or CycloneDX VEX document ("-" for
stdin). Each is scoped to an image digest or a whole repository, optionally to one package,
and becomes a not_affected decision on matching findings: now, and on findings later scans
detect. Statements without an author (the document's, or --author) or a justification, and
expired ones, are skipped and listed; so are statuses other than not_affected. Statements
for images never scanned are kept and apply once they are.`,
		Example: "  shieldmon vex import vendor.openvex.json\n  shieldmon vex import --author \"App Team\" app.cdx.json --dry-run",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if by == "" {
				return errors.New("--by is required (who imports; default from $SHIELDMON_ACTOR or $USER)")
			}
			data, err := readBounded(cmd.InOrStdin(), args[0], vex.MaxDocumentBytes)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			stmts, skipped, err := vex.Parse(data, author, now)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			for _, s := range skipped {
				fmt.Fprintf(w, "skipped %s: %s\n", printable(s.VulnID), printable(s.Reason))
			}
			if dryRun {
				for _, s := range stmts {
					fmt.Fprintf(w, "would record %s not_affected in %s%s (%s)\n", s.VulnID, productLabel(s), pkgLabel(s), printable(s.Author))
				}
				fmt.Fprintf(w, "%d statement(s) would be recorded, %d skipped\n", len(stmts), len(skipped))
				return nil
			}
			if err := a.setup(cmd); err != nil {
				return err
			}
			unlock, err := a.lock()
			if err != nil {
				return err
			}
			defer unlock()
			added, err := a.store.AddVEXStatements(cmd.Context(), stmts, by, now)
			if err != nil {
				return err
			}
			applied, err := a.store.ApplyVEX(cmd.Context(), "", a.engine.Decisions, now)
			if err != nil {
				return err
			}
			unknown, err := a.store.VEXUnknownProducts(cmd.Context(), now)
			if err != nil {
				return err
			}
			for _, s := range unknown {
				fmt.Fprintf(w, "kept, not scanned yet: %s in %s%s\n", s.VulnID, productLabel(s.Statement), pkgLabel(s.Statement))
			}
			fmt.Fprintf(w, "%d statement(s) read, %d new, %d skipped; %d finding(s) now not_affected\n",
				len(stmts), added, len(skipped), len(applied))
			return nil
		},
	}
	cmd.Flags().StringVar(&author, "author", "", "author of statements whose document names none")
	cmd.Flags().StringVar(&by, "by", engine.ActorFromEnv(), "who imports (recorded with each statement)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be recorded, record nothing")
	return cmd
}

func (a *app) vexExportCmd() *cobra.Command {
	var out, author string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the statements in force and manual not_affected decisions as OpenVEX",
		Long: `Write one OpenVEX 0.2.0 document with the VEX statements in force and the not_affected
decisions taken by hand. Risk acceptances are not exported: they say "affected, accepted",
which a VEX consumer must not read as not_affected. Importing the document gives back the
same statements.`,
		Example: "  shieldmon vex export --author \"Platform Security <sec@example.com>\" -o shieldmon.openvex.json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if author == "" {
				return errors.New("--author is required (the document's author)")
			}
			if err := a.setup(cmd); err != nil {
				return err
			}
			now := time.Now().UTC()
			stored, err := a.store.VEXStatements(cmd.Context(), now)
			if err != nil {
				return err
			}
			manual, err := a.store.ManualNotAffected(cmd.Context(), now)
			if err != nil {
				return err
			}
			seen := map[string]bool{}
			var stmts []vex.Statement
			for _, s := range append(statements(stored), manual...) {
				if !seen[s.Key()] {
					seen[s.Key()] = true
					stmts = append(stmts, s)
				}
			}
			doc, err := vex.OpenVEX(vex.Document{Author: author, Tooling: "shieldmon " + Version, Timestamp: now, Statements: stmts})
			if err != nil {
				return err
			}
			doc = append(doc, '\n')
			if out == "" || out == "-" {
				_, err = cmd.OutOrStdout().Write(doc)
				return err
			}
			if err := os.WriteFile(out, doc, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote %d statement(s) to %s\n", len(stmts), out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "file to write (default stdout)")
	cmd.Flags().StringVar(&author, "author", engine.ActorFromEnv(), "the document's author")
	return cmd
}

// statements returns the statement part of stored statements.
func statements(stored []store.VEXStatement) []vex.Statement {
	out := make([]vex.Statement, 0, len(stored))
	for _, s := range stored {
		out = append(out, s.Statement)
	}
	return out
}

// readBounded reads path ("-" for stdin), refusing more than limit bytes.
func readBounded(stdin io.Reader, path string, limit int64) ([]byte, error) {
	r := stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return data, nil
}

func productLabel(s vex.Statement) string {
	if s.Digest != "" {
		return printable(s.Repository + "@" + s.Digest)
	}
	return printable(s.Repository) + " (every digest)"
}

func pkgLabel(s vex.Statement) string {
	switch {
	case s.PURL == "":
		return ""
	case s.AnyVersion:
		return ", " + printable(s.PURL) + " (every version)"
	}
	return ", " + printable(s.PURL)
}
