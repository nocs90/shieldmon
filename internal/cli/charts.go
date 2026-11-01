package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/charts"
	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/redact"
)

// chartOCI gives chart sources registry access through internal/oci, where registry
// credentials stay (docs/adr/0032-chart-sources.md).
type chartOCI struct{ a *app }

func (c chartOCI) Tags(ctx context.Context, repository string, limit int) ([]string, error) {
	repo, err := name.NewRepository(repository)
	if err != nil {
		return nil, err
	}
	p, err := c.a.registries.For(repo.RegistryStr())
	if err != nil {
		return nil, err
	}
	tags, err := p.Tags(ctx, repo, limit)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		out = append(out, t.Name)
	}
	return out, nil
}

func (c chartOCI) Fetch(ctx context.Context, ref string, maxBytes int64, w io.Writer) (string, error) {
	return oci.FetchChart(ctx, ref, maxBytes, w, c.a.ociOptions())
}

// chartSource builds the source of a configured chart.
func (a *app) chartSource(c config.Chart) (charts.Source, error) {
	src, err := charts.New(c.Source, charts.Spec{Options: charts.Options(c.Options), OCI: chartOCI{a}})
	if err != nil {
		return nil, fmt.Errorf("charts %s: %w", c.ID(), err)
	}
	return src, nil
}

// configuredChart finds a chart of the configuration by its name.
func (a *app) configuredChart(id string) (config.Chart, error) {
	for _, c := range a.cfg.Charts {
		if c.ID() == id {
			return c, nil
		}
	}
	return config.Chart{}, fmt.Errorf("no chart %q in the configuration (charts:)", id)
}

// fetchChart downloads and checks one version of a chart; with version "" the newest that is
// not a pre-release.
func (a *app) fetchChart(ctx context.Context, c config.Chart, version string) ([]byte, string, charts.Meta, error) {
	src, err := a.chartSource(c)
	if err != nil {
		return nil, "", charts.Meta{}, err
	}
	if version == "" {
		vs, err := src.Versions(ctx, c.Chart)
		if err != nil {
			return nil, "", charts.Meta{}, err
		}
		if version = charts.Newest(vs); version == "" {
			return nil, "", charts.Meta{}, fmt.Errorf("%s: no released version", c.ID())
		}
	}
	var buf bytes.Buffer
	digest, err := src.Fetch(ctx, c.Chart, version, &buf)
	if err != nil {
		return nil, "", charts.Meta{}, err
	}
	meta, err := charts.CheckArchive(buf.Bytes(), c.Chart, version)
	if err != nil {
		return nil, "", charts.Meta{}, fmt.Errorf("%s %s: %w", c.ID(), version, err)
	}
	return buf.Bytes(), digest, meta, nil
}

// chartErr makes an error from a chart source fit for the terminal: sources and registries
// answer with hostile text, and registry errors may carry presigned URLs.
func chartErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(printable(redact.Error(err)))
}

func (a *app) chartsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "charts", Short: "Helm charts followed: their sources, versions and archives"}
	list := &cobra.Command{
		Use:   "list",
		Short: "List the configured charts and where they come from",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSOURCE\tLOCATION")
			for _, c := range a.cfg.Charts {
				src, err := a.chartSource(c)
				if err != nil {
					return err
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", c.ID(), c.Source, printable(src.Location(c.Chart)))
			}
			return tw.Flush()
		},
	}
	var limit int
	versions := &cobra.Command{
		Use:   "versions NAME",
		Short: "List a chart's versions, newest first",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			c, err := a.configuredChart(args[0])
			if err != nil {
				return err
			}
			src, err := a.chartSource(c)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()
			vs, err := src.Versions(ctx, c.Chart)
			if err != nil {
				return chartErr(err)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "VERSION\tAPP VERSION\tCREATED\tNOTE")
			for i, v := range vs {
				if limit > 0 && i == limit {
					break
				}
				created, note := "-", ""
				if !v.Created.IsZero() {
					created = v.Created.Format(time.DateOnly)
				}
				if v.Deprecated {
					note = "deprecated"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", printable(v.Version), orDash(printable(v.AppVersion)), created, note)
			}
			return tw.Flush()
		},
	}
	versions.Flags().IntVar(&limit, "limit", 20, "show at most this many (0: all)")
	var version, out string
	fetch := &cobra.Command{
		Use:   "fetch NAME",
		Short: "Download and check a chart's archive (default: the newest release)",
		Long: `Download one version of a chart and check its archive as ShieldMon does before rendering
it: regular files only, no path leaving the chart, bounded size and entries, a Chart.yaml
naming the chart and version asked for. Nothing in it is run.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				return errors.New("--out FILE is required")
			}
			if err := a.setup(cmd); err != nil {
				return err
			}
			c, err := a.configuredChart(args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()
			data, digest, meta, err := a.fetchChart(ctx, c, version)
			if err != nil {
				return chartErr(err)
			}
			if err := os.WriteFile(out, data, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s (app %s) -> %s, %s\n", printable(meta.Name), printable(meta.Version), orDash(printable(meta.AppVersion)), out, digest)
			return nil
		},
	}
	fetch.Flags().StringVar(&version, "version", "", "chart version (default: the newest release)")
	fetch.Flags().StringVar(&out, "out", "", "file to write the archive to")
	cmd.AddCommand(list, versions, fetch)
	return cmd
}
