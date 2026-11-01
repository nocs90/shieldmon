package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/nocs90/shieldmon/internal/charts"
	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/manifests"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/scanner"
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

// chartRenderer renders charts with the configured helm, in the scanners' sandbox
// (docs/adr/0033-chart-rendering.md).
func (a *app) chartRenderer() (charts.Renderer, error) {
	h := a.cfg.Helm
	bin, err := scanner.Binary{Name: "helm", Path: h.Path, SHA256: h.SHA256}.Resolve()
	if err != nil {
		return charts.Renderer{}, fmt.Errorf("%w (scripts/install-scanners.sh installs a pinned one; helm.path in the configuration)", err)
	}
	if bin, err = filepath.Abs(bin); err != nil {
		return charts.Renderer{}, err
	}
	r, err := a.scannerRunner()
	if err != nil {
		return charts.Renderer{}, err
	}
	r.Timeout = h.Timeout.Duration
	return charts.Renderer{Helm: bin, Runner: r, StageDir: filepath.Join(r.TempDir, "charts")}, nil
}

// chartProfiles returns the profiles of c (only the one named only, when set) with their
// values read.
func chartProfiles(c config.Chart, only string) ([]charts.Profile, error) {
	var out []charts.Profile
	for _, p := range c.RenderProfiles() {
		if only != "" && p.Name != only {
			continue
		}
		cp := charts.Profile{
			Name: p.Name, Release: p.Release, Namespace: p.Namespace,
			KubeVersion: p.KubeVersion, APIVersions: p.APIVersions, SkipSchemaValidation: p.SkipSchemaValidation,
		}
		for _, f := range p.ValuesFiles {
			data, err := readBounded(nil, f, charts.MaxValuesBytes)
			if err != nil {
				return nil, fmt.Errorf("%s profile %s: %w", c.ID(), p.Name, err)
			}
			cp.Values = append(cp.Values, data)
		}
		if len(p.Values) > 0 {
			data, err := yaml.Marshal(p.Values)
			if err != nil {
				return nil, fmt.Errorf("%s profile %s: values: %w", c.ID(), p.Name, err)
			}
			cp.Values = append(cp.Values, data)
		}
		out = append(out, cp)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s has no profile %q", c.ID(), only)
	}
	return out, nil
}

// renderedChart is one version of a chart rendered with each of its profiles.
type renderedChart struct {
	Meta     charts.Meta
	Digest   string
	Profiles []renderedProfile
}

type renderedProfile struct {
	Name   string
	Result manifests.Result
}

// renderChart downloads, checks and renders one version of c ("": the newest release) with
// its profiles (only, when set).
func (a *app) renderChart(ctx context.Context, c config.Chart, version, only string) (renderedChart, error) {
	profiles, err := chartProfiles(c, only)
	if err != nil {
		return renderedChart{}, err
	}
	r, err := a.chartRenderer()
	if err != nil {
		return renderedChart{}, err
	}
	data, digest, meta, err := a.fetchChart(ctx, c, version)
	if err != nil {
		return renderedChart{}, chartErr(err)
	}
	out := renderedChart{Meta: meta, Digest: digest}
	for _, p := range profiles {
		res, err := r.Render(ctx, data, c.Chart, meta.Version, p)
		if err != nil {
			// helm's stderr quotes the chart's templates.
			return renderedChart{}, chartErr(fmt.Errorf("%s: %w", c.ID(), err))
		}
		out.Profiles = append(out.Profiles, renderedProfile{Name: p.Name, Result: res})
	}
	return out, nil
}

// chartImageRefs returns the image references a rendered chart runs, in any profile, after
// printing what the manifests cannot show.
func chartImageRefs(cmd *cobra.Command, c config.Chart, rc renderedChart) ([]string, error) {
	var refs []string
	for _, p := range rc.Profiles {
		label := fmt.Sprintf("chart %s %s (profile %s)", c.ID(), rc.Meta.Version, p.Name)
		got, err := manifestRefs(cmd, label, p.Result)
		if err != nil {
			return nil, err
		}
		for _, r := range got {
			if !slices.Contains(refs, r) {
				refs = append(refs, r)
			}
		}
	}
	return refs, nil
}

// chartTargets renders the configured chart id for 'targets add --chart'.
func (a *app) chartTargets(cmd *cobra.Command, id, version, profile string) ([]string, error) {
	if a.store == nil {
		if err := a.setup(cmd); err != nil {
			return nil, err
		}
	}
	c, err := a.configuredChart(id)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
	defer cancel()
	rc, err := a.renderChart(ctx, c, version, profile)
	if err != nil {
		return nil, err
	}
	return chartImageRefs(cmd, c, rc)
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
	cmd.AddCommand(list, versions, fetch, a.chartsImagesCmd())
	return cmd
}

// chartImage is one image a chart runs, and in which profiles.
type chartImage struct {
	Ref      string   `json:"ref"`
	Profiles []string `json:"profiles"`
	Where    []string `json:"where"`
	// Hook is true when, in every profile, only Helm hooks use it.
	Hook bool `json:"hook,omitempty"`
}

type chartImagesJSON struct {
	Chart    string             `json:"chart"`
	Version  string             `json:"version"`
	Digest   string             `json:"digest"`
	Profiles []string           `json:"profiles"`
	Images   []chartImage       `json:"images"`
	Opaque   []manifests.Opaque `json:"opaque,omitempty"`
}

func chartImagesOf(c config.Chart, rc renderedChart) chartImagesJSON {
	out := chartImagesJSON{Chart: c.ID(), Version: rc.Meta.Version, Digest: rc.Digest, Images: []chartImage{}}
	byRef := map[string]int{}
	for _, p := range rc.Profiles {
		out.Profiles = append(out.Profiles, p.Name)
		for _, img := range p.Result.Images {
			i, ok := byRef[img.Ref]
			if !ok {
				i = len(out.Images)
				byRef[img.Ref] = i
				out.Images = append(out.Images, chartImage{Ref: img.Ref, Hook: true})
			}
			ci := &out.Images[i]
			ci.Profiles = append(ci.Profiles, p.Name)
			ci.Hook = ci.Hook && img.Hook
			for _, w := range img.Where {
				if !slices.Contains(ci.Where, w) {
					ci.Where = append(ci.Where, w)
				}
			}
		}
		for _, o := range p.Result.Opaque {
			if !slices.Contains(out.Opaque, o) {
				out.Opaque = append(out.Opaque, o)
			}
		}
	}
	slices.SortFunc(out.Images, func(a, b chartImage) int { return strings.Compare(a.Ref, b.Ref) })
	return out
}

func (a *app) chartsImagesCmd() *cobra.Command {
	var version, profile, format string
	cmd := &cobra.Command{
		Use:   "images NAME",
		Short: "Render a chart with its profiles and list the images it runs",
		Long: `Download one version of a chart (default: the newest release), check its archive and
render it with 'helm template' once per profile, in the scanners' sandbox: no network, no
files but the archive and the profile's values, bounded time and output. The images of every
container, init container and ephemeral container of its workloads are listed, hooks
included. Custom resources are listed too: an operator may run images for them that the
rendered manifests do not show (docs/processes/charts.md).`,
		Example: "  shieldmon charts images ingress-nginx\n  shieldmon charts images ingress-nginx --version 4.12.0 --profile prod -o json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "table" && format != "json" {
				return fmt.Errorf("unknown output format %q", format)
			}
			if err := a.setup(cmd); err != nil {
				return err
			}
			c, err := a.configuredChart(args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()
			rc, err := a.renderChart(ctx, c, version, profile)
			if err != nil {
				return err
			}
			res := chartImagesOf(c, rc)
			w := cmd.OutOrStdout()
			if format == "json" {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			fmt.Fprintf(w, "%s %s (%s), profiles %s: %d image(s)\n", c.ID(), printable(res.Version), res.Digest, strings.Join(res.Profiles, ", "), len(res.Images))
			tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "IMAGE\tPROFILES\tUSED BY\tNOTE")
			for _, img := range res.Images {
				where := img.Where[0]
				if len(img.Where) > 1 {
					where += fmt.Sprintf(" and %d more", len(img.Where)-1)
				}
				note := ""
				if img.Hook {
					note = "hooks only"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", printable(img.Ref), strings.Join(img.Profiles, ","), printable(where), note)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			for i, o := range res.Opaque {
				if i == maxListed {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: and %d more custom resources\n", len(res.Opaque)-maxListed)
					break
				}
				name := o.Name
				if o.Namespace != "" {
					name = o.Namespace + "/" + name
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s %s (%s) is a custom resource: images its operator runs are not in the manifests\n",
					printable(o.Kind), printable(name), printable(o.APIVersion))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "chart version (default: the newest release)")
	cmd.Flags().StringVar(&profile, "profile", "", "render only this profile (default: all)")
	cmd.Flags().StringVarP(&format, "output", "o", "table", "output format: table, json")
	return cmd
}
