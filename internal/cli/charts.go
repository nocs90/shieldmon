package cli

import (
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
	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/manifests"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/scanner"
	"github.com/nocs90/shieldmon/internal/store"
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
	return charts.FetchChecked(ctx, src, c.Chart, version)
}

// chartRenderer renders charts with the configured helm, in the scanners' sandbox
// (docs/adr/0033-chart-rendering.md).
func (a *app) chartRenderer(warn io.Writer) (charts.Renderer, error) {
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
	if !r.Confined() {
		// The operator's choice (ADR 0011), as for scanners; say it where it happens.
		fmt.Fprintln(warn, "warning: scanners.sandbox.backend is none: helm renders third-party templates unconfined")
	}
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
		// The bounds apply while reading: Render checks them again.
		left := int64(charts.MaxValuesBytes)
		for _, f := range p.ValuesFiles {
			data, err := readBounded(nil, f, left)
			if err != nil {
				return nil, fmt.Errorf("%s profile %s: %w (values: at most %d bytes in all)", c.ID(), p.Name, err, charts.MaxValuesBytes)
			}
			left -= int64(len(data))
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
// its profiles (only, when set); warnings go to warn.
func (a *app) renderChart(ctx context.Context, warn io.Writer, c config.Chart, version, only string) (renderedChart, error) {
	profiles, err := chartProfiles(c, only)
	if err != nil {
		return renderedChart{}, err
	}
	r, err := a.chartRenderer(warn)
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
	seen := map[string]bool{}
	for _, p := range rc.Profiles {
		label := fmt.Sprintf("chart %s %s (profile %s)", c.ID(), rc.Meta.Version, p.Name)
		got, err := manifestRefs(cmd, label, p.Result)
		if err != nil {
			return nil, err
		}
		for _, r := range got {
			if !seen[r] {
				seen[r] = true
				refs = append(refs, r)
			}
		}
	}
	return refs, nil
}

// followCharts gives the engine the configured charts to follow, with their profiles' values
// read, and the renderer (docs/adr/0034-chart-tracking.md). A chart whose configuration cannot
// be used carries the reason, and so does every chart when helm is missing: the others, and
// the targets, are still monitored.
func (a *app) followCharts(warn io.Writer) {
	if len(a.cfg.Charts) == 0 || a.engine.Charts != nil {
		return
	}
	// Targets are keyed by the platform's canonical form, as targets add stores it.
	platform := a.cfg.Platform
	if p, err := model.ParsePlatform(platform); err == nil {
		platform = p.String()
	}
	// Registries the operator configured may be internal: images on them may become targets.
	var internal []string
	for _, r := range a.cfg.Registries {
		internal = append(internal, r.Hosts...)
	}
	for _, c := range a.cfg.Charts {
		f := engine.FollowedChart{
			ID: c.ID(), Chart: c.Chart, AddTargets: c.AddTargets, Platform: platform,
			MaxNewTargets: c.MaxNewTargets, InternalRegistries: internal,
		}
		src, err := a.chartSource(c)
		if err == nil {
			f.Source = src
			f.Profiles, err = chartProfiles(c, "")
		}
		if err != nil {
			// The profiles' names still say what was recorded (status, draft-issue).
			f.Profiles = nil
			for _, p := range c.RenderProfiles() {
				f.Profiles = append(f.Profiles, charts.Profile{Name: p.Name})
			}
		}
		f.Err = err
		a.engine.Charts = append(a.engine.Charts, f)
	}
	r, err := a.chartRenderer(warn)
	if err != nil {
		a.engine.ChartRendererErr = err
		return
	}
	a.engine.ChartRenderer = r
}

// chartIDs checks that ids name configured charts.
func (a *app) chartIDs(ids []string) error {
	for _, id := range ids {
		if _, err := a.configuredChart(id); err != nil {
			return err
		}
	}
	return nil
}

func (a *app) chartsTrackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "track [NAME...]",
		Short: "Bring the record of followed charts up to their newest release, as monitor does",
		Long: `Look for each followed chart's newest release (only the charts named, when given), render
it with every profile the first time, and again when its archive or a profile changes, and
record what it runs; with add_targets, add its images as targets. 'shieldmon monitor' does
this at the start of every cycle.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			if err := a.chartIDs(args); err != nil {
				return err
			}
			unlock, err := a.lock()
			if err != nil {
				return err
			}
			defer unlock()
			a.followCharts(cmd.ErrOrStderr())
			failures := a.engine.FollowCharts(cmd.Context(), args...)
			sts, err := a.engine.ChartStatuses(cmd.Context(), args...)
			if err != nil {
				return err
			}
			for _, s := range sts {
				if msg, ok := failures[s.Chart]; ok {
					fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", s.Chart, printable(msg))
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s, %d image(s)\n", s.Chart, printable(s.Version), len(s.Images))
			}
			if len(failures) > 0 {
				return fmt.Errorf("%d chart(s) could not be followed (see 'shieldmon health')", len(failures))
			}
			return nil
		},
	}
}

func (a *app) chartsStatusCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "status [NAME...]",
		Short: "What followed charts run and whether they are neglected",
		Long: `Show, for each followed chart (only the charts named, when given), its newest recorded release,
its images and which are monitored, their findings with a fix, and whether the chart is
neglected under chart_policy: its newest release keeps a finding with a fix past
fixable_after, or it has not released for stale_after. Nothing is fetched: 'shieldmon charts
track' or 'shieldmon monitor' records releases.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "table" && format != "json" && format != "md" {
				return fmt.Errorf("unknown output format %q", format)
			}
			if err := a.setup(cmd); err != nil {
				return err
			}
			if err := a.chartIDs(args); err != nil {
				return err
			}
			a.followCharts(io.Discard)
			sts, err := a.engine.ChartStatuses(cmd.Context(), args...)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			switch format {
			case "json":
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(sts)
			case "md":
				return report.ChartsMarkdown(w, sts, time.Now())
			}
			tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "CHART\tVERSION\tRELEASED\tIMAGES\tMONITORED\tWITH A FIX\tNEGLECTED")
			for _, s := range sts {
				monitored, fixable := 0, 0
				for _, img := range s.Images {
					if img.Monitored {
						monitored++
					}
					fixable += img.Fixable
				}
				released := "-"
				if !s.ReleasedAt.IsZero() {
					released = s.ReleasedAt.Format(time.DateOnly)
				}
				neglected := "-"
				if s.Version != "" {
					neglected = s.Assessment.Verdict()
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%s\n", s.Chart, orDash(printable(s.Version)), released, len(s.Images), monitored, fixable, printable(neglected))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "table", "output format: table, json, md")
	return cmd
}

func (a *app) chartsHistoryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "history NAME",
		Short: "The releases of a followed chart ShieldMon recorded, and how their images changed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			if err := a.chartIDs(args); err != nil {
				return err
			}
			renders, err := a.store.ChartRenders(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if len(renders) == 0 {
				fmt.Fprintf(w, "%s: nothing recorded yet ('shieldmon charts track %s')\n", args[0], args[0])
				return nil
			}
			prev := map[string][]store.ChartImage{} // profile -> images of its previous render
			for _, r := range renders {
				fmt.Fprintf(w, "%s  %s  profile %s  %d image(s)  %s\n", r.RenderedAt.Format(time.DateOnly), printable(r.Version), r.Profile, len(r.Images), shortDigest(r.Digest))
				if before, ok := prev[r.Profile]; ok {
					for _, line := range imageChanges(before, r.Images) {
						fmt.Fprintf(w, "    %s\n", printable(line))
					}
				}
				prev[r.Profile] = r.Images
			}
			return nil
		},
	}
}

// imageChanges lists images added (+) and removed (-) between two renders of a profile.
func imageChanges(before, after []store.ChartImage) []string {
	had, has := map[string]bool{}, map[string]bool{}
	for _, i := range before {
		had[i.Ref] = true
	}
	for _, i := range after {
		has[i.Ref] = true
	}
	var out []string
	for _, i := range after {
		if !had[i.Ref] {
			out = append(out, "+ "+i.Ref)
		}
	}
	for _, i := range before {
		if !has[i.Ref] {
			out = append(out, "- "+i.Ref)
		}
	}
	return out
}

func (a *app) chartsDraftIssueCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "draft-issue NAME",
		Short: "Draft an issue for the maintainers of a neglected chart (never submitted)",
		Long: `Print a Markdown draft for the chart's maintainers: the images of its newest release that carry
vulnerabilities with a fixed version, past chart_policy.fixable_after. ShieldMon never submits
it: review it, follow the project's contribution guidelines, search its issues for an existing
report, and submit it yourself (docs/processes/charts.md).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			if err := a.chartIDs(args); err != nil {
				return err
			}
			a.followCharts(io.Discard)
			sts, err := a.engine.ChartStatuses(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return report.ChartIssueDraft(cmd.OutOrStdout(), sts[0], time.Now())
		},
	}
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
	rc, err := a.renderChart(ctx, cmd.ErrOrStderr(), c, version, profile)
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
	cmd.AddCommand(list, versions, fetch, a.chartsImagesCmd(), a.chartsTrackCmd(), a.chartsStatusCmd(), a.chartsHistoryCmd(), a.chartsDraftIssueCmd())
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
	// A chart can render up to manifests.MaxObjects custom resources per profile.
	opaque := map[manifests.Opaque]bool{}
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
			if !opaque[o] {
				opaque[o] = true
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
			rc, err := a.renderChart(ctx, cmd.ErrOrStderr(), c, version, profile)
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
				var notes []string
				if img.Hook {
					notes = append(notes, "hooks only")
				}
				if _, err := oci.ParseReference(img.Ref, false); err != nil {
					notes = append(notes, "not a valid reference")
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", printable(short(img.Ref, 200)), strings.Join(img.Profiles, ","), printable(short(where, 200)), strings.Join(notes, ", "))
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
