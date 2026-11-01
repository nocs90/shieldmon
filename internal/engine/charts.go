package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nocs90/shieldmon/internal/charts"
	"github.com/nocs90/shieldmon/internal/manifests"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/store"
)

// CheckChart is open while a followed chart cannot be listed, fetched or rendered.
const CheckChart = "chart_failed"

// ChartRenderer renders a chart archive with a profile (charts.Renderer).
type ChartRenderer interface {
	Render(ctx context.Context, archive []byte, chart, version string, p charts.Profile) (manifests.Result, error)
}

// FollowedChart is a chart every monitoring cycle follows (docs/adr/0034-chart-tracking.md).
type FollowedChart struct {
	// ID is its name in ShieldMon, Chart its name in Source.
	ID, Chart string
	Source    charts.Source
	Profiles  []charts.Profile
	// AddTargets makes the images of its newest release targets, for Platform.
	AddTargets bool
	Platform   string
	// Err says why it cannot be followed (its configuration: a values file unreadable).
	Err error
}

// maxAppVersion bounds the app version recorded from a chart's Chart.yaml.
const maxAppVersion = 256

// FollowCharts brings the record of every followed chart (only those in ids, when given) up
// to its newest release: a version is rendered with each profile the first time, and again
// when its archive or the profile changes. It returns the failures by chart; each opens or
// resolves a chart_failed health finding.
func (e *Engine) FollowCharts(ctx context.Context, ids ...string) map[string]string {
	failures := map[string]string{}
	for _, c := range e.Charts {
		if len(ids) > 0 && !slices.Contains(ids, c.ID) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		if err := e.followChart(ctx, c); err != nil {
			failures[c.ID] = redact.Error(err)
			e.health(ctx, CheckChart, c.ID, "medium", err)
			continue
		}
		e.healthy(ctx, CheckChart, c.ID)
	}
	return failures
}

func (e *Engine) followChart(ctx context.Context, c FollowedChart) error {
	if c.Err != nil {
		return c.Err
	}
	if e.ChartRenderer == nil {
		if e.ChartRendererErr != nil {
			return fmt.Errorf("cannot render charts: %w", e.ChartRendererErr)
		}
		return errors.New("cannot render charts: no renderer")
	}
	vs, err := c.Source.Versions(ctx, c.Chart)
	if err != nil {
		return err
	}
	newest := charts.Newest(vs)
	if newest == "" {
		return errors.New("no released version")
	}
	var v charts.Version
	for _, x := range vs {
		if x.Version == newest {
			v = x
		}
	}
	renders, err := e.Store.ChartRenders(ctx, c.ID)
	if err != nil {
		return err
	}
	latest := store.LatestChartRenders(renders)[c.ID]
	var need []charts.Profile
	for _, p := range c.Profiles {
		r, ok := latest[p.Name]
		// An index that names another digest for a recorded version: the archive changed.
		if !ok || r.Version != newest || r.ProfileHash != charts.ProfileHash(p) || (v.Digest != "" && r.Digest != v.Digest) {
			need = append(need, p)
		}
	}
	var errs []error
	if len(need) > 0 {
		data, digest, meta, err := charts.FetchChecked(ctx, c.Source, c.Chart, newest)
		if err != nil {
			return err
		}
		for _, p := range need {
			res, err := e.ChartRenderer.Render(ctx, data, c.Chart, newest, p)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			rec := chartRender(c.ID, newest, meta, v, digest, p, res)
			rec.RenderedAt = e.now()
			if _, err := e.Store.RecordChartRender(ctx, rec); err != nil {
				return err
			}
			latest = nil // read again below
			e.log().Info("chart rendered", "chart", c.ID, "version", newest, "profile", p.Name, "images", len(rec.Images))
		}
	}
	if c.AddTargets {
		if latest == nil {
			if renders, err = e.Store.ChartRenders(ctx, c.ID); err != nil {
				return err
			}
			latest = store.LatestChartRenders(renders)[c.ID]
		}
		for _, p := range c.Profiles {
			r, ok := latest[p.Name]
			if !ok || r.Version != newest {
				continue
			}
			for _, img := range r.Images {
				if _, err := e.Store.UpsertTarget(ctx, img.Ref, c.Platform, e.now()); err != nil {
					return err
				}
			}
		}
	}
	return errors.Join(errs...)
}

// ChartStatuses returns the status of every followed chart (only those in ids, when given),
// judged by ChartPolicy at the current time. A chart never rendered has no version.
func (e *Engine) ChartStatuses(ctx context.Context, ids ...string) ([]charts.Status, error) {
	all, err := e.Store.ChartRenders(ctx, "")
	if err != nil {
		return nil, err
	}
	latest := store.LatestChartRenders(all)
	targets, err := e.Store.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	digests := map[string][]string{} // ref -> scanned digests of its monitored targets
	for _, t := range targets {
		if t.RetiredAt.IsZero() && t.CurrentDigest != "" {
			digests[t.Ref] = append(digests[t.Ref], t.CurrentDigest)
		}
	}
	fixable := map[string][]store.Finding{} // digest -> active findings with a fix
	findings := func(d string) ([]store.Finding, error) {
		if fs, ok := fixable[d]; ok {
			return fs, nil
		}
		fs, err := e.Store.ListFindings(ctx, store.FindingFilter{Digest: d})
		if err != nil {
			return nil, err
		}
		fs = slices.DeleteFunc(fs, func(f store.Finding) bool { return !f.State.Active() || !f.Fixable() })
		fixable[d] = fs
		return fs, nil
	}
	now := e.now()
	var out []charts.Status
	for _, c := range e.Charts {
		if len(ids) > 0 && !slices.Contains(ids, c.ID) {
			continue
		}
		st := charts.Status{Chart: c.ID, Images: []charts.StatusImage{}}
		if c.Source != nil {
			st.Location = c.Source.Location(c.Chart)
		}
		var newest store.ChartRender
		for _, p := range c.Profiles {
			st.Profiles = append(st.Profiles, p.Name)
			if r, ok := latest[c.ID][p.Name]; ok && r.ID > newest.ID {
				newest = r
			}
		}
		if newest.ID == 0 {
			out = append(out, st)
			continue
		}
		st.Version, st.AppVersion, st.ReleasedAt, st.RenderedAt = newest.Version, newest.AppVersion, newest.ReleasedAt, newest.RenderedAt
		rel := charts.Release{Version: newest.Version, ReleasedAt: newest.ReleasedAt}
		byRef := map[string]int{}
		for _, p := range c.Profiles {
			r, ok := latest[c.ID][p.Name]
			if !ok || r.Version != newest.Version {
				st.Lagging = append(st.Lagging, p.Name)
				continue
			}
			st.Invalid += r.Invalid
			st.Opaque += r.Opaque
			for _, img := range r.Images {
				i, ok := byRef[img.Ref]
				if !ok {
					i = len(st.Images)
					byRef[img.Ref] = i
					st.Images = append(st.Images, charts.StatusImage{Ref: img.Ref, Hook: true})
				}
				st.Images[i].Profiles = append(st.Images[i].Profiles, p.Name)
				st.Images[i].Hook = st.Images[i].Hook && img.Hook
			}
		}
		slices.SortFunc(st.Images, func(a, b charts.StatusImage) int { return strings.Compare(a.Ref, b.Ref) })
		for i := range st.Images {
			img := &st.Images[i]
			rel.Images = append(rel.Images, img.Ref)
			ds := digests[img.Ref]
			if len(ds) == 0 {
				rel.Unmonitored = append(rel.Unmonitored, img.Ref)
				continue
			}
			img.Monitored = true
			seen := map[string]bool{}
			for _, d := range ds {
				fs, err := findings(d)
				if err != nil {
					return nil, err
				}
				for _, f := range fs {
					key := f.VulnID + " " + f.PkgKey
					if seen[key] {
						continue
					}
					seen[key] = true
					img.Fixable++
					rel.Fixable = append(rel.Fixable, charts.Fixable{
						Image: img.Ref, VulnID: f.VulnID, Package: f.PkgName, Version: f.PkgVersion, FixVersions: f.FixVersions,
						Severity: f.Severity, KEV: f.KEV, FirstDetected: f.FirstDetected,
					})
				}
			}
		}
		st.Assessment = charts.Assess(rel, e.ChartPolicy, now)
		out = append(out, st)
	}
	return out, nil
}

// chartRender is the record of one render: valid references in the form targets use, the
// others counted.
func chartRender(id, version string, meta charts.Meta, v charts.Version, digest string, p charts.Profile, res manifests.Result) store.ChartRender {
	r := store.ChartRender{
		Chart: id, Version: version, AppVersion: meta.AppVersion, ReleasedAt: v.Created, Digest: digest,
		Profile: p.Name, ProfileHash: charts.ProfileHash(p), Images: []store.ChartImage{}, Opaque: len(res.Opaque),
	}
	if len(r.AppVersion) > maxAppVersion {
		r.AppVersion = strings.ToValidUTF8(r.AppVersion[:maxAppVersion], "")
	}
	seen := map[string]bool{}
	for _, img := range res.Images {
		parsed, err := oci.ParseReference(img.Ref, false)
		if err != nil {
			r.Invalid++
			continue
		}
		if ref := parsed.Name(); !seen[ref] {
			seen[ref] = true
			r.Images = append(r.Images, store.ChartImage{Ref: ref, Hook: img.Hook})
		}
	}
	return r
}
