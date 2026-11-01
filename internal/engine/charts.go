package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

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
	// AddTargets makes the images of its newest release targets, for Platform, at most
	// MaxNewTargets new ones per release (0: DefaultMaxNewTargets). Images on registries that
	// do not look public are added only when InternalRegistries (host patterns: the
	// registries the operator configured) names them.
	AddTargets         bool
	Platform           string
	MaxNewTargets      int
	InternalRegistries []string
	// Err says why it cannot be followed (its configuration: a values file unreadable).
	Err error
}

const (
	// maxAppVersion bounds the app version recorded from a chart's Chart.yaml.
	maxAppVersion = 256
	// maxImageRef bounds an image reference recorded from a render; longer ones are counted
	// as invalid.
	maxImageRef = 512
	// DefaultMaxNewTargets bounds the targets one release of a chart adds unattended.
	DefaultMaxNewTargets = 50
	// DefaultChartTimeout bounds the time one chart takes in a cycle: listing, download and
	// every profile's render.
	DefaultChartTimeout = 10 * time.Minute
	// releaseSkew is how far in the future a release time may be before it is not believed.
	releaseSkew = 24 * time.Hour
)

// FollowCharts brings the record of every followed chart (only those in ids, when given) up
// to its newest release: a version is rendered with each profile the first time, and again
// when its archive or the profile changes. Each chart has ChartTimeout. It returns the
// failures by chart; each opens or resolves a chart_failed health finding.
func (e *Engine) FollowCharts(ctx context.Context, ids ...string) map[string]string {
	failures := map[string]string{}
	timeout := e.ChartTimeout
	if timeout <= 0 {
		timeout = DefaultChartTimeout
	}
	for _, c := range e.Charts {
		if len(ids) > 0 && !slices.Contains(ids, c.ID) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		err := e.followChart(cctx, c)
		if err != nil && errors.Is(cctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			err = fmt.Errorf("not done within %s: %w", timeout, err)
		}
		cancel()
		if err != nil {
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
	// The first entry of a version, as sources fetch it.
	var v charts.Version
	if i := slices.IndexFunc(vs, func(x charts.Version) bool { return x.Version == newest }); i >= 0 {
		v = vs[i]
	}
	if v.Created.After(e.now().Add(releaseSkew)) {
		v.Created = time.Time{} // a release from the future: its time is not known
	}
	latest, err := e.latestRenders(ctx, c.ID)
	if err != nil {
		return err
	}
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
			if latest, err = e.latestRenders(ctx, c.ID); err != nil {
				return err
			}
		}
		if err := e.addChartTargets(ctx, c, newest, latest); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) latestRenders(ctx context.Context, chart string) (map[string]store.ChartRender, error) {
	rs, err := e.Store.LatestChartRenders(ctx, chart)
	if err != nil {
		return nil, err
	}
	out := map[string]store.ChartRender{}
	for _, r := range rs {
		out[r.Profile] = r
	}
	return out, nil
}

// addChartTargets makes the images of version (the newest release) targets. Remote content
// chooses them, so only registries that look public, or that the operator configured, are
// contacted; and a release adding more than MaxNewTargets is left to a person
// ('targets add --chart NAME --dry-run'): nothing of it is added.
func (e *Engine) addChartTargets(ctx context.Context, c FollowedChart, version string, latest map[string]store.ChartRender) error {
	targets, err := e.Store.ListTargets(ctx)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, t := range targets {
		if t.Platform == c.Platform {
			have[t.Ref] = true
		}
	}
	var add, refused []string
	seen := map[string]bool{}
	for _, p := range c.Profiles {
		r, ok := latest[p.Name]
		if !ok || r.Version != version {
			continue
		}
		for _, img := range r.Images {
			if seen[img.Ref] || have[img.Ref] {
				continue
			}
			seen[img.Ref] = true
			ref, err := oci.ParseReference(img.Ref, false)
			if err != nil {
				continue // recorded as valid, so this does not happen
			}
			if host := ref.Context().RegistryStr(); !charts.PublicRegistry(host) && !oci.MatchHost(c.InternalRegistries, host) {
				refused = append(refused, img.Ref)
				continue
			}
			add = append(add, img.Ref)
		}
	}
	limit := c.MaxNewTargets
	if limit <= 0 {
		limit = DefaultMaxNewTargets
	}
	if len(add) > limit {
		return fmt.Errorf("%s %s would add %d new targets, more than %d: none added; review them with 'shieldmon targets add --chart %s --dry-run'",
			c.ID, version, len(add), limit, c.ID)
	}
	for _, ref := range add {
		if _, err := e.Store.UpsertTarget(ctx, ref, c.Platform, e.now()); err != nil {
			return err
		}
	}
	if len(refused) > 0 {
		return fmt.Errorf("%s %s: %d image(s) on registries that are not public and not configured in registries:, not added: %s",
			c.ID, version, len(refused), strings.Join(refused[:min(len(refused), 5)], ", "))
	}
	return nil
}

// ChartStatuses returns the status of every followed chart (only those in ids, when given),
// judged by ChartPolicy at the current time. A chart never rendered has no version.
func (e *Engine) ChartStatuses(ctx context.Context, ids ...string) ([]charts.Status, error) {
	rs, err := e.Store.LatestChartRenders(ctx, "")
	if err != nil {
		return nil, err
	}
	latest := map[string]map[string]store.ChartRender{}
	for _, r := range rs {
		if latest[r.Chart] == nil {
			latest[r.Chart] = map[string]store.ChartRender{}
		}
		latest[r.Chart][r.Profile] = r
	}
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
		if err != nil || len(parsed.Name()) > maxImageRef {
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
