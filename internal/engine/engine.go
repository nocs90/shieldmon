// Package engine orchestrates the ConMon pipeline:
//
//	resolve tag -> digest -> (fetch + generate SBOMs, once per digest)
//	-> match stored SBOMs -> normalize/dedupe -> reconcile lifecycle
//
// Every failure of the pipeline itself is recorded as a health finding.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/normalize"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/scanner"
	"github.com/nocs90/shieldmon/internal/store"
)

// Health check names.
const (
	CheckRegistryAuth   = "registry_auth"
	CheckResolve        = "resolve_failed"
	CheckFetch          = "fetch_failed"
	CheckGenerator      = "sbom_generator_failed"
	CheckMatcher        = "matcher_failed"
	CheckDBStale        = "db_stale"
	CheckMonitorMissed  = "monitor_missed"
	CheckChecksum       = "scanner_checksum_mismatch"
	CheckUnsandboxed    = "scanner_unsandboxed"
	CheckDBUpdate       = "db_update_failed"
	maxSBOMBytes        = 256 << 20
	monitorMissedFactor = 1.5
)

// Fetcher abstracts image resolution and download (tests use a fake).
type Fetcher interface {
	Resolve(ctx context.Context, ref string, platform model.Platform) (oci.Resolved, error)
	Fetch(ctx context.Context, r oci.Resolved, dir string) error
}

// RegistryFetcher is the production Fetcher backed by go-containerregistry.
type RegistryFetcher struct{ Options oci.Options }

func (f RegistryFetcher) Resolve(ctx context.Context, ref string, p model.Platform) (oci.Resolved, error) {
	o := f.Options
	o.Platform = p
	return oci.Resolve(ctx, ref, o)
}

func (f RegistryFetcher) Fetch(ctx context.Context, r oci.Resolved, dir string) error {
	return oci.Fetch(ctx, r, dir, f.Options)
}

// Engine runs scans against a store.
type Engine struct {
	Store    *store.Store
	Scanners scanner.Set
	Fetcher  Fetcher
	DataDir  string
	// DBMaxAge opens a db_stale health finding when exceeded (0 disables).
	DBMaxAge time.Duration
	// MonitorInterval is the expected cadence of Monitor (0 disables the check).
	MonitorInterval time.Duration
	// Sandboxed is true when scanners run confined (scanner.Confined). While it is false,
	// Preflight keeps a scanner_unsandboxed health finding open.
	Sandboxed bool
	Now       func() time.Time
	Log       *slog.Logger
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Result summarizes one scan of one target or digest.
type Result struct {
	Target       store.Target
	Resolved     oci.Resolved
	DigestChange bool
	PrevDigest   string
	SBOMsCreated []string
	ScanID       int64
	Kind         string
	Status       string
	Tools        []model.Tool
	Matches      int
	Created      int // new problems (no predecessor)
	Carried      int // continued from a predecessor digest
	Transitions  map[model.State]int
	Errors       []string
}

func (e *Engine) health(ctx context.Context, check, subject, severity string, err error) {
	detail := redact.Error(err)
	if herr := e.Store.RecordHealth(ctx, check, subject, severity, detail, e.now()); herr != nil {
		e.log().Error("record health finding", "check", check, "err", herr)
	}
	e.log().Warn("health finding", "check", check, "subject", subject, "detail", detail)
}

func (e *Engine) healthy(ctx context.Context, check, subject string) {
	if err := e.Store.ResolveHealth(ctx, check, subject, e.now()); err != nil {
		e.log().Error("resolve health finding", "check", check, "err", err)
	}
}

// Scan resolves ref, makes sure SBOMs exist for the resolved digest (pulling
// the image only if they do not) and matches them. Calling Scan again on an
// unchanged tag is therefore a cheap re-match: SBOM-first by construction.
func (e *Engine) Scan(ctx context.Context, ref string, platform model.Platform) (Result, error) {
	var res Result
	resolved, err := e.Fetcher.Resolve(ctx, ref, platform)
	if err != nil {
		subject := ref
		if r, perr := oci.ParseReference(ref, false); perr == nil {
			subject = r.Context().RegistryStr()
		}
		if errors.Is(err, oci.ErrAuth) {
			e.health(ctx, CheckRegistryAuth, subject, "high", err)
		} else {
			e.health(ctx, CheckResolve, ref, "medium", err)
		}
		return res, fmt.Errorf("resolve %s: %s", ref, redact.Error(err))
	}
	e.healthy(ctx, CheckRegistryAuth, resolved.Registry)
	e.healthy(ctx, CheckResolve, ref)
	res.Resolved = resolved

	now := e.now()
	target, err := e.Store.UpsertTarget(ctx, resolved.Input, platform.String(), now)
	if err != nil {
		return res, err
	}
	err = e.Store.UpsertArtifact(ctx, store.Artifact{
		Digest: resolved.Digest, Repository: resolved.Repository, IndexDigest: resolved.IndexDigest,
		MediaType: resolved.MediaType, Platform: resolved.Platform.String(),
	}, now)
	if err != nil {
		return res, err
	}
	prev, changed, err := e.Store.RecordResolution(ctx, target.ID, resolved.Digest, now)
	if err != nil {
		return res, err
	}
	target.CurrentDigest = resolved.Digest
	res.Target, res.DigestChange, res.PrevDigest = target, changed && prev != "", prev

	created, genErrs := e.ensureSBOMs(ctx, resolved)
	res.SBOMsCreated = created
	res.Errors = append(res.Errors, genErrs...)

	kind := "rematch"
	if len(created) > 0 {
		kind = "initial"
	}
	if err := e.match(ctx, resolved.Digest, target.ID, kind, &res); err != nil {
		return res, err
	}
	return res, nil
}

// Rematch re-runs matchers on the stored SBOMs of a digest without
// contacting any registry.
func (e *Engine) Rematch(ctx context.Context, digest string) (Result, error) {
	var res Result
	if _, err := e.Store.GetArtifact(ctx, digest); err != nil {
		return res, fmt.Errorf("digest %s: %w", digest, err)
	}
	targets, err := e.Store.TargetsForDigest(ctx, digest)
	if err != nil {
		return res, err
	}
	var tid int64
	if len(targets) > 0 {
		res.Target, tid = targets[0], targets[0].ID
	}
	res.Resolved.Digest = digest
	return res, e.match(ctx, digest, tid, "rematch", &res)
}

// ensureSBOMs generates missing SBOMs for the digest. The image is fetched at
// most once, into a private temporary OCI layout that is removed afterwards.
func (e *Engine) ensureSBOMs(ctx context.Context, r oci.Resolved) (created, errs []string) {
	gens, err := e.Scanners.RequiredGenerators()
	if err != nil {
		return nil, []string{err.Error()}
	}
	have, err := e.Store.SBOMs(ctx, r.Digest)
	if err != nil {
		return nil, []string{err.Error()}
	}
	var missing []scanner.Generator
	for _, g := range gens {
		if findSBOM(have, g.Name()) == nil {
			missing = append(missing, g)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}

	tmpRoot := filepath.Join(e.DataDir, "tmp")
	if err := os.MkdirAll(tmpRoot, 0o700); err != nil {
		return nil, []string{err.Error()}
	}
	tmp, err := os.MkdirTemp(tmpRoot, "scan-")
	if err != nil {
		return nil, []string{err.Error()}
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	ociDir := filepath.Join(tmp, "oci")
	e.log().Info("fetching image", "ref", r.DigestRef())
	if err := e.Fetcher.Fetch(ctx, r, ociDir); err != nil {
		check := CheckFetch
		if errors.Is(err, oci.ErrAuth) {
			check = CheckRegistryAuth
		}
		e.health(ctx, check, r.Registry, "high", err)
		return nil, []string{"fetch: " + redact.Error(err)}
	}
	e.healthy(ctx, CheckFetch, r.Registry)

	for _, g := range missing {
		out := filepath.Join(tmp, g.Name())
		if err := os.Mkdir(out, 0o700); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if err := e.generate(ctx, g, r, ociDir, out); err != nil {
			check := CheckGenerator
			if errors.Is(err, scanner.ErrChecksumMismatch) {
				check = CheckChecksum
			}
			e.health(ctx, check, g.Name(), "high", err)
			errs = append(errs, g.Name()+": "+redact.Error(err))
			continue
		}
		e.healthy(ctx, CheckGenerator, g.Name())
		e.healthy(ctx, CheckChecksum, g.Name())
		created = append(created, g.Name())
	}
	return created, errs
}

func (e *Engine) generate(ctx context.Context, g scanner.Generator, r oci.Resolved, ociDir, out string) error {
	tool, err := g.Tool(ctx)
	if err != nil {
		return err
	}
	e.log().Info("generating SBOM", "generator", g.Name(), "version", tool.Version, "digest", r.Digest)
	gctx := scanner.WithPolicy(ctx, scanner.Policy{ReadOnly: []string{ociDir}, Writable: []string{out}})
	files, err := g.Generate(gctx, scanner.Source{OCIDir: ociDir, Name: r.Repository, Version: r.Digest}, out)
	if err != nil {
		return err
	}
	destDir := filepath.Join(e.DataDir, "sboms", strings.ReplaceAll(r.Digest, ":", "_"))
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return err
	}
	for _, f := range files {
		if err := validateSBOM(f); err != nil {
			return fmt.Errorf("%s produced an invalid %s: %w", g.Name(), f.Format, err)
		}
		sum, err := scanner.FileSHA256(f.Path)
		if err != nil {
			return err
		}
		st, err := os.Stat(f.Path)
		if err != nil {
			return err
		}
		rel := filepath.Join("sboms", filepath.Base(destDir), g.Name()+"."+f.Format+".json")
		if err := moveFile(f.Path, filepath.Join(e.DataDir, rel)); err != nil {
			return err
		}
		err = e.Store.InsertSBOM(ctx, store.SBOM{
			Digest: r.Digest, Generator: g.Name(), GeneratorVersion: tool.Version, Format: f.Format,
			SHA256: sum, Size: st.Size(), Path: rel, CreatedAt: e.now(),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// validateSBOM bounds and sanity-checks generator output before storing it.
func validateSBOM(f scanner.SBOMFile) error {
	st, err := os.Stat(f.Path)
	if err != nil {
		return err
	}
	if st.Size() > maxSBOMBytes {
		return fmt.Errorf("size %d exceeds %d", st.Size(), maxSBOMBytes)
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}
	var head struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	switch f.Format {
	case scanner.FormatCycloneDXJSON:
		if head.BOMFormat != "CycloneDX" {
			return fmt.Errorf("missing bomFormat=CycloneDX")
		}
	case scanner.FormatSPDXJSON:
		if !strings.HasPrefix(head.SPDXVersion, "SPDX-") {
			return fmt.Errorf("missing spdxVersion")
		}
	}
	return nil
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return os.Chmod(dst, 0o600)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func findSBOM(list []store.SBOM, generator string) *store.SBOM {
	for i := range list {
		if list[i].Generator == generator && list[i].Format == scanner.FormatCycloneDXJSON {
			return &list[i]
		}
	}
	return nil
}

// match runs every configured matcher on the stored SBOMs and reconciles.
func (e *Engine) match(ctx context.Context, digest string, targetID int64, kind string, res *Result) error {
	scanID, err := e.Store.CreateScan(ctx, digest, targetID, kind, e.now())
	if err != nil {
		return err
	}
	res.ScanID, res.Kind = scanID, kind
	sboms, err := e.Store.SBOMs(ctx, digest)
	if err != nil {
		return err
	}
	var raw []model.RawMatch
	var matchErrs []string
	succeeded := 0
	for _, m := range e.Scanners.Matchers {
		sb := findSBOM(sboms, m.Generator())
		if sb == nil {
			matchErrs = append(matchErrs, fmt.Sprintf("%s: no %s SBOM stored for %s", m.Name(), m.Generator(), digest))
			continue
		}
		e.log().Info("matching", "matcher", m.Name(), "digest", digest)
		sbomPath := filepath.Join(e.DataDir, sb.Path)
		out, err := m.Match(scanner.WithPolicy(ctx, scanner.Policy{ReadOnly: []string{sbomPath}}), sbomPath)
		if err != nil {
			check := CheckMatcher
			if errors.Is(err, scanner.ErrChecksumMismatch) {
				check = CheckChecksum
			}
			e.health(ctx, check, m.Name(), "high", err)
			matchErrs = append(matchErrs, m.Name()+": "+redact.Error(err))
			continue
		}
		e.healthy(ctx, CheckMatcher, m.Name())
		e.healthy(ctx, CheckChecksum, m.Name())
		succeeded++
		res.Tools = append(res.Tools, out.Tool)
		raw = append(raw, out.Matches...)
		e.checkDBAge(ctx, out.Tool)
	}
	res.Errors = append(res.Errors, matchErrs...)

	status := store.ScanComplete
	switch {
	case succeeded == 0:
		status = store.ScanFailed
	case len(matchErrs) > 0:
		status = store.ScanPartial
	}
	res.Status = status

	if status != store.ScanFailed {
		merged := normalize.Merge(raw)
		res.Matches = len(merged)
		var tids []int64
		targets, err := e.Store.TargetsForDigest(ctx, digest)
		if err != nil {
			return err
		}
		for _, t := range targets {
			tids = append(tids, t.ID)
		}
		plan, err := e.Store.ReconcileScan(ctx, store.ReconcileArgs{
			ScanID: scanID, Digest: digest, TargetIDs: tids, Matches: merged,
			Complete: status == store.ScanComplete, Now: e.now(),
		})
		if err != nil {
			_ = e.Store.FinishScan(ctx, scanID, store.ScanFailed, res.Tools, redact.Error(err), e.now())
			return fmt.Errorf("reconcile: %w", err)
		}
		for _, c := range plan.Creates {
			if c.PredecessorID != 0 {
				res.Carried++
			} else {
				res.Created++
			}
		}
		res.Transitions = map[model.State]int{}
		for _, t := range plan.Transitions {
			res.Transitions[t.To]++
		}
	}
	errMsg := strings.Join(res.Errors, "; ")
	return e.Store.FinishScan(ctx, scanID, status, res.Tools, errMsg, e.now())
}

func (e *Engine) checkDBAge(ctx context.Context, t model.Tool) {
	if e.DBMaxAge <= 0 {
		return
	}
	if t.DBBuilt.IsZero() {
		e.health(ctx, CheckDBStale, t.Name, "medium", fmt.Errorf("%s did not report its vulnerability DB build time", t.Name))
		return
	}
	if age := t.DBAge(e.now()); age > e.DBMaxAge {
		e.health(ctx, CheckDBStale, t.Name, "high",
			fmt.Errorf("%s vulnerability DB built %s is %s old (max %s)", t.Name, t.DBBuilt.Format(time.RFC3339), age.Round(time.Minute), e.DBMaxAge))
		return
	}
	e.healthy(ctx, CheckDBStale, t.Name)
}

// Preflight runs before scanning: it records whether scanners are confined and refreshes
// the matchers' vulnerability DBs. A failed update is a health finding, not a reason to
// skip the cycle: matching then uses the DB on disk and checkDBAge judges its age.
func (e *Engine) Preflight(ctx context.Context) error {
	if e.Sandboxed {
		e.healthy(ctx, CheckUnsandboxed, "scanners")
	} else {
		e.health(ctx, CheckUnsandboxed, "scanners", "high",
			errors.New("scanners parse image content with the invoking user's filesystem and network (scanners.sandbox.backend: none)"))
	}
	return e.UpdateDBs(ctx)
}

// UpdateDBs refreshes the vulnerability DB of every matcher that keeps one. These are the
// only scanner processes with network, and they never receive image content or SBOMs.
func (e *Engine) UpdateDBs(ctx context.Context) error {
	var errs []error
	for _, m := range e.Scanners.Matchers {
		u, ok := m.(scanner.DBUpdater)
		if !ok {
			continue
		}
		e.log().Info("updating vulnerability DB", "matcher", m.Name())
		if err := u.UpdateDB(scanner.WithPolicy(ctx, scanner.Policy{Network: true})); err != nil {
			check, severity := CheckDBUpdate, "medium"
			if errors.Is(err, scanner.ErrChecksumMismatch) {
				check, severity = CheckChecksum, "high"
			}
			e.health(ctx, check, m.Name(), severity, err)
			errs = append(errs, fmt.Errorf("%s: %s", m.Name(), redact.Error(err)))
			continue
		}
		e.healthy(ctx, CheckDBUpdate, m.Name())
	}
	return errors.Join(errs...)
}

// MonitorSummary summarizes one monitoring cycle.
type MonitorSummary struct {
	RunID           int64
	Status          string
	Results         []Result
	Failures        map[string]string // target ref -> error
	ExpiredDecision []int64
}

// Monitor runs one ConMon cycle over every target: check the schedule, expire
// decisions, preflight (sandbox posture, DB updates), then scan (resolve + rematch,
// pulling only new digests).
func (e *Engine) Monitor(ctx context.Context) (MonitorSummary, error) {
	sum := MonitorSummary{Failures: map[string]string{}}
	now := e.now()
	if e.MonitorInterval > 0 {
		last, err := e.Store.LastMonitorRun(ctx)
		switch {
		case err == nil && now.Sub(last.StartedAt) > time.Duration(float64(e.MonitorInterval)*monitorMissedFactor):
			e.health(ctx, CheckMonitorMissed, "schedule", "high",
				fmt.Errorf("previous monitoring cycle started %s ago (expected every %s)", now.Sub(last.StartedAt).Round(time.Minute), e.MonitorInterval))
		case err == nil || errors.Is(err, store.ErrNotFound):
			e.healthy(ctx, CheckMonitorMissed, "schedule")
		default:
			return sum, err
		}
	}
	runID, err := e.Store.StartMonitorRun(ctx, now)
	if err != nil {
		return sum, err
	}
	sum.RunID = runID

	if sum.ExpiredDecision, err = e.Store.ExpireDecisions(ctx, now); err != nil {
		return sum, err
	}
	targets, err := e.Store.ListTargets(ctx)
	if err != nil {
		return sum, err
	}
	// Without targets nothing is matched, so the cycle needs no DB and no network.
	if len(targets) > 0 {
		if err := e.Preflight(ctx); err != nil {
			e.log().Warn("vulnerability DB update failed; matching with the DBs on disk", "err", err)
		}
	}
	errCount := 0
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		p, err := model.ParsePlatform(t.Platform)
		if err != nil {
			sum.Failures[t.Ref] = err.Error()
			errCount++
			continue
		}
		r, err := e.Scan(ctx, t.Ref, p)
		if err != nil {
			sum.Failures[t.Ref] = redact.Error(err)
			errCount++
			continue
		}
		if r.Status != store.ScanComplete {
			errCount++
		}
		sum.Results = append(sum.Results, r)
	}
	sum.Status = "ok"
	switch {
	case ctx.Err() != nil || (errCount > 0 && errCount == len(targets)):
		sum.Status = "failed"
	case errCount > 0:
		sum.Status = "degraded"
	}
	if err := e.Store.FinishMonitorRun(context.WithoutCancel(ctx), runID, sum.Status, len(targets), errCount, e.now()); err != nil {
		return sum, err
	}
	return sum, ctx.Err()
}

// ActorFromEnv returns a default human actor name for manual transitions.
func ActorFromEnv() string {
	for _, k := range []string{"SHIELDMON_ACTOR", "USER", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
