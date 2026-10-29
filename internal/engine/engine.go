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
	"slices"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/enrich"
	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/normalize"
	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/scanner"
	"github.com/nocs90/shieldmon/internal/store"
)

// Health check names.
const (
	CheckRegistryAuth    = "registry_auth"
	CheckResolve         = "resolve_failed"
	CheckFetch           = "fetch_failed"
	CheckGenerator       = "sbom_generator_failed"
	CheckMatcher         = "matcher_failed"
	CheckDBStale         = "db_stale"
	CheckMonitorMissed   = "monitor_missed"
	CheckChecksum        = "scanner_checksum_mismatch"
	CheckUnsandboxed     = "scanner_unsandboxed"
	CheckSandboxDegraded = "scanner_sandbox_degraded"
	CheckDBUpdate        = "db_update_failed"
	CheckNotify          = "notify_failed"
	CheckAuditChain      = "audit_chain_broken"
	CheckEnrichUpdate    = "enrichment_update_failed"
	CheckEnrichStale     = "enrichment_stale"
	CheckImageInspect    = "image_inspect_failed"
	CheckBaseResolve     = "base_resolve_failed"
	maxSBOMBytes         = 256 << 20
	monitorMissedFactor  = 1.5
)

// Fetcher abstracts image resolution and download (tests use a fake).
type Fetcher interface {
	Resolve(ctx context.Context, ref string, platform model.Platform) (oci.Resolved, error)
	Fetch(ctx context.Context, r oci.Resolved, dir string) error
	// Inspect reads an image's manifest and config, no layers (docs/adr/0022-base-image-lineage.md).
	Inspect(ctx context.Context, ref string, platform model.Platform) (oci.ImageInfo, error)
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

func (f RegistryFetcher) Inspect(ctx context.Context, ref string, p model.Platform) (oci.ImageInfo, error) {
	o := f.Options
	o.Platform = p
	return oci.Inspect(ctx, ref, o)
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
	// Decisions is the policy VEX statements are applied under, like manual decisions.
	Decisions lifecycle.Policy
	// Sandboxed is true when scanners run confined (scanner.Confined). While it is false,
	// Preflight keeps a scanner_unsandboxed health finding open.
	Sandboxed bool
	// SandboxDegraded says which guarantee the sandbox lacks on this host
	// (scanner.SandboxDegraded); while set, Preflight keeps scanner_sandbox_degraded open.
	SandboxDegraded error
	// Channels receive the events of each monitoring cycle (docs/adr/0015-notifications.md).
	Channels []notify.Channel
	// DueSoon is how long before its remediation deadline a finding is due soon.
	DueSoon time.Duration
	// AuditVerifyInterval is how often monitor verifies the audit chain (0 disables;
	// docs/adr/0018-audit-chain.md).
	AuditVerifyInterval time.Duration
	// Enrichers add facts (CISA KEV) to every scan's matches (docs/adr/0019-enrichers.md).
	Enrichers []enrich.Instance
	Now       func() time.Time
	Log       *slog.Logger

	// observedBases are the base references observed in the running monitor cycle: each is
	// resolved once per cycle, however many targets share it.
	observedBases map[string]bool
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
	// NotAffectedByVEX counts findings a VEX statement made not_affected after this scan.
	NotAffectedByVEX int
	Errors           []string
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
	if err := e.refuseRetired(ctx, ref, platform); err != nil {
		return res, err
	}
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
	e.trackLineage(ctx, target, resolved, platform)
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
		// Enriched on every scan, so that findings follow the data (a CVE added to KEV is
		// flagged at the next cycle, whatever the scanners say).
		for _, en := range e.Enrichers {
			for i := range merged {
				en.Enricher.Enrich(&merged[i])
			}
		}
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
		// VEX statements in force cover findings this scan created (docs/adr/0014-vex.md).
		// A failure here leaves the reconciled scan as it is and is reported.
		applied, err := e.Store.ApplyVEX(ctx, digest, e.Decisions, e.now())
		res.NotAffectedByVEX = len(applied)
		if err != nil {
			e.log().Warn("applying VEX statements", "digest", digest, "err", redact.Error(err))
			res.Errors = append(res.Errors, "vex: "+redact.Error(err))
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
	switch {
	case !e.Sandboxed:
		e.health(ctx, CheckUnsandboxed, "scanners", "high",
			errors.New("scanners parse image content with the invoking user's filesystem and network (scanners.sandbox.backend: none)"))
		e.healthy(ctx, CheckSandboxDegraded, "scanners")
	case e.SandboxDegraded != nil:
		e.healthy(ctx, CheckUnsandboxed, "scanners")
		e.health(ctx, CheckSandboxDegraded, "scanners", "medium", e.SandboxDegraded)
	default:
		e.healthy(ctx, CheckUnsandboxed, "scanners")
		e.healthy(ctx, CheckSandboxDegraded, "scanners")
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
	for _, en := range e.Enrichers {
		e.log().Info("updating enrichment data", "enricher", en.Name)
		if err := en.Enricher.Update(ctx); err != nil {
			e.health(ctx, CheckEnrichUpdate, en.Name, "medium", err)
			errs = append(errs, fmt.Errorf("%s: %s", en.Name, redact.Error(err)))
		} else {
			e.healthy(ctx, CheckEnrichUpdate, en.Name)
		}
		e.checkEnrichAge(ctx, en)
	}
	return errors.Join(errs...)
}

// checkEnrichAge keeps enrichment_stale in step with the age of an enricher's data: findings
// are enriched from whatever data is on disk, and old data misses recent KEV additions.
func (e *Engine) checkEnrichAge(ctx context.Context, en enrich.Instance) {
	if en.MaxAge <= 0 {
		return
	}
	at := en.Enricher.UpdatedAt()
	switch {
	case at.IsZero():
		e.health(ctx, CheckEnrichStale, en.Name, "high", fmt.Errorf("%s has no data yet: findings are not enriched", en.Name))
	case e.now().Sub(at) > en.MaxAge:
		e.health(ctx, CheckEnrichStale, en.Name, "high", fmt.Errorf("%s data last confirmed %s ago (max %s)",
			en.Name, e.now().Sub(at).Round(time.Minute), en.MaxAge))
	default:
		e.healthy(ctx, CheckEnrichStale, en.Name)
	}
}

// MonitorSummary summarizes one monitoring cycle.
type MonitorSummary struct {
	RunID           int64
	Status          string
	Results         []Result
	Failures        map[string]string // target ref -> error
	ExpiredDecision []int64
	// Notified counts the events sent per channel; NotifyFailures holds failed channels.
	Notified       map[string]int
	NotifyFailures map[string]string
}

// Monitor runs one ConMon cycle over every target: check the schedule, expire
// decisions, preflight (sandbox posture, DB updates), then scan (resolve + rematch,
// pulling only new digests), and notify.
func (e *Engine) Monitor(ctx context.Context) (MonitorSummary, error) {
	sum := MonitorSummary{Failures: map[string]string{}}
	now := e.now()
	last, lastErr := e.Store.LastMonitorRun(ctx)
	if lastErr != nil && !errors.Is(lastErr, store.ErrNotFound) {
		return sum, lastErr
	}
	if e.MonitorInterval > 0 {
		if lastErr == nil && now.Sub(last.StartedAt) > time.Duration(float64(e.MonitorInterval)*monitorMissedFactor) {
			e.health(ctx, CheckMonitorMissed, "schedule", "high",
				fmt.Errorf("previous monitoring cycle started %s ago (expected every %s)", now.Sub(last.StartedAt).Round(time.Minute), e.MonitorInterval))
		} else {
			e.healthy(ctx, CheckMonitorMissed, "schedule")
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
	// Retired targets are not monitored (ADR 0017).
	targets = slices.DeleteFunc(targets, func(t store.Target) bool { return !t.RetiredAt.IsZero() })
	// Without targets nothing is matched, so the cycle needs no DB and no network.
	if len(targets) > 0 {
		if err := e.Preflight(ctx); err != nil {
			e.log().Warn("vulnerability DB update failed; matching with the DBs on disk", "err", err)
		}
	}
	errCount := 0
	e.observedBases = map[string]bool{}
	defer func() { e.observedBases = nil }()
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
	if e.AuditVerifyInterval > 0 && ctx.Err() == nil {
		if err := e.verifyAuditIfDue(ctx); err != nil {
			return sum, err
		}
	}
	if len(e.Channels) > 0 && ctx.Err() == nil {
		// Findings created since the previous cycle began are new (none before the first).
		sum.Notified, sum.NotifyFailures, err = e.Notify(ctx, last.StartedAt)
		if err != nil {
			e.log().Error("notifications", "err", redact.Error(err))
			sum.NotifyFailures["*"] = redact.Error(err)
		}
		if len(sum.NotifyFailures) > 0 && sum.Status == "ok" {
			sum.Status = "degraded"
		}
	}
	if err := e.Store.FinishMonitorRun(context.WithoutCancel(ctx), runID, sum.Status, len(targets), errCount, e.now()); err != nil {
		return sum, err
	}
	return sum, ctx.Err()
}

// Notify sends the events the store warrants to every channel (docs/adr/0015-notifications.md):
// events are recorded, each channel is sent what it has not been sent, and what was sent is
// recorded. A failing channel opens a notify_failed health finding and keeps its events for
// the next cycle. It returns the number of events sent and the failures, per channel.
func (e *Engine) Notify(ctx context.Context, since time.Time) (map[string]int, map[string]string, error) {
	sent, failed := map[string]int{}, map[string]string{}
	now := e.now()
	in, err := e.notifyInput(ctx, since, now)
	if err != nil {
		return sent, failed, err
	}
	names := make([]string, 0, len(e.Channels))
	for _, ch := range e.Channels {
		names = append(names, ch.Name)
	}
	if err := e.Store.RecordNotificationEvents(ctx, notify.Collect(in), names, now); err != nil {
		return sent, failed, err
	}
	for _, ch := range e.Channels {
		pending, err := e.Store.PendingNotifications(ctx, ch.Name, ch.Kinds)
		if err != nil {
			return sent, failed, err
		}
		pending = notify.Current(pending, in)
		if len(pending) == 0 {
			continue
		}
		keys, sendErr := notify.Dispatch(ctx, ch, pending, now)
		// Recorded even when the cycle is cancelled: those were sent.
		if err := e.Store.RecordNotifications(context.WithoutCancel(ctx), ch.Name, keys, now); err != nil {
			return sent, failed, err
		}
		sent[ch.Name] = len(keys)
		if sendErr != nil {
			failed[ch.Name] = redact.Error(sendErr)
			e.health(ctx, CheckNotify, ch.Name, "high", fmt.Errorf("%w (%d event(s) wait for the next cycle)", sendErr, len(pending)-len(keys)))
			continue
		}
		e.healthy(ctx, CheckNotify, ch.Name)
	}
	return sent, failed, nil
}

// PendingNotifications returns, per channel, what the next monitoring cycle would send if the
// store did not change, without recording or sending anything.
func (e *Engine) PendingNotifications(ctx context.Context) (map[string][]notify.Event, error) {
	last, err := e.Store.LastMonitorRun(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	in, err := e.notifyInput(ctx, last.StartedAt, e.now())
	if err != nil {
		return nil, err
	}
	fresh := notify.Collect(in)
	keys := make([]string, len(fresh))
	for i, ev := range fresh {
		keys[i] = ev.Key
	}
	known, err := e.Store.NotificationEventsKnown(ctx, keys)
	if err != nil {
		return nil, err
	}
	out := map[string][]notify.Event{}
	for _, ch := range e.Channels {
		pending, err := e.Store.PendingNotifications(ctx, ch.Name, ch.Kinds)
		if err != nil {
			return nil, err
		}
		for _, ev := range fresh {
			if !known[ev.Key] && ch.Wants(ev.Kind) {
				pending = append(pending, ev)
			}
		}
		pending = notify.Current(pending, in)
		notify.Sort(pending)
		out[ch.Name] = pending
	}
	return out, nil
}

func (e *Engine) notifyInput(ctx context.Context, since, now time.Time) (notify.Input, error) {
	in, err := e.Store.NotifyInput(ctx, e.Decisions, since, now)
	in.Now, in.Since, in.DueSoon = now, since, e.DueSoon
	return in, err
}

// verifyAuditIfDue verifies the audit chain when the last verification is older than
// AuditVerifyInterval: a chain nobody verifies proves nothing (ADR 0018).
func (e *Engine) verifyAuditIfDue(ctx context.Context) error {
	last, err := e.Store.LastAuditVerification(ctx)
	if err != nil {
		return err
	}
	if !last.IsZero() && e.now().Sub(last) < e.AuditVerifyInterval {
		return nil
	}
	_, err = e.VerifyAudit(ctx, nil)
	return err
}

// VerifyAudit verifies the audit chain against itself and the given digests, records the
// verification, and keeps the audit_chain_broken health finding in step with the result.
func (e *Engine) VerifyAudit(ctx context.Context, digests []store.AuditDigest) (store.AuditReport, error) {
	r, err := e.Store.VerifyAudit(ctx, digests)
	if err != nil {
		return r, err
	}
	if err := e.Store.RecordAuditVerification(ctx, r, e.now()); err != nil {
		return r, err
	}
	if r.OK() {
		e.healthy(ctx, CheckAuditChain, "database")
		return r, nil
	}
	first := r.Problems[0]
	e.health(ctx, CheckAuditChain, "database", "critical", fmt.Errorf(
		"%d problem(s) in the audit trail, first: %s at entry %d (%s %s); run 'shieldmon audit verify'",
		r.Count, first.Kind, first.Seq, first.Table, first.Key))
	return r, nil
}

// ErrRetiredTarget is returned when scanning a retired target: restore it first.
var ErrRetiredTarget = errors.New("target is retired")

// refuseRetired fails before any registry access when (ref, platform) is a retired target.
func (e *Engine) refuseRetired(ctx context.Context, ref string, platform model.Platform) error {
	r, err := oci.ParseReference(ref, false)
	if err != nil {
		return nil // Resolve reports the invalid reference
	}
	targets, err := e.Store.TargetsByRef(ctx, r.Name())
	if err != nil {
		return err
	}
	for _, t := range targets {
		if t.Platform == platform.String() && !t.RetiredAt.IsZero() {
			return fmt.Errorf("%w: %s (%s) since %s; 'shieldmon targets restore %d' to monitor it again",
				ErrRetiredTarget, t.Ref, t.Platform, t.RetiredAt.Format(time.DateOnly), t.ID)
		}
	}
	return nil
}

// RetireTarget stops monitoring a target (ADR 0017): recorded with actor and reason, findings
// unchanged. Health findings about resolving its reference are resolved, since no cycle will
// check them again.
func (e *Engine) RetireTarget(ctx context.Context, t store.Target, actor, reason string) error {
	if err := e.Store.RetireTarget(ctx, t.ID, actor, reason, e.now()); err != nil {
		return err
	}
	e.healthy(ctx, CheckResolve, t.Ref)
	return nil
}

// RestoreTarget monitors a retired target again; the next cycle resolves and rescans it.
func (e *Engine) RestoreTarget(ctx context.Context, t store.Target, actor, reason string) error {
	return e.Store.RestoreTarget(ctx, t.ID, actor, reason, e.now())
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
