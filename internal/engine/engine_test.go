package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/scanner"
	"github.com/nocs90/shieldmon/internal/store"
)

// fakeFetcher resolves refs from a mutable tag table, like a registry whose
// tags move over time.
type fakeFetcher struct {
	tags    map[string]string // ref -> digest
	fetches int
}

func (f *fakeFetcher) Resolve(_ context.Context, ref string, p model.Platform) (oci.Resolved, error) {
	d, ok := f.tags[ref]
	if !ok {
		return oci.Resolved{}, fmt.Errorf("%w: 401 for %s", oci.ErrAuth, ref)
	}
	return oci.Resolved{
		Input: ref, Repository: "registry.test/app", Registry: "registry.test", Digest: d,
		MediaType: "application/vnd.oci.image.manifest.v1+json", Platform: p,
	}, nil
}

func (f *fakeFetcher) Fetch(_ context.Context, r oci.Resolved, dir string) error {
	f.fetches++
	return os.MkdirAll(dir, 0o700)
}

// fakeGenerator writes a minimal SBOM that records the digest it describes.
type fakeGenerator struct {
	name  string
	calls int
}

func (g *fakeGenerator) Name() string { return g.name }
func (g *fakeGenerator) Tool(context.Context) (model.Tool, error) {
	return model.Tool{Name: g.name, Version: "1.0.0"}, nil
}

func (g *fakeGenerator) Generate(_ context.Context, src scanner.Source, out string) ([]scanner.SBOMFile, error) {
	g.calls++
	p := filepath.Join(out, "bom.json")
	doc := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": map[string]any{"component": map[string]string{"version": src.Version}}}
	b, _ := json.Marshal(doc)
	return []scanner.SBOMFile{{Format: scanner.FormatCycloneDXJSON, Path: p}}, os.WriteFile(p, b, 0o600)
}

// fakeMatcher returns the vulnerabilities configured for the SBOM's digest.
type fakeMatcher struct {
	name, gen string
	vulns     map[string][]model.RawMatch // digest -> matches
	fail      bool
	dbBuilt   time.Time
	// updateFail makes UpdateDB fail; calls records "update"/"match" with the network
	// grant of each process, e.g. "update+net".
	updateFail bool
	calls      []string
}

func (m *fakeMatcher) record(ctx context.Context, call string) {
	if scanner.PolicyFrom(ctx).Network {
		call += "+net"
	}
	m.calls = append(m.calls, call)
}

func (m *fakeMatcher) Name() string      { return m.name }
func (m *fakeMatcher) Generator() string { return m.gen }
func (m *fakeMatcher) UpdateDB(ctx context.Context) error {
	m.record(ctx, "update")
	if m.updateFail {
		return errors.New("db listing unreachable: https://user:hunter2@mirror.test/listing.json")
	}
	return nil
}

func (m *fakeMatcher) Match(ctx context.Context, path string) (scanner.Result, error) {
	m.record(ctx, "match")
	if m.fail {
		return scanner.Result{}, errors.New("db download failed: token=abc123secret")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return scanner.Result{}, err
	}
	var doc struct {
		Metadata struct{ Component struct{ Version string } }
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return scanner.Result{}, err
	}
	var out []model.RawMatch
	for _, v := range m.vulns[doc.Metadata.Component.Version] {
		v.Scanner = m.name
		out = append(out, v)
	}
	return scanner.Result{Tool: model.Tool{Name: m.name, Version: "9.9.9", DBBuilt: m.dbBuilt}, Matches: out}, nil
}

func vuln(pkg, version, id string, sev model.Severity, fix ...string) model.RawMatch {
	return model.RawMatch{
		VulnID: id, PURL: fmt.Sprintf("pkg:apk/alpine/%s@%s?arch=x86_64", pkg, version),
		PkgName: pkg, PkgVersion: version, Severity: sev, FixVersions: fix,
	}
}

type harness struct {
	t      *testing.T
	ctx    context.Context
	clock  time.Time
	store  *store.Store
	fetch  *fakeFetcher
	syft   *fakeGenerator
	trivyG *fakeGenerator
	grype  *fakeMatcher
	trivy  *fakeMatcher
	eng    *engine.Engine
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := &harness{
		t: t, ctx: ctx, store: st,
		clock:  time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC),
		fetch:  &fakeFetcher{tags: map[string]string{}},
		syft:   &fakeGenerator{name: "syft"},
		trivyG: &fakeGenerator{name: "trivy"},
	}
	h.grype = &fakeMatcher{name: "grype", gen: "syft", vulns: map[string][]model.RawMatch{}, dbBuilt: h.clock}
	h.trivy = &fakeMatcher{name: "trivy", gen: "trivy", vulns: map[string][]model.RawMatch{}, dbBuilt: h.clock}
	h.eng = &engine.Engine{
		Store: st, Fetcher: h.fetch, DataDir: t.TempDir(),
		Scanners: scanner.Set{
			Generators: map[string]scanner.Generator{"syft": h.syft, "trivy": h.trivyG},
			Matchers:   []scanner.Matcher{h.grype, h.trivy},
		},
		DBMaxAge: 72 * time.Hour, MonitorInterval: 24 * time.Hour,
		Now: func() time.Time { return h.clock },
	}
	return h
}

func (h *harness) advance(d time.Duration) {
	h.clock = h.clock.Add(d)
	h.grype.dbBuilt, h.trivy.dbBuilt = h.clock, h.clock
}

// image publishes digest under ref with the same vulns seen by both scanners.
func (h *harness) image(ref, digest string, vulns ...model.RawMatch) {
	h.fetch.tags[ref] = digest
	h.grype.vulns[digest] = vulns
	h.trivy.vulns[digest] = vulns
}

func (h *harness) scan(ref string) engine.Result {
	h.t.Helper()
	r, err := h.eng.Scan(h.ctx, ref, model.Platform{OS: "linux", Architecture: "amd64"})
	if err != nil {
		h.t.Fatalf("scan %s: %v", ref, err)
	}
	return r
}

func (h *harness) finding(vulnID, digest string) store.Finding {
	h.t.Helper()
	fs, err := h.store.ListFindings(h.ctx, store.FindingFilter{VulnID: vulnID, Digest: digest})
	if err != nil {
		h.t.Fatal(err)
	}
	if len(fs) != 1 {
		h.t.Fatalf("want exactly one %s finding on %s, got %d", vulnID, digest, len(fs))
	}
	return fs[0]
}

func (h *harness) health(check, subject string) *store.HealthFinding {
	hs, err := h.store.ListHealth(h.ctx, true)
	if err != nil {
		h.t.Fatal(err)
	}
	for i := range hs {
		if hs[i].Check == check && hs[i].Subject == subject {
			return &hs[i]
		}
	}
	return nil
}

const (
	ref     = "registry.test/app:prod"
	digestA = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
	digestB = "sha256:bbbb000000000000000000000000000000000000000000000000000000000000"
	digestC = "sha256:cccc000000000000000000000000000000000000000000000000000000000000"
)

func TestContinuousMonitoringLifecycle(t *testing.T) {
	h := newHarness(t)

	// Day 0: first scan of app:prod -> digest A.
	h.image(ref, digestA,
		vuln("busybox", "1.36.0-r9", "CVE-2022-48174", model.SeverityCritical, "1.36.1-r1"),
		vuln("libcrypto3", "3.1.0-r4", "CVE-2024-6119", model.SeverityHigh, "3.1.7-r0"),
	)
	r := h.scan(ref)
	if r.Status != store.ScanComplete || r.Kind != "initial" || r.Created != 2 {
		t.Fatalf("first scan: %+v", r)
	}
	if h.fetch.fetches != 1 || h.syft.calls != 1 || h.trivyG.calls != 1 {
		t.Fatalf("fetch/generate counts: %d/%d/%d", h.fetch.fetches, h.syft.calls, h.trivyG.calls)
	}
	bb := h.finding("CVE-2022-48174", digestA)
	if bb.State != model.StateOpen || strings.Join(bb.Scanners, ",") != "grype,trivy" {
		t.Fatalf("busybox finding: %+v", bb)
	}

	// Day 1: unchanged tag -> SBOM-first rematch, no pull, no new findings.
	h.advance(24 * time.Hour)
	r = h.scan(ref)
	if r.Kind != "rematch" || r.Created != 0 || h.fetch.fetches != 1 || h.syft.calls != 1 {
		t.Fatalf("rematch must not pull or regenerate: %+v fetches=%d", r, h.fetch.fetches)
	}

	// A human triages the openssl finding; closing it by hand is refused.
	ssl := h.finding("CVE-2024-6119", digestA)
	if err := h.store.Transition(h.ctx, ssl.ID, model.StateTriaged, "alice", "base image bump planned", h.clock); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Transition(h.ctx, ssl.ID, model.StateFixed, "alice", "trust me", h.clock); err == nil {
		t.Fatal("manual close must be refused")
	}

	// Day 4: tag moves to digest B. busybox is fixed; libcrypto3 was bumped
	// but is still vulnerable.
	h.advance(72 * time.Hour)
	h.image(ref, digestB,
		vuln("busybox", "1.36.1-r1", "CVE-2099-0001", model.SeverityLow),
		vuln("libcrypto3", "3.1.4-r0", "CVE-2024-6119", model.SeverityHigh, "3.1.7-r0"),
	)
	r = h.scan(ref)
	if !r.DigestChange || r.PrevDigest != digestA || h.fetch.fetches != 2 {
		t.Fatalf("digest change not detected: %+v", r)
	}
	if r.Transitions[model.StateFixed] != 1 || r.Transitions[model.StateSuperseded] != 1 {
		t.Fatalf("transitions: %v", r.Transitions)
	}
	bb = h.finding("CVE-2022-48174", digestA)
	if bb.State != model.StateFixed || bb.ClosedAt.IsZero() {
		t.Fatalf("busybox must be fixed by evidence: %+v", bb)
	}
	evs, _ := h.store.Events(h.ctx, bb.ID)
	last := evs[len(evs)-1]
	if last.To != model.StateFixed || last.ScanID != r.ScanID || last.Actor != "engine" {
		t.Fatalf("fix event must cite the successor scan as evidence: %+v", last)
	}
	sslB := h.finding("CVE-2024-6119", digestB)
	if sslB.State != model.StateTriaged || sslB.PredecessorID != ssl.ID || !sslB.FirstDetected.Equal(ssl.FirstDetected) {
		t.Fatalf("successor must inherit triage and first detection: %+v", sslB)
	}
	if got := h.finding("CVE-2024-6119", digestA).State; got != model.StateSuperseded {
		t.Fatalf("predecessor state = %s, want superseded", got)
	}

	// Day 5: trivy fails. The scan is partial, a health finding opens (with
	// the secret redacted) and nothing is closed by absence.
	h.advance(24 * time.Hour)
	h.trivy.fail = true
	h.grype.vulns[digestB] = h.grype.vulns[digestB][:1] // grype alone stops reporting libcrypto3
	r = h.scan(ref)
	if r.Status != store.ScanPartial {
		t.Fatalf("status = %s, want partial", r.Status)
	}
	if got := h.finding("CVE-2024-6119", digestB).State; got != model.StateTriaged {
		t.Fatalf("partial scan closed a finding: %s", got)
	}
	hf := h.health(engine.CheckMatcher, "trivy")
	if hf == nil || hf.State != "open" {
		t.Fatalf("matcher failure must be a health finding: %+v", hf)
	}
	if strings.Contains(hf.Detail, "abc123secret") {
		t.Fatalf("health detail leaks a secret: %s", hf.Detail)
	}

	// Day 6: trivy recovers -> health finding resolves.
	h.advance(24 * time.Hour)
	h.trivy.fail = false
	h.grype.vulns[digestB] = h.trivy.vulns[digestB]
	r = h.scan(ref)
	if r.Status != store.ScanComplete {
		t.Fatalf("status = %s", r.Status)
	}
	if hf := h.health(engine.CheckMatcher, "trivy"); hf.State != "resolved" {
		t.Fatalf("health finding not resolved: %+v", hf)
	}

	// Day 7: grype's DB stops updating.
	h.advance(24 * time.Hour)
	h.grype.dbBuilt = h.clock.Add(-96 * time.Hour)
	h.scan(ref)
	if hf := h.health(engine.CheckDBStale, "grype"); hf == nil || hf.State != "open" {
		t.Fatalf("stale DB must open a health finding: %+v", hf)
	}

	// Day 8: regression. digest C reintroduces the old busybox CVE.
	h.advance(24 * time.Hour)
	h.image(ref, digestC,
		vuln("busybox", "1.36.0-r9", "CVE-2022-48174", model.SeverityCritical, "1.36.1-r1"),
		vuln("libcrypto3", "3.1.4-r0", "CVE-2024-6119", model.SeverityHigh, "3.1.7-r0"),
	)
	h.scan(ref)
	if got := h.finding("CVE-2022-48174", digestC).State; got != model.StateReopened {
		t.Fatalf("regression state = %s, want reopened", got)
	}

	// Unknown registry credentials -> auth health finding.
	if _, err := h.eng.Scan(h.ctx, "registry.test/private:1", model.Platform{OS: "linux", Architecture: "amd64"}); err == nil {
		t.Fatal("expected auth failure")
	}
	if hf := h.health(engine.CheckRegistryAuth, "registry.test"); hf == nil {
		t.Fatal("auth failure must be a health finding")
	}

	// The monthly report is derived from the audit trail.
	sla, _ := config.SLAProfile("commercial", nil)
	rep, err := report.BuildMonthly(h.ctx, h.store, report.MonthPeriod(h.clock), "commercial", sla, h.clock)
	if err != nil {
		t.Fatal(err)
	}
	s := rep.Summary
	if s.Opened != 3 || s.Fixed != 2 || s.Reopened != 1 || s.OpenAtStart != 0 {
		t.Errorf("summary: %+v", s)
	}
	// busybox: detected day 0, fixed day 4. CVE-2099-0001 (B only): day 4 -> day 8.
	if s.MTTRMeanDays != 4 || s.MTTRMedianDays != 4 {
		t.Errorf("MTTR = %.1f/%.1f, want 4/4", s.MTTRMeanDays, s.MTTRMedianDays)
	}
	// Open now: busybox regression + libcrypto3 (lineage from day 0).
	if s.OpenAtEnd != 2 || rep.OpenBySeverity["critical"] != 1 || rep.OpenBySeverity["high"] != 1 {
		t.Errorf("open at end = %d by severity %v", s.OpenAtEnd, rep.OpenBySeverity)
	}
	if len(rep.Burndown) != 9 {
		t.Errorf("burndown days = %d, want 9", len(rep.Burndown))
	}
	for _, f := range []string{"md", "json", "csv"} {
		var buf bytes.Buffer
		if err := report.Render(&buf, rep, f); err != nil || buf.Len() == 0 {
			t.Errorf("render %s: %v", f, err)
		}
	}
}

func TestRiskAcceptanceExpiresAndFollowsSuccessor(t *testing.T) {
	h := newHarness(t)
	h.image(ref, digestA, vuln("zlib", "1.2.13-r1", "CVE-2023-45853", model.SeverityCritical))
	h.scan(ref)
	f := h.finding("CVE-2023-45853", digestA)

	d := lifecycleDecision(h.clock.AddDate(0, 0, 10))
	policy, _ := config.Default().Policy()
	if _, err := h.store.ApplyDecision(h.ctx, f.ID, d, policy, h.clock); err != nil {
		t.Fatal(err)
	}
	// The tag moves; the accepted risk follows the problem to the new digest.
	h.advance(48 * time.Hour)
	h.image(ref, digestB, vuln("zlib", "1.2.13-r2", "CVE-2023-45853", model.SeverityCritical))
	h.scan(ref)
	fb := h.finding("CVE-2023-45853", digestB)
	sla, _ := config.SLAProfile("commercial", nil)
	rep, err := report.BuildMonthly(h.ctx, h.store, report.MonthPeriod(h.clock), "commercial", sla, h.clock)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.RiskAccepted != 1 || rep.Summary.Opened != 1 || len(rep.AcceptedRisks) != 1 {
		t.Fatalf("a carried-over decision is one acceptance, not two: %+v", rep.Summary)
	}
	if fb.State != model.StateRiskAccepted {
		t.Fatalf("successor state = %s, want risk_accepted", fb.State)
	}
	ds, _ := h.store.Decisions(h.ctx, fb.ID)
	if len(ds) != 1 || !ds[0].ExpiresAt.Equal(d.ExpiresAt) {
		t.Fatalf("decision must be carried with its expiry: %+v", ds)
	}

	// After expiry, the monitor cycle reopens it.
	h.advance(10 * 24 * time.Hour)
	sum, err := h.eng.Monitor(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.ExpiredDecision) != 1 || sum.ExpiredDecision[0] != fb.ID {
		t.Fatalf("expired = %v", sum.ExpiredDecision)
	}
	if got := h.finding("CVE-2023-45853", digestB).State; got != model.StateReopened {
		t.Fatalf("state after expiry = %s", got)
	}
}

func TestMonitorDetectsMissedSchedule(t *testing.T) {
	h := newHarness(t)
	h.image(ref, digestA)
	h.scan(ref)
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	h.advance(24 * time.Hour)
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if hf := h.health(engine.CheckMonitorMissed, "schedule"); hf != nil && hf.State == "open" {
		t.Fatal("on-schedule run flagged as missed")
	}
	h.advance(5 * 24 * time.Hour)
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if hf := h.health(engine.CheckMonitorMissed, "schedule"); hf == nil || hf.State != "open" {
		t.Fatal("5-day gap must open a monitor_missed health finding")
	}
}

func TestMonitorUpdatesDBsOfflineFromScanning(t *testing.T) {
	h := newHarness(t)
	h.image(ref, digestA, vuln("busybox", "1.36.0-r9", "CVE-2022-48174", model.SeverityCritical))
	h.scan(ref)
	h.grype.calls = nil

	// Unsandboxed: the cycle keeps a health finding open, DBs update with network
	// before matching, and matching has none.
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if hf := h.health(engine.CheckUnsandboxed, "scanners"); hf == nil || hf.State != "open" || hf.Severity != "high" {
		t.Fatalf("scanners without a sandbox must be a high health finding: %+v", hf)
	}
	if got := strings.Join(h.grype.calls, ","); got != "update+net,match" {
		t.Fatalf("grype calls = %s, want the DB update with network, then matching without", got)
	}

	// A failed update is a health finding (redacted), and the cycle still matches.
	h.advance(24 * time.Hour)
	h.eng.Sandboxed = true
	h.grype.updateFail = true
	sum, err := h.eng.Monitor(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Status != "ok" || len(sum.Results) != 1 || sum.Results[0].Status != store.ScanComplete {
		t.Fatalf("a failed DB update must not fail the cycle: %+v", sum)
	}
	hf := h.health(engine.CheckDBUpdate, "grype")
	if hf == nil || hf.State != "open" {
		t.Fatalf("failed DB update must be a health finding: %+v", hf)
	}
	if strings.Contains(hf.Detail, "hunter2") {
		t.Fatalf("health detail leaks a secret: %s", hf.Detail)
	}
	if hf := h.health(engine.CheckUnsandboxed, "scanners"); hf.State != "resolved" {
		t.Fatalf("sandboxed scanners must resolve scanner_unsandboxed: %+v", hf)
	}

	h.advance(24 * time.Hour)
	h.grype.updateFail = false
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if hf := h.health(engine.CheckDBUpdate, "grype"); hf.State != "resolved" {
		t.Fatalf("a successful DB update must resolve db_update_failed: %+v", hf)
	}
}

func TestMonitorReportsDegradedSandbox(t *testing.T) {
	h := newHarness(t)
	h.image(ref, digestA)
	h.scan(ref)
	h.eng.Sandboxed = true
	h.eng.SandboxDegraded = errors.New("without Landlock, a scanner can execute files it writes")
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if hf := h.health(engine.CheckSandboxDegraded, "scanners"); hf == nil || hf.State != "open" || hf.Severity != "medium" {
		t.Fatalf("a degraded sandbox must be a medium health finding: %+v", hf)
	}
	if hf := h.health(engine.CheckUnsandboxed, "scanners"); hf != nil && hf.State == "open" {
		t.Fatalf("a degraded sandbox is still a sandbox: %+v", hf)
	}

	h.advance(24 * time.Hour)
	h.eng.SandboxDegraded = nil
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if hf := h.health(engine.CheckSandboxDegraded, "scanners"); hf.State != "resolved" {
		t.Fatalf("full guarantees must resolve scanner_sandbox_degraded: %+v", hf)
	}
}

func TestRematchNeedsNoRegistry(t *testing.T) {
	h := newHarness(t)
	h.image(ref, digestA, vuln("busybox", "1.36.0-r9", "CVE-2022-48174", model.SeverityCritical))
	h.scan(ref)
	delete(h.fetch.tags, ref) // registry unreachable
	r, err := h.eng.Rematch(h.ctx, digestA)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != store.ScanComplete || r.Matches != 1 || h.fetch.fetches != 1 {
		t.Fatalf("rematch: %+v fetches=%d", r, h.fetch.fetches)
	}
}

func TestCarryOverIsNotCountedAsNew(t *testing.T) {
	h := newHarness(t)
	h.image(ref, digestA, vuln("zlib", "1.2.13-r1", "CVE-2023-45853", model.SeverityCritical))
	h.scan(ref)
	h.advance(24 * time.Hour)
	h.image(ref, digestB, vuln("zlib", "1.2.13-r2", "CVE-2023-45853", model.SeverityCritical))
	if r := h.scan(ref); r.Created != 0 || r.Carried != 1 {
		t.Fatalf("scan result must report a carry-over, not a new finding: created=%d carried=%d", r.Created, r.Carried)
	}
	if got := h.finding("CVE-2023-45853", digestB); got.State != model.StateOpen || got.PredecessorID == 0 {
		t.Fatalf("successor = %+v", got)
	}
	sla, _ := config.SLAProfile("commercial", nil)
	rep, err := report.BuildMonthly(h.ctx, h.store, report.MonthPeriod(h.clock), "commercial", sla, h.clock)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Opened != 1 || rep.Summary.OpenAtEnd != 1 || rep.Summary.Fixed != 0 {
		t.Fatalf("one problem across two digests must count once: %+v", rep.Summary)
	}
}
