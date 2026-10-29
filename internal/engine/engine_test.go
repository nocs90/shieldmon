package engine_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/enrich"
	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/scanner"
	"github.com/nocs90/shieldmon/internal/store"
	"github.com/nocs90/shieldmon/internal/vex"
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

// fakeGenerator writes a minimal SBOM that records the digest it describes. With pad > 0
// the file is extended to pad bytes (sparse: no disk is used).
type fakeGenerator struct {
	name  string
	calls int
	pad   int64
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
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return nil, err
	}
	if g.pad > 0 {
		if err := os.Truncate(p, g.pad); err != nil {
			return nil, err
		}
	}
	return []scanner.SBOMFile{{Format: scanner.FormatCycloneDXJSON, Path: p}}, nil
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
	return newHarnessAt(t, ":memory:")
}

// newHarnessAt is newHarness with the database at path (a file, for tests that open it
// again, as an attacker with the file would).
func newHarnessAt(t *testing.T, path string) *harness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, path)
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
	sla, err := config.SLAProfile("standard", nil)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := report.BuildMonthly(h.ctx, h.store, report.MonthPeriod(h.clock), "standard", sla, h.clock)
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

	// Day 9: a vendor VEX statement for the whole repository; the next scan makes the open
	// libcrypto3 finding not_affected, by the vendor, through a decision.
	h.advance(24 * time.Hour)
	_, err = h.store.AddVEXStatements(h.ctx, []vex.Statement{{
		VulnID: "CVE-2024-6119", Repository: "registry.test/app", PURL: "pkg:apk/alpine/libcrypto3", AnyVersion: true,
		Justification: "vulnerable_code_not_in_execute_path", Author: "Vendor PSIRT", Timestamp: h.clock,
	}}, "tester", h.clock)
	if err != nil {
		t.Fatal(err)
	}
	if r := h.scan(ref); r.NotAffectedByVEX != 1 {
		t.Fatalf("the scan must apply the statement: %+v", r)
	}
	if f := h.finding("CVE-2024-6119", digestC); f.State != model.StateNotAffected {
		t.Fatalf("state after the VEX statement = %s", f.State)
	}

	// Day 10: the image is decommissioned (ADR 0017). Monitoring stops, the busybox regression
	// keeps its state but leaves the open numbers; restoring brings it back as it was.
	h.advance(24 * time.Hour)
	tgs, err := h.store.TargetsByRef(h.ctx, ref)
	if err != nil || len(tgs) != 1 {
		t.Fatal(tgs, err)
	}
	if err := h.eng.RetireTarget(h.ctx, tgs[0], "platform-team", "decommissioned in CHG-2041"); err != nil {
		t.Fatal(err)
	}
	h.fetch.tags[ref] = digestA // the tag moves, but nobody looks any more
	if sum, err := h.eng.Monitor(h.ctx); err != nil || len(sum.Results) != 0 || len(sum.Failures) != 0 || sum.Status != "ok" {
		t.Fatalf("monitor must skip a retired target, not fail on it: %+v %v", sum, err)
	}
	if _, err := h.eng.Scan(h.ctx, ref, model.Platform{OS: "linux", Architecture: "amd64"}); !errors.Is(err, engine.ErrRetiredTarget) {
		t.Fatalf("scanning a retired target: %v", err)
	}
	if tg, _ := h.store.GetTarget(h.ctx, tgs[0].ID); tg.CurrentDigest != digestC {
		t.Fatalf("a retired target is not resolved: %s", tg.CurrentDigest)
	}
	if f := h.finding("CVE-2022-48174", digestC); f.State != model.StateReopened {
		t.Fatalf("retirement must not change findings: %s", f.State)
	}
	rep, err = report.BuildMonthly(h.ctx, h.store, report.MonthPeriod(h.clock), "standard", sla, h.clock)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.OpenAtEnd != 0 || rep.Summary.RetiredWithAsset != 1 || rep.Summary.Fixed != 2 ||
		rep.Burndown[len(rep.Burndown)-1].Open != 0 || rep.Burndown[len(rep.Burndown)-2].Open != 1 {
		t.Fatalf("retired with the image: out of the open numbers, not fixed: %+v %v", rep.Summary, rep.Burndown)
	}
	if err := h.eng.RestoreTarget(h.ctx, tgs[0], "platform-team", "back in production"); err != nil {
		t.Fatal(err)
	}
	rep, err = report.BuildMonthly(h.ctx, h.store, report.MonthPeriod(h.clock), "standard", sla, h.clock)
	if err != nil || rep.Summary.OpenAtEnd != 1 || rep.Summary.RetiredWithAsset != 0 {
		t.Fatalf("a restored image's findings are open again: %+v %v", rep.Summary, err)
	}
}

// TestVEXStatements covers docs/adr/0014-vex.md: statements are stored once, apply now and to
// findings later scans detect, once per finding, and statements for images not scanned yet
// are kept.
func TestVEXStatements(t *testing.T) {
	h := newHarness(t)
	h.image(ref, digestA,
		vuln("busybox", "1.36.0-r9", "CVE-2022-48174", model.SeverityCritical),
		vuln("zlib", "1.2.13-r1", "CVE-2023-45853", model.SeverityCritical))
	h.scan(ref)

	stmts := []vex.Statement{
		// Every build of the repository, any busybox version.
		{
			VulnID: "CVE-2022-48174", Repository: "registry.test/app", PURL: "pkg:apk/alpine/busybox", AnyVersion: true,
			Justification: "vulnerable_code_not_in_execute_path", Author: "Vendor PSIRT", Timestamp: h.clock,
		},
		// A digest not scanned yet.
		{
			VulnID: "CVE-2024-9999", Digest: digestB, Repository: "registry.test/app",
			Justification: "component_not_present", Author: "Vendor PSIRT", Timestamp: h.clock,
		},
		// Expired: never applies.
		{
			VulnID: "CVE-2023-45853", Digest: digestA, Repository: "registry.test/app", Justification: "component_not_present",
			Author: "Vendor PSIRT", Timestamp: h.clock.Add(-48 * time.Hour), ExpiresAt: h.clock.Add(-time.Hour),
		},
	}
	for _, c := range []struct {
		label string
		want  int
	}{{"first import", 3}, {"same statements again", 0}} {
		if n, err := h.store.AddVEXStatements(h.ctx, stmts, "importer", h.clock); err != nil || n != c.want {
			t.Fatalf("%s: %d new, want %d (%v)", c.label, n, c.want, err)
		}
	}
	applied, err := h.store.ApplyVEX(h.ctx, "", h.eng.Decisions, h.clock)
	if err != nil || len(applied) != 1 {
		t.Fatalf("applied = %+v, %v", applied, err)
	}
	if f := h.finding("CVE-2022-48174", digestA); f.State != model.StateNotAffected {
		t.Fatalf("busybox = %s, want not_affected", f.State)
	}
	if f := h.finding("CVE-2023-45853", digestA); f.State != model.StateOpen {
		t.Fatalf("an expired statement must not apply: zlib = %s", f.State)
	}
	ds, err := h.store.Decisions(h.ctx, h.finding("CVE-2022-48174", digestA).ID)
	if err != nil || len(ds) != 1 || ds[0].Author != "Vendor PSIRT" || !strings.Contains(ds[0].Justification, "VEX statement #1") {
		t.Fatalf("the decision must name its author and statement: %+v %v", ds, err)
	}
	if again, _ := h.store.ApplyVEX(h.ctx, "", h.eng.Decisions, h.clock); len(again) != 0 {
		t.Errorf("a statement applies once per finding: %+v", again)
	}
	if unknown, _ := h.store.VEXUnknownProducts(h.ctx, h.clock); len(unknown) != 1 || unknown[0].Digest != digestB {
		t.Errorf("the statement for digest B must be kept and reported: %+v", unknown)
	}

	// The next build brings CVE-2024-9999: the kept statement now applies, during the scan.
	h.advance(24 * time.Hour)
	h.image(ref, digestB,
		vuln("busybox", "1.36.0-r9", "CVE-2022-48174", model.SeverityCritical),
		vuln("openssl", "3.1.0-r0", "CVE-2024-9999", model.SeverityHigh),
		vuln("curl", "8.4.0-r0", "CVE-2024-1111", model.SeverityMedium))
	r := h.scan(ref)
	if f := h.finding("CVE-2024-9999", digestB); f.State != model.StateNotAffected || r.NotAffectedByVEX < 1 {
		t.Fatalf("a statement for a digest scanned later must apply in that scan: %s, %+v", f.State, r)
	}
	if unknown, _ := h.store.VEXUnknownProducts(h.ctx, h.clock); len(unknown) != 0 {
		t.Errorf("no statement is pending once its digest is scanned: %+v", unknown)
	}

	// Only decisions taken by hand are exported as such: the busybox decision carried to
	// digest B still comes from the statement.
	if manual, err := h.store.ManualNotAffected(h.ctx, h.clock); err != nil || len(manual) != 0 {
		t.Fatalf("no manual decision yet: %+v %v", manual, err)
	}
	curl := h.finding("CVE-2024-1111", digestB)
	if _, err := h.store.ApplyDecision(h.ctx, curl.ID, lifecycle.Decision{
		State: model.StateNotAffected, Justification: "component_not_present: curl is not on any code path", Author: "alice",
	}, h.eng.Decisions, h.clock); err != nil {
		t.Fatal(err)
	}
	manual, err := h.store.ManualNotAffected(h.ctx, h.clock)
	if err != nil || len(manual) != 1 {
		t.Fatalf("manual decisions = %+v %v", manual, err)
	}
	if m := manual[0]; m.Digest != digestB || m.PURL != curl.PURL || m.Justification != "component_not_present" ||
		m.Impact != "curl is not on any code path" || m.Author != "alice" {
		t.Errorf("manual decision as a statement = %+v", m)
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
	sla, err := config.SLAProfile("standard", nil)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := report.BuildMonthly(h.ctx, h.store, report.MonthPeriod(h.clock), "standard", sla, h.clock)
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

// TestGiantSBOMIsRejected is the hostile fixture suite's giant-SBOM case (#10): an SBOM over
// the size limit is never parsed or stored, and the generator gets a health finding.
func TestGiantSBOMIsRejected(t *testing.T) {
	h := newHarness(t)
	h.syft.pad = 256<<20 + 1
	h.image(ref, digestA)
	r := h.scan(ref)
	if slices.Contains(r.SBOMsCreated, "syft") {
		t.Fatalf("an oversized SBOM must not be stored: %+v", r)
	}
	if sboms, _ := h.store.SBOMs(h.ctx, digestA); slices.ContainsFunc(sboms, func(s store.SBOM) bool { return s.Generator == "syft" }) {
		t.Fatal("an oversized SBOM was recorded")
	}
	if hf := h.health(engine.CheckGenerator, "syft"); hf == nil || hf.State != "open" || !strings.Contains(hf.Detail, "exceeds") {
		t.Fatalf("an oversized SBOM must open sbom_generator_failed naming the limit: %+v", hf)
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
	sla, err := config.SLAProfile("standard", nil)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := report.BuildMonthly(h.ctx, h.store, report.MonthPeriod(h.clock), "standard", sla, h.clock)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Opened != 1 || rep.Summary.OpenAtEnd != 1 || rep.Summary.Fixed != 0 {
		t.Fatalf("one problem across two digests must count once: %+v", rep.Summary)
	}
}

// recordingNotifier records what a channel was sent; it fails while err is set.
type recordingNotifier struct {
	msgs []notify.Message
	err  error
}

func (n *recordingNotifier) Send(_ context.Context, m notify.Message) error {
	if n.err != nil {
		return n.err
	}
	n.msgs = append(n.msgs, m)
	return nil
}

// sent returns "kind subject" for every event sent so far, in order.
func (n *recordingNotifier) sent() []string {
	var out []string
	for _, m := range n.msgs {
		for _, e := range m.Events {
			what := ""
			switch {
			case e.Finding != nil:
				what = e.Finding.VulnID
			case e.Health != nil:
				what = e.Health.Check + "/" + e.Health.Subject
			}
			out = append(out, string(e.Kind)+" "+what)
		}
	}
	return out
}

func (h *harness) monitor() engine.MonitorSummary {
	h.t.Helper()
	sum, err := h.eng.Monitor(h.ctx)
	if err != nil && sum.Status == "" {
		h.t.Fatalf("monitor: %v", err)
	}
	return sum
}

// TestNotificationsAfterMonitor follows notifications across cycles (docs/adr/0015-
// notifications.md): new KEV and critical findings, deadlines, health findings; each event
// once per channel, digests, a failing channel catching up, a channel added later.
func TestNotificationsAfterMonitor(t *testing.T) {
	h := newHarness(t)
	sla, err := config.SLAProfile("standard", nil)
	if err != nil {
		t.Fatal(err)
	}
	h.eng.Decisions = lifecycle.Policy{Profile: "standard", SLADays: sla}
	h.eng.DueSoon = 7 * 24 * time.Hour
	// No scanner_unsandboxed or monitor_missed health finding in this scenario.
	h.eng.Sandboxed, h.eng.MonitorInterval = true, 0
	all, dig, fixes := &recordingNotifier{}, &recordingNotifier{}, &recordingNotifier{}
	h.eng.Channels = []notify.Channel{
		{Name: "all", Kinds: notify.DefaultKinds, Sender: all},
		{Name: "dig", Kinds: []notify.Kind{notify.FindingNewKEV, notify.HealthOpened}, Digest: true, Sender: dig},
		{Name: "fixes", Kinds: []notify.Kind{notify.FindingFixed}, Sender: fixes},
	}
	xz := vuln("xz-libs", "5.6.0", "CVE-2024-3094", model.SeverityCritical, "5.6.1")
	xz.KEV = true
	zlib := vuln("zlib", "1.2.13-r0", "CVE-2023-45853", model.SeverityHigh, "1.2.13-r1")
	h.image(ref, digestA, xz, zlib)
	h.scan(ref)

	// Day 0: the KEV finding (not also "new critical": KEV wins); the high one is not news.
	if sum := h.monitor(); sum.Status != "ok" || sum.Notified["all"] != 1 {
		t.Fatalf("first cycle: %+v", sum)
	}
	if got := all.sent(); !slices.Equal(got, []string{"finding_new_kev CVE-2024-3094"}) {
		t.Fatalf("all got %q", got)
	}
	if len(dig.msgs) != 1 || !dig.msgs[0].Digest {
		t.Fatalf("dig gets one digest: %+v", dig.msgs)
	}

	// Day 1: nothing new, nothing sent again.
	h.advance(24 * time.Hour)
	if sum := h.monitor(); len(sum.Notified) != 0 || len(all.msgs) != 1 || len(dig.msgs) != 1 {
		t.Fatalf("an event is sent once per channel: %+v", sum.Notified)
	}

	// Day 2: a new digest brings a critical finding while "all" is down: its event waits, the
	// cycle is degraded, and notify_failed opens without the credential in its detail.
	h.advance(24 * time.Hour)
	curl := vuln("curl", "8.5.0-r0", "CVE-2024-2398", model.SeverityCritical, "8.7.1-r0")
	h.image(ref, digestB, xz, zlib, curl)
	all.err = errors.New("POST hooks.example.com: answered 503; Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
	sum := h.monitor()
	if sum.Status != "degraded" || sum.NotifyFailures["all"] == "" {
		t.Fatalf("a failing channel degrades the cycle: %+v", sum)
	}
	hf := h.health(engine.CheckNotify, "all")
	if hf == nil || hf.State != "open" || strings.Contains(hf.Detail, "abcdefghijklmnop") || !strings.Contains(hf.Detail, "1 event(s) wait") {
		t.Fatalf("notify_failed = %+v", hf)
	}
	if len(dig.msgs) != 1 {
		t.Fatal("a carried-over KEV finding is not new; a new critical one is not for dig")
	}

	// Day 3: "all" is back and catches up; both channels hear of the notify_failed finding
	// open at the start of the cycle; it resolves.
	h.advance(24 * time.Hour)
	all.err = nil
	if sum := h.monitor(); sum.Status != "ok" {
		t.Fatalf("recovered cycle: %+v", sum)
	}
	if got := all.sent()[1:]; !slices.Equal(got, []string{"finding_new_critical CVE-2024-2398", "health_opened notify_failed/all"}) {
		t.Fatalf("all caught up with %q", got)
	}
	if got := dig.sent()[1:]; !slices.Equal(got, []string{"health_opened notify_failed/all"}) {
		t.Fatalf("dig got %q", got)
	}
	if hf := h.health(engine.CheckNotify, "all"); hf.State != "resolved" {
		t.Fatal("a successful send resolves notify_failed")
	}

	// Day 24: within 7 days of the 30-day deadline of the problems first seen on day 0, not
	// yet of curl's (day 32); each once, by lineage (the findings moved to digest B on day 2).
	n := len(all.msgs)
	h.advance(21 * 24 * time.Hour)
	h.monitor()
	h.monitor()
	if got := all.sent()[n:]; !slices.Equal(got, []string{"sla_due_soon CVE-2024-3094", "sla_due_soon CVE-2023-45853"}) {
		t.Fatalf("due soon: %q", got)
	}
	for _, m := range all.msgs[n:] {
		if f := m.Events[0].Finding; f.Digest != digestB {
			t.Errorf("events show the lineage's current finding, got digest %s", f.Digest)
		}
	}

	// Day 31: the day-0 deadlines passed, curl's is due soon. A channel added now hears only
	// from now on: no backlog of the due-soon events sent before.
	late := &recordingNotifier{}
	h.eng.Channels = append(h.eng.Channels, notify.Channel{Name: "late", Kinds: notify.DefaultKinds, Sender: late})
	h.advance(7 * 24 * time.Hour)
	if pending, err := h.eng.PendingNotifications(h.ctx); err != nil || len(pending["all"]) != 3 || len(pending["late"]) != 3 {
		t.Fatalf("preview shows what the cycle will send: %v %+v", err, pending)
	}
	h.monitor()
	want := []string{"sla_breached CVE-2024-3094", "sla_breached CVE-2023-45853", "sla_due_soon CVE-2024-2398"}
	if got := late.sent(); !slices.Equal(got, want) {
		t.Fatalf("late got %q", got)
	}
	if got := all.sent()[len(all.sent())-3:]; !slices.Equal(got, want) {
		t.Fatalf("all got %q", got)
	}
	if pending, err := h.eng.PendingNotifications(h.ctx); err != nil || len(pending["all"])+len(pending["late"]) != 0 {
		t.Fatalf("nothing pending after sending: %v %+v", err, pending)
	}

	// Day 32: curl's deadline passes, but the image is fixed in the same cycle: nothing about
	// fixed problems is sent.
	h.advance(24 * time.Hour)
	h.image(ref, digestC)
	sent := len(all.sent())
	h.monitor()
	if got := all.sent()[sent:]; len(got) != 0 {
		t.Fatalf("nothing about fixed problems: %q", got)
	}

	// Only a channel that asks for finding_fixed hears of the fixes, with the target whose
	// scan gave the evidence and nothing of the vulnerability left in it.
	got := fixes.sent()
	slices.Sort(got)
	if !slices.Equal(got, []string{"finding_fixed CVE-2023-45853", "finding_fixed CVE-2024-2398", "finding_fixed CVE-2024-3094"}) {
		t.Fatalf("fixes got %q", got)
	}
	for _, m := range fixes.msgs {
		e := m.Events[0]
		if e.Remaining != 0 || !slices.Equal(e.Finding.Targets, []string{ref + " (linux/amd64)"}) || e.Finding.State != "fixed" {
			t.Errorf("fixed event %+v %+v", e, e.Finding)
		}
	}
}

// TestInventoryReflectsEvidence builds the inventory from real scans: a fully evidenced
// image, one whose last scan was partial, one whose evidence went stale, a rebuild counted.
func TestInventoryReflectsEvidence(t *testing.T) {
	h := newHarness(t)
	const app, api, old = "registry.test/app:prod", "registry.test/api:1", "registry.test/old:1"
	h.image(app, digestA, vuln("zlib", "1.2.13-r0", "CVE-2023-45853", model.SeverityCritical))
	h.image(old, digestC)
	h.scan(app)
	h.scan(old)

	h.advance(3 * 24 * time.Hour)
	h.image(app, digestB, vuln("zlib", "1.2.13-r0", "CVE-2023-45853", model.SeverityCritical))
	h.scan(app)
	h.image(api, digestC) // the same digest as old: one digest, two images
	h.trivy.fail = true
	h.scan(api)
	h.trivy.fail = false

	inv, err := report.BuildInventory(h.ctx, h.store, report.InventoryOptions{
		Now: h.clock, StaleAfter: 36 * time.Hour, Generators: []string{"syft", "trivy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	byRef := map[string]report.Image{}
	for _, img := range inv.Images {
		byRef[img.Ref] = img
	}
	if a := byRef[app]; a.Digest != digestB || a.DigestChanges != 1 || len(a.Gaps) != 0 || a.Open["critical"] != 1 ||
		len(a.SBOMs) != 2 || a.LastScan == nil || a.LastScan.Status != "complete" || len(a.LastScan.Tools) != 2 {
		t.Errorf("app: %+v", a)
	}
	// api and old share digest C: its last scan (api's) was partial, and its last complete
	// scan (old's, three days ago) is stale for both.
	for _, ref := range []string{api, old} {
		if got := strings.Join(byRef[ref].Gaps, ","); got != "last_scan_partial,stale_evidence" {
			t.Errorf("%s gaps = %q", ref, got)
		}
	}
	if inv.Summary.Targets != 3 || inv.Summary.Digests != 2 || inv.Summary.WithGaps != 2 || inv.Summary.Open["critical"] != 1 {
		t.Errorf("summary %+v", inv.Summary)
	}
}

// TestReadSBOMChecksIntegrity: a stored SBOM is read back only if it is the file the scan
// recorded.
func TestReadSBOMChecksIntegrity(t *testing.T) {
	h := newHarness(t)
	h.image(ref, digestA)
	h.scan(ref)
	list, err := h.store.SBOMs(h.ctx, digestA)
	if err != nil || len(list) == 0 {
		t.Fatal(list, err)
	}
	b := list[0]
	if data, err := h.eng.ReadSBOM(b, 1<<20); err != nil || !strings.Contains(string(data), "CycloneDX") {
		t.Fatalf("intact SBOM: %v", err)
	}
	if _, err := h.eng.ReadSBOM(b, 10); err == nil {
		t.Error("the size limit applies")
	}
	path := filepath.Join(h.eng.DataDir, b.Path)
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(orig, []byte("CycloneDX"), []byte("CycloneDY"), 1)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.eng.ReadSBOM(b, 1<<20); err == nil || !strings.Contains(err.Error(), "changed after the scan") {
		t.Errorf("same size, other content: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hosts", path); err != nil {
		t.Fatal(err)
	}
	if _, err := h.eng.ReadSBOM(b, 1<<20); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("symlink: %v", err)
	}
	b.Path = "../outside.json"
	if _, err := h.eng.ReadSBOM(b, 1<<20); err == nil || !strings.Contains(err.Error(), "outside the data directory") {
		t.Errorf("path outside: %v", err)
	}
}

// TestRetiredImagesAreNotNotified: a decommissioned image's open findings raise no deadline
// events (ADR 0017); restored, they do again.
func TestRetiredImagesAreNotNotified(t *testing.T) {
	h := newHarness(t)
	sla, err := config.SLAProfile("standard", nil)
	if err != nil {
		t.Fatal(err)
	}
	h.eng.Decisions = lifecycle.Policy{Profile: "standard", SLADays: sla}
	h.eng.DueSoon = 7 * 24 * time.Hour
	h.eng.Channels = []notify.Channel{{Name: "all", Kinds: notify.DefaultKinds, Sender: &recordingNotifier{}}}
	h.image(ref, digestA, vuln("zlib", "1.2.13-r0", "CVE-2023-45853", model.SeverityHigh, "1.2.13-r1"))
	h.scan(ref)
	h.advance(40 * 24 * time.Hour) // past the 30-day deadline
	tgs, _ := h.store.TargetsByRef(h.ctx, ref)
	if err := h.eng.RetireTarget(h.ctx, tgs[0], "ops", "decommissioned in CHG-7"); err != nil {
		t.Fatal(err)
	}
	pending, err := h.eng.PendingNotifications(h.ctx)
	if err != nil || len(pending["all"]) != 0 {
		t.Fatalf("no deadline events for a retired image: %+v %v", pending, err)
	}
	if err := h.eng.RestoreTarget(h.ctx, tgs[0], "ops", "back in production"); err != nil {
		t.Fatal(err)
	}
	pending, err = h.eng.PendingNotifications(h.ctx)
	if err != nil || len(pending["all"]) != 1 || pending["all"][0].Kind != notify.SLABreached {
		t.Fatalf("restored, the breach is news again: %+v %v", pending, err)
	}
}

// TestInventoryChanges: images added, rebuilt (with the scan of the new digest), retired and
// restored in a month, from append-only history: the same answer later.
func TestInventoryChanges(t *testing.T) {
	h := newHarness(t) // 2026-10-01
	const api = "registry.test/api:1"
	h.image(ref, digestA)
	h.scan(ref)
	h.advance(5 * 24 * time.Hour)
	h.image(api, digestC)
	h.scan(api)
	h.advance(5 * 24 * time.Hour)
	h.image(ref, digestB)
	h.scan(ref)
	h.advance(5 * 24 * time.Hour)
	tgs, _ := h.store.TargetsByRef(h.ctx, api)
	if err := h.eng.RetireTarget(h.ctx, tgs[0], "ops", "decommissioned in CHG-9"); err != nil {
		t.Fatal(err)
	}
	october := report.MonthPeriod(h.clock)
	before, err := report.BuildChanges(h.ctx, h.store, october)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Added) != 2 || len(before.Retired) != 1 || before.Retired[0].Actor != "ops" || len(before.Restored) != 0 {
		t.Fatalf("october changes: %+v", before)
	}
	if len(before.Rebuilt) != 1 {
		t.Fatalf("one rebuild: %+v", before.Rebuilt)
	}
	rb := before.Rebuilt[0]
	if rb.From != digestA || rb.To != digestB || rb.Scan == nil || rb.Scan.Kind != "initial" || rb.Scan.Status != "complete" {
		t.Errorf("rebuild with the scan of the new digest: %+v %+v", rb, rb.Scan)
	}

	// November: restored. October's changes do not move.
	h.advance(20 * 24 * time.Hour)
	if err := h.eng.RestoreTarget(h.ctx, tgs[0], "ops", "back in production"); err != nil {
		t.Fatal(err)
	}
	after, err := report.BuildChanges(h.ctx, h.store, october)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Errorf("past changes are reproducible:\n before %+v\n after  %+v", before, after)
	}
	november, err := report.BuildChanges(h.ctx, h.store, report.MonthPeriod(h.clock))
	if err != nil || len(november.Restored) != 1 || len(november.Added)+len(november.Rebuilt)+len(november.Retired) != 0 {
		t.Errorf("november changes: %+v", november)
	}
	rep, err := report.BuildMonthly(h.ctx, h.store, october, "standard", nil, h.clock)
	if err != nil || len(rep.InventoryChanges.Rebuilt) != 1 {
		t.Fatalf("the monthly report carries the changes: %v", err)
	}
	var md bytes.Buffer
	if err := report.Render(&md, rep, "md"); err != nil || !strings.Contains(md.String(), "## Inventory changes (2026-10-01 to 2026-10-31)") ||
		!strings.Contains(md.String(), "decommissioned in CHG-9") {
		t.Errorf("markdown section: %v\n%s", err, md.String())
	}
}

// TestAuditChainIsVerifiedByMonitor covers docs/adr/0018-audit-chain.md: monitor verifies
// the chain on schedule; a decision edited behind ShieldMon's back opens audit_chain_broken;
// an exported digest survives normal operation.
func TestAuditChainIsVerifiedByMonitor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shieldmon.db")
	h := newHarnessAt(t, path)
	h.eng.AuditVerifyInterval = 24 * time.Hour
	h.image(ref, digestA, vuln("zlib", "1.2.13-r0", "CVE-2023-45853", model.SeverityCritical))
	h.scan(ref)
	f := h.finding("CVE-2023-45853", digestA)
	if _, err := h.store.ApplyDecision(h.ctx, f.ID, lifecycleDecision(h.clock.AddDate(0, 0, 10)), lifecycle.Policy{}, h.clock); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SealAudit(h.ctx); err != nil {
		t.Fatal(err)
	}
	exported, err := h.store.AuditHead(h.ctx)
	if err != nil || exported.Seq == 0 {
		t.Fatal(exported, err)
	}
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if hf := h.health(engine.CheckAuditChain, "database"); hf != nil && hf.State == "open" {
		t.Fatalf("an untouched trail verifies: %+v", hf)
	}

	// Someone with the database file rewrites the justification.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`DROP TRIGGER decisions_no_update`,
		`UPDATE decisions SET justification = 'accepted long ago, nothing to see here'`,
	} {
		if _, err := db.ExecContext(h.ctx, q); err != nil {
			t.Fatal(q, err)
		}
	}
	h.advance(time.Hour) // within the interval: not verified again yet
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if hf := h.health(engine.CheckAuditChain, "database"); hf != nil && hf.State == "open" {
		t.Fatal("verification follows audit_verify_interval")
	}
	h.advance(24 * time.Hour)
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	hf := h.health(engine.CheckAuditChain, "database")
	if hf == nil || hf.State != "open" || hf.Severity != "critical" || !strings.Contains(hf.Detail, "row_changed") {
		t.Fatalf("tampering opens audit_chain_broken: %+v", hf)
	}
	r, err := h.eng.VerifyAudit(h.ctx, []store.AuditDigest{exported})
	if err != nil || r.OK() || r.Digests != 1 {
		t.Fatalf("verify: %+v %v", r, err)
	}
}

// fakeEnricher marks the IDs in kev; Update fails while fail is set.
type fakeEnricher struct {
	kev  map[string]bool
	at   time.Time
	now  func() time.Time
	fail bool
}

func (f *fakeEnricher) Update(context.Context) error {
	if f.fail {
		return errors.New("GET www.cisa.gov: answered 503 Service Unavailable")
	}
	f.at = f.now()
	return nil
}
func (f *fakeEnricher) UpdatedAt() time.Time { return f.at }
func (f *fakeEnricher) Enrich(m *model.Match) {
	if f.kev[m.VulnID] {
		m.KEV = true
	}
}

// TestEnrichersFollowEveryCycle: KEV comes from the catalog whatever the scanners say, and a
// CVE added to it is flagged at the next cycle; update failures and old data are health
// findings (docs/adr/0019-enrichers.md).
func TestEnrichersFollowEveryCycle(t *testing.T) {
	h := newHarness(t)
	kev := &fakeEnricher{kev: map[string]bool{"CVE-2024-3094": true}, now: func() time.Time { return h.clock }}
	h.eng.Enrichers = []enrich.Instance{{Name: "kev", MaxAge: 72 * time.Hour, Enricher: kev}}
	h.image(ref, digestA,
		vuln("xz-libs", "5.6.0", "CVE-2024-3094", model.SeverityCritical, "5.6.1"),
		vuln("zlib", "1.2.13-r0", "CVE-2023-45853", model.SeverityCritical))
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	h.scan(ref)
	if !h.finding("CVE-2024-3094", digestA).KEV || h.finding("CVE-2023-45853", digestA).KEV {
		t.Fatal("KEV from the catalog, not from the scanners")
	}

	// CISA adds the zlib CVE; the next cycle's rematch flags the existing finding.
	h.advance(24 * time.Hour)
	kev.kev["CVE-2023-45853"] = true
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if !h.finding("CVE-2023-45853", digestA).KEV {
		t.Fatal("a CVE added to the catalog is flagged at the next cycle")
	}

	// The catalog cannot be fetched: matching goes on with the data on disk until it is too old.
	kev.fail = true
	h.advance(24 * time.Hour)
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if hf := h.health(engine.CheckEnrichUpdate, "kev"); hf == nil || hf.State != "open" {
		t.Fatalf("update failure: %+v", hf)
	}
	if hf := h.health(engine.CheckEnrichStale, "kev"); hf != nil && hf.State == "open" {
		t.Fatal("one day old: not stale yet")
	}
	h.advance(3 * 24 * time.Hour)
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	if hf := h.health(engine.CheckEnrichStale, "kev"); hf == nil || hf.State != "open" || hf.Severity != "high" {
		t.Fatalf("stale after max_age: %+v", hf)
	}
	kev.fail = false
	h.advance(time.Hour)
	if _, err := h.eng.Monitor(h.ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{engine.CheckEnrichUpdate, engine.CheckEnrichStale} {
		if hf := h.health(c, "kev"); hf.State != "resolved" {
			t.Errorf("%s resolves once the catalog updates: %+v", c, hf)
		}
	}
}
