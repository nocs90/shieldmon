package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/normalize"
	"github.com/nocs90/shieldmon/internal/priority"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/store"
)

type fixture struct {
	srv      *httptest.Server
	st       *store.Store
	tokens   map[string]string // role -> secret
	finding  int64
	triggers int
	running  bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "shieldmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Now().UTC()
	digest := "sha256:" + strings.Repeat("d", 64)
	if err := st.UpsertArtifact(ctx, store.Artifact{Digest: digest, Repository: "registry.test/app", Platform: "linux/amd64"}, now); err != nil {
		t.Fatal(err)
	}
	scan, err := st.CreateScan(ctx, digest, 0, "initial", now)
	if err != nil {
		t.Fatal(err)
	}
	raw := []model.RawMatch{{
		VulnID: "CVE-2023-45853", PURL: "pkg:apk/alpine/zlib@1.2.13-r0", PkgName: "zlib", PkgVersion: "1.2.13-r0",
		Severity: model.SeverityCritical, FixVersions: []string{"1.2.13-r1"}, Scanner: "grype",
	}}
	if _, err := st.ReconcileScan(ctx, store.ReconcileArgs{ScanID: scan, Digest: digest, Matches: normalize.Merge(raw), Complete: true, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(ctx, scan, store.ScanComplete, []model.Tool{{Name: "grype", Version: "0.99.0", DBBuilt: now}}, "", now); err != nil {
		t.Fatal(err)
	}
	fs, err := st.ListFindings(ctx, store.FindingFilter{})
	if err != nil || len(fs) != 1 {
		t.Fatalf("seed: %v %v", fs, err)
	}
	sla, _ := config.SLAProfile("standard", nil)
	policy := lifecycle.Policy{Profile: "standard", SLADays: sla, VendorDependencyMaxDays: 30, OperationalRequirementMaxDays: 365}
	f := &fixture{st: st, finding: fs[0].ID, tokens: map[string]string{}}
	var ts Tokens
	for _, role := range []string{"viewer", "triager", "admin"} {
		secret, sum, err := GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		tok, err := NewToken(role+"-user", role, sum)
		if err != nil {
			t.Fatal(err)
		}
		ts = append(ts, tok)
		f.tokens[role] = secret
	}
	h := Handler(Deps{
		Store: st, Policy: policy, Auth: ts,
		Score: func(x store.Finding) priority.Score {
			return priority.Compute(priority.Input{Severity: x.Severity, Now: now})
		},
		Monthly: func(ctx context.Context, at time.Time) (report.Monthly, error) {
			return report.BuildMonthly(ctx, st, report.MonthPeriod(at), "standard", sla, now)
		},
		Status:  func() Status { return Status{Scheduler: true, Interval: 24 * time.Hour, Running: f.running} },
		Trigger: func() bool { f.triggers++; return !f.running },
	})
	f.srv = httptest.NewServer(h)
	t.Cleanup(f.srv.Close)
	return f
}

// reply is what tests look at in a response, read and closed by do.
type reply struct {
	StatusCode int
	Header     http.Header
}

func (f *fixture) do(t *testing.T, method, path, role, body string) (reply, string) {
	t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if role != "" {
		req.Header.Set("Authorization", "Bearer "+f.tokens[role])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return reply{resp.StatusCode, resp.Header}, string(b)
}

func TestAuthenticationAndRoles(t *testing.T) {
	f := newFixture(t)
	if resp, _ := f.do(t, "GET", "/healthz", "", ""); resp.StatusCode != 200 {
		t.Errorf("liveness needs no token: %d", resp.StatusCode)
	}
	resp, _ := f.do(t, "GET", "/api/v1/findings", "", "")
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("no token: %d %v", resp.StatusCode, resp.Header)
	}
	for _, bad := range []string{"Bearer smt_wrong", "Basic dXNlcjpwYXNz", "Bearer " + strings.Repeat("x", 300), f.tokens["admin"]} {
		req, _ := http.NewRequest("GET", f.srv.URL+"/api/v1/findings", nil)
		req.Header.Set("Authorization", bad)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("credential %.20q: %d", bad, resp.StatusCode)
		}
	}
	if resp, _ := f.do(t, "POST", "/api/v1/cycles", "triager", ""); resp.StatusCode != 403 {
		t.Errorf("a triager cannot start cycles: %d", resp.StatusCode)
	}
	if resp, body := f.do(t, "POST", "/api/v1/findings/1/decision", "viewer", `{}`); resp.StatusCode != 403 || !strings.Contains(body, "triager") {
		t.Errorf("a viewer cannot decide: %d %s", resp.StatusCode, body)
	}
	for _, h := range []string{"X-Content-Type-Options", "Cache-Control", "Content-Security-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if resp, _ := f.do(t, "GET", "/nope", "viewer", ""); resp.StatusCode != 404 {
		t.Errorf("unknown endpoint: %d", resp.StatusCode)
	}
}

func TestInternalErrorsAreNotShown(t *testing.T) {
	a := &api{Deps: Deps{Log: slog.New(slog.DiscardHandler)}}
	w := httptest.NewRecorder()
	a.fail(w, httptest.NewRequest("POST", "/x", nil), errors.New("database is locked (5) at /var/lib/shieldmon/shieldmon.db"), http.StatusUnprocessableEntity)
	if w.Code != 500 || strings.Contains(w.Body.String(), "locked") {
		t.Errorf("an internal error is a 500 without details: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	a.fail(w, httptest.NewRequest("POST", "/x", nil), lifecycle.CheckManual(model.StateOpen, model.StateFixed), http.StatusUnprocessableEntity)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "scan evidence") {
		t.Errorf("a refusal says why: %d %s", w.Code, w.Body)
	}
}

func TestTokensMatchExactlyOne(t *testing.T) {
	secret, sum, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := NewToken("a", "admin", sum)
	b, _ := NewToken("b", "viewer", sum)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	if id, ok := (Tokens{a}).Authenticate(req); !ok || id.Name != "a" || id.Role != RoleAdmin {
		t.Errorf("one token: %+v %v", id, ok)
	}
	if _, ok := (Tokens{a, b}).Authenticate(req); ok {
		t.Error("a secret configured twice is ambiguous: refused")
	}
	for _, c := range [][3]string{{"Alice", "viewer", sum}, {"a", "root", sum}, {"a", "viewer", "abc"}, {"engine", "triager", sum}} {
		if _, err := NewToken(c[0], c[1], c[2]); err == nil {
			t.Errorf("token %q accepted", c)
		}
	}
	if !strings.HasPrefix(secret, "smt_") || len(secret) < 40 {
		t.Errorf("secret %q", secret)
	}
}

func TestReadFindings(t *testing.T) {
	f := newFixture(t)
	resp, body := f.do(t, "GET", "/api/v1/findings?sort=priority&severity=high", "viewer", "")
	var list struct {
		Findings []map[string]any `json:"findings"`
		Count    int              `json:"count"`
	}
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &list) != nil || list.Count != 1 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	row := list.Findings[0]
	for _, k := range []string{"id", "vuln_id", "severity", "priority", "sla_due", "state"} {
		if _, ok := row[k]; !ok {
			t.Errorf("finding lacks %q: %v", k, row)
		}
	}
	for _, q := range []string{"state=closed", "severity=huge", "limit=0", "limit=5000", "sort=age"} {
		if resp, _ := f.do(t, "GET", "/api/v1/findings?"+q, "viewer", ""); resp.StatusCode != 400 {
			t.Errorf("%s: %d", q, resp.StatusCode)
		}
	}
	if resp, body := f.do(t, "GET", "/api/v1/findings/1", "viewer", ""); resp.StatusCode != 200 || !strings.Contains(body, `"events"`) {
		t.Errorf("show: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "GET", "/api/v1/findings/999", "viewer", ""); resp.StatusCode != 404 {
		t.Errorf("missing finding: %d", resp.StatusCode)
	}
	for _, p := range []string{"/api/v1/targets", "/api/v1/health", "/api/v1/status"} {
		if resp, body := f.do(t, "GET", p, "viewer", ""); resp.StatusCode != 200 || !json.Valid([]byte(body)) {
			t.Errorf("%s: %d %s", p, resp.StatusCode, body)
		}
	}
}

func TestDecisionsAreAuthoredByTheIdentity(t *testing.T) {
	f := newFixture(t)
	path := "/api/v1/findings/1/decision"
	if resp, body := f.do(t, "POST", path, "triager", `{"state":"risk_accepted","justification":"x","author":"someone-else"}`); resp.StatusCode != 400 {
		t.Errorf("the author cannot be given: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "POST", path, "triager", `{"state":"fixed","justification":"x"}`); resp.StatusCode != 422 {
		t.Errorf("only decisions: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "POST", path, "triager", `{"state":"risk_accepted","justification":""}`); resp.StatusCode != 422 {
		t.Errorf("the lifecycle policy applies: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", path, "triager", `{"state":"risk_accepted","justification":"`+strings.Repeat("x", maxBody)+`"}`); resp.StatusCode != 400 {
		t.Errorf("bodies are bounded: %d", resp.StatusCode)
	}
	resp, body := f.do(t, "POST", path, "triager", `{"state":"risk_accepted","justification":"no listener; RISK-12"}`)
	if resp.StatusCode != 200 || !strings.Contains(body, `"author": "api:triager-user"`) {
		t.Fatalf("decision: %d %s", resp.StatusCode, body)
	}
	ds, err := f.st.Decisions(context.Background(), f.finding)
	if err != nil || len(ds) != 1 || ds[0].Author != "api:triager-user" {
		t.Errorf("recorded decision: %+v %v", ds, err)
	}

	tr := "/api/v1/findings/1/transition"
	if resp, _ := f.do(t, "POST", tr, "triager", `{"to":"fixed"}`); resp.StatusCode != 422 {
		t.Errorf("closure needs scan evidence: %d", resp.StatusCode)
	}
	if resp, body := f.do(t, "POST", tr, "triager", `{"to":"open","note":"reconsidered"}`); resp.StatusCode != 200 && resp.StatusCode != 409 {
		t.Errorf("transition: %d %s", resp.StatusCode, body)
	}
}

func TestReportsAndCycles(t *testing.T) {
	f := newFixture(t)
	resp, body := f.do(t, "GET", "/api/v1/reports/monthly?format=html", "viewer", "")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || !strings.Contains(body, "<html") ||
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "style-src 'unsafe-inline'") {
		t.Errorf("html report: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, body := f.do(t, "GET", "/api/v1/reports/monthly", "viewer", ""); resp.StatusCode != 200 || !json.Valid([]byte(body)) {
		t.Errorf("json report: %d", resp.StatusCode)
	}
	resp, body = f.do(t, "GET", "/api/v1/reports/monthly?format=remediation-plan", "viewer", "")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") || !strings.HasPrefix(body, "item_id,") {
		t.Errorf("plan: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, body := f.do(t, "GET", "/api/v1/reports/monthly?format=markdown", "viewer", ""); resp.StatusCode != 200 || !strings.HasPrefix(body, "# ") {
		t.Errorf("markdown alias: %d", resp.StatusCode)
	}
	for _, q := range []string{"format=exe", "month=2026-13", "month=0001-01", "month=2999-01"} {
		if resp, _ := f.do(t, "GET", "/api/v1/reports/monthly?"+q, "viewer", ""); resp.StatusCode != 400 {
			t.Errorf("%s: %d", q, resp.StatusCode)
		}
	}
	if resp, _ := f.do(t, "POST", "/api/v1/cycles", "admin", ""); resp.StatusCode != 202 || f.triggers != 1 {
		t.Errorf("start a cycle: %d %d", resp.StatusCode, f.triggers)
	}
	f.running = true
	if resp, _ := f.do(t, "POST", "/api/v1/cycles", "admin", ""); resp.StatusCode != 409 {
		t.Errorf("one cycle at a time: %d", resp.StatusCode)
	}
}
