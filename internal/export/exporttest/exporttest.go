// Package exporttest is the conformance kit of exporters (docs/extending/exporter.md): every
// exporter must deliver a hostile batch, keep its credential out of everything but the
// request's authentication header, follow no redirect and stop when its context ends.
package exporttest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/export"
	"github.com/nocs90/shieldmon/internal/report"
)

// Fixture describes how to build the exporter under test against a URL.
type Fixture struct {
	Name string
	// Options returns the exporter's options for an endpoint at url, its credential named by
	// an *_env option whose variable holds Secret.
	Options func(url string) map[string]any
	Secret  string
	// AuthHeader is the header that carries the credential.
	AuthHeader string
}

// rlo is U+202E RIGHT-TO-LEFT OVERRIDE, built at run time: never a literal in source.
var rlo = string(rune(0x202e))

// HostileBatch has two targets whose findings carry what scanner output may hold.
func HostileBatch() export.Batch {
	evil := rlo + "\r\nX-Injected: 1\r\n<script>alert(1)</script> \"quote\" gnp.exe" + strings.Repeat("long ", 300)
	first := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	rows := []report.Row{
		{
			ID: 1, State: "open", VulnID: "CVE-2024-3094", Severity: "critical", Package: "xz-libs" + evil, Version: "5.6.0" + evil,
			PURL: "pkg:rpm/xz-libs@5.6.0", Title: "xz backdoor" + evil, KEV: true, FirstDetected: first, FixVersions: []string{"5.6.1"},
		},
		{
			ID: 2, State: "risk_accepted", VulnID: "GHSA-xxxx-yyyy-zzzz", Severity: "negligible", Package: "zlib", Version: "1.3",
			PURL: "pkg:apk/alpine/zlib@1.3", FirstDetected: first,
			Decision: &report.DecisionInfo{State: "risk_accepted", Author: "lead" + evil, Justification: "no fix" + evil, ExpiresAt: first.AddDate(0, 1, 0)},
		},
		{ID: 3, State: "not_affected", VulnID: "CVE-2024-0001", Severity: "high", Package: "busybox", Version: "1.36", PURL: "pkg:apk/alpine/busybox@1.36"},
	}
	// Stored SBOMs are valid JSON; their strings carry hostile content.
	sbom, _ := json.Marshal(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6",
		"components": []map[string]string{{"type": "library", "name": "x" + evil}},
	})
	return export.Batch{
		Now: first.AddDate(0, 0, 30), Tool: "shieldmon test",
		Targets: []export.Target{
			{
				Ref: "registry.test/app:prod", Platform: "linux/amd64", Digest: "sha256:aaaa", Repository: "registry.test/app", Tag: "prod",
				MultiPlatform: true, SBOM: sbom, Findings: rows,
			},
			{
				Ref: "registry.test/app:prod", Platform: "linux/arm64", Digest: "sha256:bbbb", Repository: "registry.test/app", Tag: "prod",
				MultiPlatform: true, SBOM: sbom, Findings: rows[:1],
			},
		},
	}
}

type recorded struct {
	header http.Header
	body   []byte
}

type recorder struct {
	mu   sync.Mutex
	reqs []recorded
}

func (r *recorder) handler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 64<<20))
		r.mu.Lock()
		r.reqs = append(r.reqs, recorded{req.Header.Clone(), b})
		r.mu.Unlock()
		if status >= 400 {
			// A hostile endpoint echoes the request, credentials included.
			w.WriteHeader(status)
			_, _ = w.Write([]byte(req.Header.Get("Authorization") + req.Header.Get("X-Api-Key"))) //nolint:gosec // G705: the fake echoes the request on purpose, as a hostile endpoint
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"token":"t"}`))
	}
}

func build(t *testing.T, f Fixture, url string) export.Exporter {
	t.Helper()
	p, ok := export.Lookup(f.Name)
	if !ok {
		t.Fatalf("exporter %q is not registered", f.Name)
	}
	if p.Description == "" {
		t.Errorf("exporter %q has no description", f.Name)
	}
	e, err := p.New(export.Spec{Name: "kit", Options: f.Options(url), Env: func(string) string { return f.Secret }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// CheckExporter verifies an exporter's contract.
func CheckExporter(t *testing.T, f Fixture) {
	t.Helper()
	ctx := context.Background()
	batch := HostileBatch()

	ok := &recorder{}
	srv := httptest.NewServer(ok.handler(http.StatusOK))
	defer srv.Close()
	res, err := build(t, f, srv.URL).Export(ctx, batch)
	if err != nil || res.Sent != len(batch.Targets) || len(res.Failed) != 0 {
		t.Fatalf("export: %+v %v", res, err)
	}
	if len(ok.reqs) != len(batch.Targets) {
		t.Fatalf("%d requests for %d targets", len(ok.reqs), len(batch.Targets))
	}
	for _, r := range ok.reqs {
		if !strings.Contains(r.header.Get(f.AuthHeader), f.Secret) {
			t.Errorf("the credential is sent in %s", f.AuthHeader)
		}
		if bytes.Contains(r.body, []byte(f.Secret)) {
			t.Error("the credential is in the request body")
		}
		if bytes.Contains(r.body, []byte("\r\nX-Injected: 1\r\n")) && !strings.Contains(r.header.Get("Content-Type"), "multipart/") {
			t.Error("hostile text reaches a non-multipart body raw")
		}
	}

	// A failing endpoint that echoes the request: reported per target, without the credential.
	bad := &recorder{}
	failing := httptest.NewServer(bad.handler(http.StatusInternalServerError))
	defer failing.Close()
	res, err = build(t, f, failing.URL).Export(ctx, batch)
	if err != nil || res.Sent != 0 || len(res.Failed) == 0 {
		t.Fatalf("failing endpoint: %+v %v", res, err)
	}
	for ref, msg := range res.Failed {
		if strings.Contains(msg, f.Secret) || ref == "" {
			t.Errorf("failure of %q leaks the credential: %s", ref, msg)
		}
	}

	// No redirect is followed: it would carry the credential elsewhere.
	other := &recorder{}
	elsewhere := httptest.NewServer(other.handler(http.StatusOK))
	defer elsewhere.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect) //nolint:gosec // G710: redirects to the kit's own second server
	}))
	defer redirecting.Close()
	if res, _ := build(t, f, redirecting.URL).Export(ctx, batch); res.Sent != 0 || len(other.reqs) != 0 {
		t.Errorf("a redirect was followed: %+v, %d requests elsewhere", res, len(other.reqs))
	}

	// A cancelled export stops and says so.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := build(t, f, srv.URL).Export(cancelled, batch); err == nil {
		t.Error("a cancelled export returns its context's error")
	}

	// Payloads (--dry-run) are what would be sent, one document per target.
	if p, ok := build(t, f, srv.URL).(export.Payloader); ok {
		docs, err := p.Payloads(batch)
		if err != nil || len(docs) == 0 {
			t.Fatalf("payloads: %d %v", len(docs), err)
		}
		for name, doc := range docs {
			if !json.Valid(doc) || strings.ContainsAny(name, "/\\: ") {
				t.Errorf("payload %q: valid JSON with a plain file name", name)
			}
		}
	}
}
