package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

var clock = time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/kev-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// catalogServer serves body with an ETag, answering 304 to a matching If-None-Match.
func catalogServer(t *testing.T, body *atomic.Value) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		b := body.Load().([]byte)
		etag := `"` + strings.Repeat("e", len(b)%7+1) + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func newTestKEV(t *testing.T, dir string, srv *httptest.Server, opts map[string]any) Enricher {
	t.Helper()
	if opts == nil {
		opts = map[string]any{"url": srv.URL + "/feeds/kev.json"}
	}
	spec := Spec{CacheDir: dir, Options: opts, Now: func() time.Time { return clock }}
	if srv != nil {
		spec.Transport = srv.Client().Transport
	}
	e, err := newKEV(spec)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestKEVUpdateAndEnrich(t *testing.T) {
	var body atomic.Value
	body.Store(fixture(t))
	srv, requests := catalogServer(t, &body)
	dir := t.TempDir()
	k := newTestKEV(t, dir, srv, nil)
	if !k.UpdatedAt().IsZero() {
		t.Fatal("no data before the first update")
	}
	if err := k.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !k.UpdatedAt().Equal(clock) {
		t.Errorf("updated at %s", k.UpdatedAt())
	}
	for _, c := range []struct {
		m    model.Match
		want bool
	}{
		{model.Match{VulnID: "CVE-2021-44228"}, true},
		{model.Match{VulnID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}}, true},
		{model.Match{VulnID: "CVE-2021-45046"}, false},
	} {
		m := c.m
		k.Enrich(&m)
		if m.KEV != c.want {
			t.Errorf("%s: KEV=%t, want %t", c.m.VulnID, m.KEV, c.want)
		}
	}

	// A second update with the same catalog is a 304: confirmed, not downloaded again.
	clock = clock.Add(time.Hour)
	if err := k.Update(context.Background()); err != nil || !k.UpdatedAt().Equal(clock) || requests.Load() != 2 {
		t.Fatalf("conditional update: %v %s %d", err, k.UpdatedAt(), requests.Load())
	}
	// The cache survives a restart.
	again := newTestKEV(t, dir, srv, nil)
	m := model.Match{VulnID: "CVE-2024-3400"}
	again.Enrich(&m)
	if !m.KEV || !again.UpdatedAt().Equal(clock) {
		t.Errorf("cached catalog after a restart: %v %s", m.KEV, again.UpdatedAt())
	}
	if st, err := os.Stat(filepath.Join(dir, "kev.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("cache file owner-only: %v %v", st, err)
	}
}

func TestKEVRefusesHostileCatalogs(t *testing.T) {
	good := string(fixture(t))
	for what, doc := range map[string]string{
		"html":      "<html>maintenance</html>",
		"empty":     `{"title":"x","count":0,"vulnerabilities":[]}`,
		"truncated": strings.Replace(good, `"count": 6`, `"count": 1762`, 1),
		"malformed": `{"count":2,"vulnerabilities":[{"cveID":"CVE-1","dateAdded":"x"},{"cveID":"'; DROP","dateAdded":"2026-01-01"}]}`,
		"oversized": `{"vulnerabilities":[],"x":"` + strings.Repeat("a", kevMaxBytes) + `"}`,
	} {
		t.Run(what, func(t *testing.T) {
			var body atomic.Value
			body.Store(fixture(t))
			srv, _ := catalogServer(t, &body)
			k := newTestKEV(t, t.TempDir(), srv, nil)
			if err := k.Update(context.Background()); err != nil {
				t.Fatal(err)
			}
			body.Store([]byte(doc))
			clock = clock.Add(time.Hour)
			if err := k.Update(context.Background()); err == nil {
				t.Fatal("must be refused")
			}
			m := model.Match{VulnID: "CVE-2021-44228"}
			k.Enrich(&m)
			if !m.KEV || k.UpdatedAt().Equal(clock) {
				t.Error("a refused catalog keeps the previous data, and its age")
			}
		})
	}
}

func TestKEVRefusesAShrunkCatalog(t *testing.T) {
	if _, err := parseKEV(fixture(t), 13); err == nil || !strings.Contains(err.Error(), "lost more than half") {
		t.Errorf("6 entries where 13 were known: %v", err)
	}
	if c, err := parseKEV(fixture(t), 11); err != nil || len(c.Entries) != 6 {
		t.Errorf("6 of 11 is fine: %v", err)
	}
}

func TestKEVOptions(t *testing.T) {
	for what, opts := range map[string]map[string]any{
		"http":        {"url": "http://www.cisa.gov/kev.json"},
		"credentials": {"url": "https://user:pw@mirror.example.com/kev.json"},
	} {
		if _, err := newKEV(Spec{CacheDir: t.TempDir(), Options: opts}); err == nil {
			t.Errorf("%s: must be refused", what)
		}
	}
	// A local copy, for hosts without internet access.
	file := filepath.Join(t.TempDir(), "kev.json")
	if err := os.WriteFile(file, fixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	k := newTestKEV(t, t.TempDir(), nil, map[string]any{"file": file})
	if err := k.Update(context.Background()); err != nil || k.UpdatedAt().IsZero() {
		t.Fatalf("file: %v", err)
	}
}

func TestKEVRedirectToHTTPRefused(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture(t))
	}))
	t.Cleanup(plain.Close)
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/kev.json", http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	k := newTestKEV(t, t.TempDir(), redirect, nil)
	if err := k.Update(context.Background()); err == nil {
		t.Error("a redirect to plain http must be refused")
	}
}

func FuzzParseKEV(f *testing.F) {
	b, err := os.ReadFile("testdata/kev-catalog.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := parseKEV(data, 0)
		if err != nil {
			return
		}
		for id, e := range c.Entries {
			if !cveRE.MatchString(id) || !isDate(e.Added) {
				t.Fatalf("invalid entry accepted: %s %+v", id, e)
			}
		}
	})
}
