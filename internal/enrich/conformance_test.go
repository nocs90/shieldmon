package enrich_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/enrich"
	"github.com/nocs90/shieldmon/internal/enrich/enrichtest"
	"github.com/nocs90/shieldmon/internal/model"
)

func TestKEVConformance(t *testing.T) {
	catalog, err := os.ReadFile("testdata/kev-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	serve := func(t *testing.T, body []byte, status int) *httptest.Server {
		t.Helper()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	build := func(t *testing.T, dir string, srv *httptest.Server) enrich.Enricher {
		t.Helper()
		insts, err := enrich.New(map[string]enrich.Config{"kev": {Options: map[string]any{"url": srv.URL + "/kev.json"}}}, dir,
			enrich.Spec{Transport: srv.Client().Transport, Now: func() time.Time { return time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC) }})
		if err != nil || len(insts) != 1 {
			t.Fatal(insts, err)
		}
		return insts[0].Enricher
	}
	var root string
	enrichtest.CheckEnricher(t, enrichtest.Fixture{
		Name: "kev",
		New: func(t *testing.T) enrich.Enricher {
			root = t.TempDir()
			return build(t, root, serve(t, catalog, http.StatusOK))
		},
		Known:   model.Match{VulnID: "CVE-2021-44228"},
		Unknown: model.Match{VulnID: "CVE-2021-45046"},
		Broken: func(t *testing.T, _ enrich.Enricher) enrich.Enricher {
			return build(t, root, serve(t, []byte("<html>maintenance</html>"), http.StatusOK))
		},
	})
}

func TestNewEnrichers(t *testing.T) {
	off := false
	insts, err := enrich.New(map[string]enrich.Config{"kev": {Enabled: &off}}, t.TempDir(), enrich.Spec{})
	if err != nil || len(insts) != 0 {
		t.Errorf("kev can be turned off: %v %v", insts, err)
	}
	if insts, err := enrich.New(nil, t.TempDir(), enrich.Spec{}); err != nil || len(insts) != 1 || insts[0].Name != "kev" {
		t.Errorf("kev is on by default: %v %v", insts, err)
	}
	for what, cfg := range map[string]map[string]enrich.Config{
		"unknown enricher": {"epss": {}},
		"unknown option":   {"kev": {Options: map[string]any{"uri": "x"}}},
		"credential":       {"kev": {Options: map[string]any{"url": "https://mirror.example.com/kev.json?token=abcdefghijklmnop"}}},
	} {
		if _, err := enrich.New(cfg, t.TempDir(), enrich.Spec{}); err == nil {
			t.Errorf("%s: must be refused", what)
		}
	}
}
