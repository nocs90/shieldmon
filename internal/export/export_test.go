package export_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nocs90/shieldmon/internal/export"
	"github.com/nocs90/shieldmon/internal/export/exporttest"
)

const secret = "s3cr3t-api-k3y-value-0123456789"

func TestConformance(t *testing.T) {
	for _, f := range []exporttest.Fixture{
		{
			Name: "dependency-track", Secret: secret, AuthHeader: "X-Api-Key",
			Options: func(u string) map[string]any { return map[string]any{"url": u, "api_key_env": "DT_KEY"} },
		},
		{
			Name: "defectdojo", Secret: secret, AuthHeader: "Authorization",
			Options: func(u string) map[string]any { return map[string]any{"url": u, "api_key_env": "DOJO_KEY"} },
		},
	} {
		t.Run(f.Name, func(t *testing.T) { exporttest.CheckExporter(t, f) })
	}
}

type capture struct {
	mu    sync.Mutex
	path  string
	auth  string
	forms []map[string][]byte
}

func (c *capture) server(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Errorf("content type: %v", err)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		form := map[string][]byte{}
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(p)
			form[p.FormName()] = b
		}
		c.mu.Lock()
		c.path, c.auth = r.URL.Path, r.Header.Get("Authorization")+r.Header.Get("X-Api-Key")
		c.forms = append(c.forms, form)
		c.mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
}

func newExporter(t *testing.T, name string, opts map[string]any) export.Exporter {
	t.Helper()
	ins, err := export.New([]export.Config{{Name: "x", Exporter: name, Options: opts}}, export.Spec{Env: func(string) string { return secret }})
	if err != nil {
		t.Fatal(err)
	}
	return ins[0].Sender
}

func TestDependencyTrackUpload(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	defer srv.Close()
	e := newExporter(t, "dependency-track", map[string]any{"url": srv.URL + "/", "api_key_env": "DT"})
	batch := exporttest.HostileBatch()
	batch.Targets = append(batch.Targets, export.Target{Ref: "registry.test/new:1", Repository: "registry.test/new", Tag: "1", Digest: "sha256:cccc"})
	res, err := e.Export(context.Background(), batch)
	if err != nil || res.Sent != 2 || !strings.Contains(res.Failed["registry.test/new:1"], "no CycloneDX SBOM") {
		t.Fatalf("export: %+v %v", res, err)
	}
	if c.path != "/api/v1/bom" || c.auth != secret {
		t.Errorf("path %q, key %q", c.path, c.auth)
	}
	f := c.forms[0]
	if string(f["autoCreate"]) != "true" || string(f["projectName"]) != "registry.test/app" || string(f["projectVersion"]) != "prod (linux/amd64)" ||
		!bytes.Equal(f["bom"], batch.Targets[0].SBOM) {
		t.Errorf("form: autoCreate=%s name=%s version=%s bom=%d bytes", f["autoCreate"], f["projectName"], f["projectVersion"], len(f["bom"]))
	}
}

// allowed are the Generic Findings Import keys ShieldMon may send: DefectDojo refuses unknown ones.
var allowed = map[string]bool{
	"title": true, "description": true, "severity": true, "date": true, "mitigation": true, "references": true, "cve": true,
	"vulnerability_ids": true, "component_name": true, "component_version": true, "purl": true, "unique_id_from_tool": true,
	"vuln_id_from_tool": true, "cvssv3_score": true, "epss_score": true, "known_exploited": true, "fix_available": true,
	"fix_version": true, "planned_remediation_date": true, "active": true, "risk_accepted": true, "tags": true,
}

func TestDefectDojoReimport(t *testing.T) {
	c := &capture{}
	srv := c.server(t)
	defer srv.Close()
	e := newExporter(t, "defectdojo", map[string]any{"url": srv.URL, "api_key_env": "DOJO", "product_type": "Payments"})
	batch := exporttest.HostileBatch()
	if res, err := e.Export(context.Background(), batch); err != nil || res.Sent != 2 {
		t.Fatalf("export: %+v %v", res, err)
	}
	if c.path != "/api/v2/reimport-scan/" || c.auth != "Token "+secret {
		t.Errorf("path %q, auth %q", c.path, c.auth)
	}
	f := c.forms[0]
	for k, want := range map[string]string{
		"scan_type": "Generic Findings Import", "product_type_name": "Payments", "product_name": "registry.test/app",
		"engagement_name": "ShieldMon", "test_title": "registry.test/app:prod (linux/amd64)", "auto_create_context": "true",
		"close_old_findings": "true", "scan_date": "2026-10-31", "version": "sha256:aaaa",
	} {
		if got := string(f[k]); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	var doc struct {
		Type     string           `json:"type"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(f["file"], &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Type != "ShieldMon" || len(doc.Findings) != 2 {
		t.Fatalf("report: type %q, %d findings (not_affected is not sent)", doc.Type, len(doc.Findings))
	}
	ids := map[any]bool{}
	for _, fd := range doc.Findings {
		for k := range fd {
			if !allowed[k] {
				t.Errorf("key %q would stop the import", k)
			}
		}
		ids[fd["unique_id_from_tool"]] = true
		if n := len(fd["component_version"].(string)); n > 100 {
			t.Errorf("component_version is %d bytes: DefectDojo allows 100", n)
		}
		if n := len(fd["title"].(string)); n > 500 {
			t.Errorf("title is %d bytes", n)
		}
	}
	xz, zlib := doc.Findings[0], doc.Findings[1]
	if xz["severity"] != "Critical" || xz["cve"] != "CVE-2024-3094" || xz["known_exploited"] != true || xz["fix_version"] != "5.6.1" ||
		xz["unique_id_from_tool"] != "shieldmon:CVE-2024-3094:pkg:rpm/xz-libs" || xz["risk_accepted"] != false {
		t.Errorf("xz: %v", xz)
	}
	if zlib["severity"] != "Info" || zlib["risk_accepted"] != true || zlib["cve"] != nil {
		t.Errorf("zlib (negligible, accepted, a GHSA): %v", zlib)
	}
	if len(ids) != 2 {
		t.Errorf("unique ids repeat: %v", ids)
	}
}

func TestExportsValidated(t *testing.T) {
	for _, c := range []struct {
		cfg  export.Config
		want string
	}{
		{export.Config{Name: "Bad Name", Exporter: "defectdojo"}, "name"},
		{export.Config{Name: "x", Exporter: "jira"}, "unknown exporter"},
		{export.Config{Name: "x", Exporter: "defectdojo", Options: map[string]any{"url": "https://d.test", "token": "abc"}}, "unknown option"},
		{export.Config{Name: "x", Exporter: "defectdojo", Options: map[string]any{"url": "https://d.test", "product_type": "password=hunter2"}}, "looks like a credential"},
		{export.Config{Name: "x", Exporter: "defectdojo", Options: map[string]any{"url": "http://d.test", "api_key_env": "K"}}, "https"},
		{export.Config{Name: "x", Exporter: "dependency-track", Options: map[string]any{"url": "https://dt.test"}}, "api_key_env is required"},
		{export.Config{Name: "x", Exporter: "dependency-track", Options: map[string]any{"api_key_env": "K"}}, "url is required"},
	} {
		if _, err := export.New([]export.Config{c.cfg}, export.Spec{Env: func(string) string { return secret }}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.cfg, err, c.want)
		}
	}
	if _, err := export.New([]export.Config{
		{Name: "a", Exporter: "defectdojo", Options: map[string]any{"url": "https://d.test", "api_key_env": "K"}},
		{Name: "a", Exporter: "defectdojo", Options: map[string]any{"url": "https://d.test", "api_key_env": "K"}},
	}, export.Spec{Env: func(string) string { return secret }}); err == nil {
		t.Error("duplicate names")
	}
}
