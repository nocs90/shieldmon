package vex

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

var now = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

const (
	digestA = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
	digestB = "sha256:bbbb000000000000000000000000000000000000000000000000000000000000"
	repo    = "ghcr.io/vendor/app"
)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseOpenVEX(t *testing.T) {
	stmts, skipped, err := Parse(readFile(t, "openvex-vendor.json"), "", now)
	if err != nil {
		t.Fatal(err)
	}
	vendor := "Vendor Security Team <psirt@vendor.example.com>"
	want := []Statement{
		{
			VulnID: "CVE-2023-45853", Aliases: []string{"GHSA-mq29-j5xf-cjwr"}, Digest: digestA, Repository: repo,
			PURL: "pkg:apk/alpine/zlib@1.2.13-r1", Justification: "vulnerable_code_not_in_execute_path",
			Impact: "minizip is not built into the image", Author: vendor,
			Timestamp: time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC), Source: "https://vendor.example.com/vex/2026-10-001",
		},
		{
			VulnID: "CVE-2022-48174", Repository: repo, PURL: "pkg:apk/alpine/busybox", AnyVersion: true,
			Justification: "vulnerable_code_cannot_be_controlled_by_adversary", Notes: "reviewed in RISK-118", Author: vendor,
			Timestamp: time.Date(2026, 10, 21, 9, 30, 0, 0, time.UTC), ExpiresAt: time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC),
			Source: "https://vendor.example.com/vex/2026-10-001",
		},
		{
			VulnID: "CVE-2024-0001", Digest: digestB, Repository: repo, Justification: "component_not_present",
			Author: "Platform Team", Timestamp: time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC),
			Source: "https://vendor.example.com/vex/2026-10-001",
		},
	}
	if !reflect.DeepEqual(stmts, want) {
		t.Errorf("statements:\n got %+v\nwant %+v", stmts, want)
	}
	reasons := map[string]string{}
	for _, s := range skipped {
		reasons[s.VulnID] = s.Reason
	}
	for id, want := range map[string]string{
		"CVE-2024-0002": "status affected",
		"CVE-2024-0003": "expired on 2026-01-01",
		"CVE-2024-0004": "not a sha256 digest",
		"CVE-2024-0005": "no justification",
	} {
		if !strings.Contains(reasons[id], want) {
			t.Errorf("%s: skipped because %q, want %q", id, reasons[id], want)
		}
	}
}

func TestParseCycloneDX(t *testing.T) {
	stmts, skipped, err := Parse(readFile(t, "cyclonedx-vex.json"), "", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(stmts) != 2 {
		t.Fatalf("statements = %+v", stmts)
	}
	busybox := stmts[0]
	if busybox.VulnID != "CVE-2022-48174" || busybox.PURL != "pkg:apk/alpine/busybox@1.36.0-r9" || busybox.AnyVersion ||
		busybox.Justification != "vulnerable_code_not_in_execute_path" || busybox.Digest != digestA || busybox.Author != "App Team" ||
		!reflect.DeepEqual(busybox.Aliases, []string{"GHSA-0000-0000-0000"}) {
		t.Errorf("busybox statement = %+v", busybox)
	}
	if fp := stmts[1]; fp.VulnID != "CVE-2023-0001" || fp.PURL != "" || fp.Impact != "false positive" {
		t.Errorf("a false positive on the image covers every package: %+v", fp)
	}
	if len(skipped) != 2 {
		t.Errorf("skipped = %+v: exploitable and an unknown justification", skipped)
	}
}

func TestParseNeedsAnAuthor(t *testing.T) {
	doc := strings.Replace(string(readFile(t, "cyclonedx-vex.json")), `"authors": [ { "name": "App Team" } ],`, "", 1)
	stmts, skipped, err := Parse([]byte(doc), "", now)
	if err != nil || len(stmts) != 0 || !strings.Contains(skipped[0].Reason, "no author") {
		t.Fatalf("without an author nothing is imported: %+v %+v %v", stmts, skipped, err)
	}
	if stmts, _, _ := Parse([]byte(doc), "alice", now); len(stmts) != 2 || stmts[0].Author != "alice" {
		t.Errorf("--author supplies a missing author: %+v", stmts)
	}
}

func TestParseRejectsHostileDocuments(t *testing.T) {
	for what, doc := range map[string]string{
		"not JSON":        "<html>",
		"neither format":  `{"hello":"world"}`,
		"other OpenVEX":   `{"@context":"https://openvex.dev/ns/v0.1.0","statements":[]}`,
		"oversized":       `{"@context":"https://openvex.dev/ns/v0.2.0","x":"` + strings.Repeat("a", MaxDocumentBytes) + `"}`,
		"cdx no product":  `{"bomFormat":"CycloneDX","metadata":{"component":{"purl":"pkg:npm/x@1"}},"vulnerabilities":[]}`,
		"cdx wrong types": `{"bomFormat":"CycloneDX","vulnerabilities":"yes"}`,
	} {
		if _, _, err := Parse([]byte(doc), "x", now); err == nil {
			t.Errorf("%s: must be refused", what)
		}
	}
	long := `{"@context":"https://openvex.dev/ns/v0.2.0","author":"a","statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"` + digestA + `"}],"status":"not_affected","impact_statement":"` + strings.Repeat("x", maxFieldLen+1) + `"}]}`
	if stmts, skipped, _ := Parse([]byte(long), "", now); len(stmts) != 0 || len(skipped) != 1 {
		t.Errorf("an oversized field skips its statement: %+v %+v", stmts, skipped)
	}
}

func TestMatches(t *testing.T) {
	f := Finding{Digest: digestA, Repository: repo, PURL: "pkg:apk/alpine/busybox@1.36.0-r9", PkgKey: "pkg:apk/alpine/busybox", VulnID: "CVE-2022-48174", Aliases: []string{"GHSA-x"}}
	for _, c := range []struct {
		s    Statement
		want bool
	}{
		{Statement{VulnID: "CVE-2022-48174", Digest: digestA}, true},
		{Statement{VulnID: "CVE-2022-48174", Digest: digestB}, false},
		{Statement{VulnID: "CVE-2022-48174", Repository: repo}, true},
		{Statement{VulnID: "CVE-2022-48174", Repository: "ghcr.io/other/app"}, false},
		{Statement{VulnID: "CVE-2022-48174", Digest: digestA, PURL: "pkg:apk/alpine/busybox@1.36.0-r9"}, true},
		{Statement{VulnID: "CVE-2022-48174", Digest: digestA, PURL: "pkg:apk/alpine/busybox@1.36.1-r0"}, false},
		{Statement{VulnID: "CVE-2022-48174", Digest: digestA, PURL: "pkg:apk/alpine/busybox", AnyVersion: true}, true},
		{Statement{VulnID: "GHSA-x", Digest: digestA}, true},
		{Statement{VulnID: "CVE-9", Aliases: []string{"CVE-2022-48174"}, Digest: digestA}, true},
		{Statement{VulnID: "CVE-9", Digest: digestA}, false},
		{Statement{VulnID: "CVE-2022-48174"}, false}, // no product: never
	} {
		if got := c.s.Matches(f); got != c.want {
			t.Errorf("%+v matches = %t, want %t", c.s, got, c.want)
		}
	}
}

// TestOpenVEXExportIsSchemaValidAndLossless covers both acceptance criteria of the export:
// valid against the OpenVEX schema, and import → export → import gives the same statements.
func TestOpenVEXExportIsSchemaValidAndLossless(t *testing.T) {
	in, _, err := Parse(readFile(t, "openvex-vendor.json"), "", now)
	if err != nil {
		t.Fatal(err)
	}
	cdx, _, err := Parse(readFile(t, "cyclonedx-vex.json"), "", now)
	if err != nil {
		t.Fatal(err)
	}
	in = append(in, cdx...)
	doc, err := OpenVEX(Document{Author: "ShieldMon export <ops@example.com>", Tooling: "shieldmon test", Timestamp: now, Statements: in})
	if err != nil {
		t.Fatal(err)
	}

	c := jsonschema.NewCompiler()
	schema, err := jsonschema.UnmarshalJSON(bytes.NewReader(readFile(t, "openvex_json_schema.json")))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("openvex.json", schema); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("export is not valid OpenVEX: %v\n%s", err, doc)
	}

	out, skipped, err := Parse(doc, "", now)
	if err != nil || len(skipped) != 0 {
		t.Fatalf("re-import: %v %+v", err, skipped)
	}
	keys := func(ss []Statement) map[string]bool {
		m := map[string]bool{}
		for _, s := range ss {
			m[s.Key()] = true
		}
		return m
	}
	if !reflect.DeepEqual(keys(in), keys(out)) {
		t.Errorf("round trip lost information:\n in  %+v\n out %+v", in, out)
	}
	again, err := OpenVEX(Document{Author: "ShieldMon export <ops@example.com>", Tooling: "shieldmon test", Timestamp: now, Statements: out})
	if err != nil || !bytes.Equal(doc, again) {
		t.Error("exporting the same statements must give the same document")
	}
}

func TestProductPURL(t *testing.T) {
	for _, c := range []struct{ digest, repo string }{{digestA, repo}, {"", repo}, {digestA, ""}} {
		d, r, err := product(ProductPURL(c.digest, c.repo))
		if err != nil || d != c.digest || r != c.repo {
			t.Errorf("ProductPURL(%q, %q) does not round-trip: %q %q %v", c.digest, c.repo, d, r, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, name := range []string{"openvex-vendor.json", "cyclonedx-vex.json"} {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		stmts, _, err := Parse(data, "fuzz", now)
		if err != nil {
			return
		}
		for _, s := range stmts {
			if s.Author == "" || len(s.Reason()) < 10 || (s.Digest == "" && s.Repository == "") || !s.InForce(now) {
				t.Fatalf("invalid statement accepted: %+v", s)
			}
			if s.Digest != "" && !digestRE.MatchString(s.Digest) {
				t.Fatalf("invalid digest accepted: %q", s.Digest)
			}
		}
		if _, err := json.Marshal(stmts); err != nil {
			t.Fatal(err)
		}
	})
}
