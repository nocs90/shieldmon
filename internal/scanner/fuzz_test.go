package scanner

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nocs90/shieldmon/internal/normalize"
)

// Scanner output is derived from hostile image content: parsers and the
// normalizer must never panic on arbitrary bytes.

func FuzzParseGrype(f *testing.F) {
	seed, _ := os.ReadFile("testdata/grype-alpine-3.18.0.json")
	f.Add(seed)
	f.Add([]byte(`{"matches":[{"vulnerability":{"id":"GHSA-x"},"relatedVulnerabilities":[{"id":"CVE-1"}],"artifact":{"purl":"pkg:npm/a@1"}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := ParseGrype(data)
		if err == nil {
			normalize.Merge(res.Matches)
		}
	})
}

func FuzzParseTrivy(f *testing.F) {
	seed, _ := os.ReadFile("testdata/trivy-alpine-3.18.0.json")
	f.Add(seed)
	f.Add([]byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","FixedVersion":", ,1.0,","PkgIdentifier":{"PURL":"pkg:%%"}}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := ParseTrivy(data)
		if err == nil {
			normalize.Merge(res.Matches)
		}
	})
}

func FuzzParseOSV(f *testing.F) {
	f.Add([]byte(osvOutput))
	f.Add([]byte(`{"results":[{"packages":[{"package":{"ecosystem":"../x"},"groups":[{"ids":["A"],"max_severity":"NaN"}]}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, ecosystems, err := parseOSV(data)
		if err != nil {
			return
		}
		normalize.Merge(res.Matches)
		o := &OSV{}
		for e, n := range ecosystems {
			if n < 1 {
				t.Errorf("ecosystem %q reported with %d packages", e, n)
			}
			// Ecosystem names from the output become paths only when safe.
			if p, err := o.dbFile("/cache", e); err == nil && !strings.HasPrefix(p, "/cache/osv-scalibr/") {
				t.Errorf("ecosystem %q escapes the database directory: %s", e, p)
			}
		}
	})
}

// FuzzOSVSelectComponents: the selection of a hostile SBOM's components never panics, keeps
// only configured ecosystems, and writes a document that decodes.
func FuzzOSVSelectComponents(f *testing.F) {
	f.Add([]byte(`{"bomFormat":"CycloneDX","components":[{"purl":"pkg:npm/a@1"},{"purl":"pkg:npm/a@1?x=y"},{"purl":"pkg:pypi/b@2"}]}`))
	f.Add([]byte(`{"components":[{"purl":"pkg:apk/alpine/busybox@1?distro=alpine-3.18"},{"purl":7}],"dependencies":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		o := &OSV{Ecosystems: []string{"npm", "PyPI", "Alpine"}}
		out, want, err := o.selectComponents(data)
		if err != nil {
			return
		}
		for e, n := range want {
			if !slices.Contains(o.Ecosystems, e) || n < 1 {
				t.Errorf("selected %d packages of %q", n, e)
			}
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Errorf("the selection does not decode: %v", err)
		}
	})
}
