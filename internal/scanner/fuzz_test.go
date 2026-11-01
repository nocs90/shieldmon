package scanner

import (
	"os"
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
		for _, e := range ecosystems {
			// Ecosystem names from the output become paths only when safe.
			if p, err := o.dbFile("/cache", e); err == nil && !strings.HasPrefix(p, "/cache/osv-scalibr/") {
				t.Errorf("ecosystem %q escapes the database directory: %s", e, p)
			}
		}
	})
}
