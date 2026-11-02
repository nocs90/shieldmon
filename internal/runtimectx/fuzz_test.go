package runtimectx

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Object names and labels come from every tenant of a cluster: the parser must never panic,
// and what it keeps stays bounded.
func FuzzParseInventory(f *testing.F) {
	f.Add([]byte(list))
	f.Add([]byte(`{"kind":"PodList","items":[{"metadata":{"name":"p"},"status":{"phase":"Running","containerStatuses":[{"imageID":"x@` + web + `","state":{"running":{}}}]},"spec":{"hostNetwork":true}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		inv, err := Parse(data, "c", taken)
		if err != nil {
			return
		}
		for d, c := range inv.images {
			if !digestRE.MatchString(d) || !strings.HasPrefix(d, "sha256:") {
				t.Errorf("kept a malformed digest %q", d)
			}
			if len(c.Exposure) > maxReasons {
				t.Errorf("%d exposure reasons", len(c.Exposure))
			}
			for _, r := range c.Exposure {
				if len(r) > 200 || !utf8.ValidString(r) && utf8.ValidString(string(data)) {
					t.Errorf("unbounded or broken reason: %q", r)
				}
			}
		}
	})
}
