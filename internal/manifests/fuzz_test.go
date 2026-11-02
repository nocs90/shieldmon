package manifests

import (
	"bytes"
	"testing"
)

// Third-party charts are hostile input: the parser must never panic, and what it keeps
// stays bounded.
func FuzzParseManifests(f *testing.F) {
	f.Add([]byte(rendered))
	f.Add([]byte(`{"kind":"List","items":[{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"a","image":"x:1"}]}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, img := range r.Images {
			if len(img.Where) > maxWhere || len(img.Charts) > maxWhere {
				t.Errorf("unbounded image uses: %+v", img)
			}
		}
	})
}
