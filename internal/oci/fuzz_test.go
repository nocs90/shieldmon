package oci

import "testing"

func FuzzParseReference(f *testing.F) {
	for _, s := range []string{"alpine:3.18", "ghcr.io/a/b@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "-x", "a b", "localhost:5000/x:y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseReference(s, false)
		if err != nil {
			return
		}
		// Anything accepted must be safe to place in argv.
		name := r.Name()
		if name == "" || name[0] == '-' {
			t.Fatalf("accepted unsafe reference %q -> %q", s, name)
		}
	})
}
