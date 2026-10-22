package normalize

import (
	"strings"
	"testing"
)

func FuzzCanonicalPURL(f *testing.F) {
	for _, s := range []string{
		"pkg:apk/alpine/busybox@1.36.0-r9?arch=aarch64&distro=alpine-3.18.0",
		"pkg:rpm/redhat/openssl@1.1.1k?epoch=1", "pkg:pypi/Django_Rest@3", "pkg:%zz", "", "pkg:/@?#",
	} {
		f.Add(s, "apk", "name", "1.0")
	}
	f.Fuzz(func(t *testing.T, raw, typ, name, version string) {
		purl, key := CanonicalPURL(raw, typ, name, version)
		if purl == "" || key == "" {
			t.Fatalf("empty canonical form for %q", raw)
		}
		// Canonicalization is idempotent.
		p2, k2 := CanonicalPURL(purl, typ, name, version)
		if p2 != purl || (k2 != key && !strings.Contains(raw, "#")) {
			t.Fatalf("not idempotent: %q -> %q -> %q", raw, purl, p2)
		}
	})
}

func FuzzCanonicalVulnID(f *testing.F) {
	for _, s := range []string{"cve-2024-1", "GHSA-AbC-dEf", "DLA-1-1", "", "ghsa-"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		once := CanonicalVulnID(id)
		if CanonicalVulnID(once) != once {
			t.Fatalf("not idempotent: %q -> %q", id, once)
		}
	})
}
