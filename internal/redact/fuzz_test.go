package redact

import (
	"strings"
	"testing"
)

func FuzzString(f *testing.F) {
	f.Add("Authorization: Bearer abcdefghijklmnop")
	f.Add("https://u:p@host/x?X-Amz-Signature=abc")
	f.Add("token=glpat-ABCDEFGHIJKLMNOPQRST")
	f.Fuzz(func(t *testing.T, s string) {
		out := String(s)
		// Redaction must be stable: redacting twice changes nothing more.
		if String(out) != out {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, out, String(out))
		}
		if strings.Contains(s, "AKIA") && strings.Contains(out, s) && len(s) > 40 {
			t.Logf("input unchanged: %q", s)
		}
	})
}
