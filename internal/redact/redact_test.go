package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	cases := map[string]string{
		"Authorization: Bearer abc.def.ghi-123456":                       "abc.def.ghi-123456",
		"GET https://user:s3cr3t@registry.example.com/v2/":               "s3cr3t",
		"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "wJalrXUtnFEMI",
		"key AKIAIOSFODNN7EXAMPLE used":                                  "AKIAIOSFODNN7EXAMPLE",
		"token glpat-ABCDEFGHIJKLMNOPQRST rejected":                      "glpat-ABCDEFGHIJKLMNOPQRST",
		// The gitlab registry provider's credentials: job token, deploy token, API headers.
		"login gitlab-ci-token:glcbt-64_abcdefghij0123456789 failed": "glcbt-64_abcdefghij0123456789",
		"deploy token gldt-abcdefghijklmnopqrst refused":             "gldt-abcdefghijklmnopqrst",
		"JOB-TOKEN: 64_opaquejobtokenvalue12345":                     "64_opaquejobtokenvalue12345",
		"PRIVATE-TOKEN: opaque-api-token-without-prefix":             "opaque-api-token-without-prefix",
		// The webhook notifier's signing secret.
		"secret whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw is too short":                                       "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789":                                                         "ghp_abcdefghijklmnopqrstuvwxyz",
		"https://s3.amazonaws.com/x?X-Amz-Signature=deadbeef&a=1":                                          "deadbeef",
		`{"password": "hunter2"}`:                                                                          "hunter2",
		"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U": "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
	}
	for in, secret := range cases {
		out := String(in)
		if strings.Contains(out, secret) {
			t.Errorf("secret survived redaction: %q -> %q", in, out)
		}
		if !strings.Contains(out, "REDACTED") {
			t.Errorf("no redaction marker: %q -> %q", in, out)
		}
	}
}

func TestStringKeepsOrdinaryText(t *testing.T) {
	in := "GET https://index.docker.io/v2/library/alpine/manifests/3.18.0: 404 Not Found"
	if out := String(in); out != in {
		t.Errorf("ordinary text changed: %q", out)
	}
}
