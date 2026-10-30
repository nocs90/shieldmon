package redact

import (
	"errors"
	"fmt"
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
		// Chat notifiers: webhook URLs and tokens.
		"POST https://hooks.slack.com/services/T0000/B0000/XXXXsecretXXXX failed": "XXXXsecretXXXX",
		"POST https://mm.example.com/hooks/abcdefghijklmnopqrstuvwxyz failed":     "abcdefghijklmnopqrstuvwxyz",
		"token xoxb-1234567890-abcdefghij rejected":                               "xoxb-1234567890-abcdefghij",
		"M_UNKNOWN_TOKEN syt_c2hpZWxkbW9u_s3cretmatrixtoken_0abc12":               "syt_c2hpZWxkbW9u",
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

func TestError(t *testing.T) {
	if Error(nil) != "" {
		t.Error("nil is no message")
	}
	inner := errors.New("GET https://ci:glcbt-64_abcdefghij0123456789@gitlab.example.com/v2/: 401")
	got := Error(fmt.Errorf("resolve registry.example.com/app:1: %w", inner))
	if strings.Contains(got, "glcbt-64_abcdefghij") || !strings.HasPrefix(got, "resolve registry.example.com/app:1: GET https://") {
		t.Errorf("wrapped errors are redacted whole, the rest kept: %q", got)
	}
}
