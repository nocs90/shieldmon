package owners

import (
	"slices"
	"strings"
	"testing"

	"github.com/nocs90/shieldmon/internal/config"
)

func TestOwnership(t *testing.T) {
	o, err := New([]config.Owner{
		{Team: "checkout", Contact: "checkout@example.com", Targets: []string{"registry.example.com/payments/checkout"}},
		{Team: "payments", Targets: []string{"registry.example.com/payments/*"}},
		{Team: "platform", Targets: []string{"nginx", "ghcr.io/example/tools:2.*", "alpine:3.20"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for ref, want := range map[string]string{
		"registry.example.com/payments/checkout:1.4":                          "checkout", // first match wins
		"registry.example.com/payments/api:1.4":                               "payments",
		"registry.example.com/payments/api@sha256:" + strings.Repeat("a", 64): "payments",
		"registry.example.com/payments/team/api:1":                            "", // * stays within a path segment
		"index.docker.io/library/nginx:1.27":                                  "platform",
		"ghcr.io/example/tools:2.1":                                           "platform",
		"ghcr.io/example/tools:3.0":                                           "",
		"index.docker.io/library/alpine:3.20":                                 "platform",
		"index.docker.io/library/alpine:3.21":                                 "", // a pattern with a tag owns that tag only
	} {
		if got := o.Of(ref); got != want {
			t.Errorf("%s: owner %q, want %q", ref, got, want)
		}
	}
	if got := o.Teams([]string{"registry.example.com/payments/api:1 (linux/amd64)", "x.test/y:1 (linux/amd64)", "registry.example.com/payments/checkout:2 (linux/arm64)"}); !slices.Equal(got, []string{"-", "checkout", "payments"}) {
		t.Errorf("teams = %v", got)
	}
	if o.Contact("checkout") != "checkout@example.com" || !o.Has("platform") || o.Has("nobody") {
		t.Error("contact and lookup")
	}
	var none Ownership
	if none.Of("index.docker.io/library/nginx:1") != "" {
		t.Error("no configuration owns nothing")
	}
}

func TestOwnersValidated(t *testing.T) {
	for _, c := range []struct {
		owners []config.Owner
		want   string
	}{
		{[]config.Owner{{Team: "Payments", Targets: []string{"a.test/b"}}}, "lowercase"},
		{[]config.Owner{{Team: "-", Targets: []string{"a.test/b"}}}, "lowercase"},
		{[]config.Owner{{Team: "a", Targets: []string{"a.test/b"}}, {Team: "a", Targets: []string{"c.test/d"}}}, "twice"},
		{[]config.Owner{{Team: "a"}}, "at least one pattern"},
		{[]config.Owner{{Team: "a", Targets: []string{"a.test/[b"}}}, "syntax"},
		{[]config.Owner{{Team: "a", Targets: []string{"a.test/b c"}}}, "without spaces"},
		{[]config.Owner{{Team: "a", Targets: []string{"-x"}}}, "invalid"},
		{[]config.Owner{{Team: "a", Contact: "x\r\nBcc: evil", Targets: []string{"a.test/b"}}}, "printable"},
	} {
		if _, err := New(c.owners); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.owners, err, c.want)
		}
	}
}
