package oci

import "testing"

func TestRefPattern(t *testing.T) {
	for _, c := range []struct {
		pattern, ref string
		want         bool
	}{
		{"registry.example.com/payments/*", "registry.example.com/payments/api:1.4", true},
		{"registry.example.com/payments/*", "registry.example.com/payments/team/api:1", false},
		{"registry.example.com/payments/*/*", "registry.example.com/payments/team/api:1", true},
		{"nginx", "index.docker.io/library/nginx:1.27", true},
		{"nginx", "index.docker.io/library/nginx-unprivileged:1", false},
		{"alpine:3.20", "index.docker.io/library/alpine:3.20", true},
		{"alpine:3.20", "index.docker.io/library/alpine:3.21", false},
		{"docker.io/library/python:3.11*", "index.docker.io/library/python:3.11-slim", true},
		{"python:3.11*", "index.docker.io/library/python:3.11-alpine", true},
		{"bitnami/*", "index.docker.io/bitnami/redis:7", true},
		{"*/payments/*", "registry.example.com/payments/api:1", true},
		{"localhost:5000/*", "localhost:5000/app:1", true},
		{"ghcr.io/example/*", "ghcr.io/example/tools@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
	} {
		p, err := RefPattern(c.pattern)
		if err != nil {
			t.Fatalf("%s: %v", c.pattern, err)
		}
		if got := MatchRef(p, c.ref); got != c.want {
			t.Errorf("%s (%s) on %s: %v, want %v", c.pattern, p, c.ref, got, c.want)
		}
	}
	for _, bad := range []string{"", "a b", "a.test/[x", "-x"} {
		if _, err := RefPattern(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
