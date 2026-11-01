package lineage

import (
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/config"
)

func TestSuccessors(t *testing.T) {
	s, err := NewSuccessors([]config.Successor{
		{From: "registry.access.redhat.com/ubi9/nodejs-20-minimal", To: "registry.access.redhat.com/ubi9/nodejs-22-minimal:latest"},
		{From: "docker.io/library/python:3.11*", To: "python:3.13-slim"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for base, want := range map[string]string{
		"registry.access.redhat.com/ubi9/nodejs-20-minimal:latest": "registry.access.redhat.com/ubi9/nodejs-22-minimal:latest",
		"registry.access.redhat.com/ubi9/nodejs-20-minimal:1-63":   "registry.access.redhat.com/ubi9/nodejs-22-minimal:latest",
		"registry.access.redhat.com/ubi9/nodejs-22-minimal:latest": "",
		"index.docker.io/library/python:3.11-slim":                 "index.docker.io/library/python:3.13-slim", // docker.io patterns match Docker Hub references
		"index.docker.io/library/alpine:3.20":                      "",
	} {
		if got := s.For(base); got != want {
			t.Errorf("%s: successor %q, want %q", base, got, want)
		}
	}
	for _, c := range []struct {
		cfg  config.Successor
		want string
	}{
		{config.Successor{From: "a.test/[x", To: "a.test/y:1"}, "syntax"},
		{config.Successor{From: "a.test/x", To: "a.test/y@sha256:" + strings.Repeat("a", 64)}, "tag to follow"},
		{config.Successor{From: "a.test/x", To: "-y"}, "invalid"},
	} {
		if _, err := NewSuccessors([]config.Successor{c.cfg}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c.cfg, err)
		}
	}
}

func TestFreshness(t *testing.T) {
	if since, src := Freshness(nil, now); !since.IsZero() || src != "" {
		t.Error("nothing observed")
	}
	created := now.Add(-40 * day)
	if since, src := Freshness([]Observation{{ObservedAt: now.Add(-day), Created: created}}, now); !since.Equal(created) || src != "created" {
		t.Errorf("never seen moving: %v %s", since, src)
	}
	moved := []Observation{{ObservedAt: now.Add(-90 * day)}, {ObservedAt: now.Add(-3 * day), Created: created}}
	if since, src := Freshness(moved, now); !since.Equal(now.Add(-3*day)) || src != "observed" {
		t.Errorf("seen moving: %v %s", since, src)
	}
	_ = time.Second
}
