package oci

import (
	"fmt"
	"path"
	"strings"
	"unicode"

	"github.com/google/go-containerregistry/pkg/name"
)

// maxPattern bounds a reference pattern.
const maxPattern = 512

// RefPattern validates a pattern over image references (path.Match syntax: '*' stays within a
// path segment). A pattern without wildcards is a reference, normalized: a repository stands
// for all its tags, a reference with a tag or digest for itself.
func RefPattern(p string) (string, error) {
	if p == "" || len(p) > maxPattern || strings.ContainsFunc(p, unicode.IsSpace) {
		return "", fmt.Errorf("want a reference pattern of at most %d characters without spaces", maxPattern)
	}
	if _, err := path.Match(p, ""); err != nil {
		return "", err
	}
	if strings.ContainsAny(p, `*?[\`) {
		return dockerHub(p), nil
	}
	ref, err := ParseReference(p, false)
	if err != nil {
		return "", err
	}
	if strings.Contains(p[strings.LastIndex(p, "/")+1:], ":") || strings.Contains(p, "@") {
		return ref.Name(), nil
	}
	return ref.Context().Name(), nil
}

// dockerHub writes a wildcard pattern for Docker Hub as references are stored: docker.io and
// host-less patterns become index.docker.io, official images library/NAME.
func dockerHub(p string) string {
	host, rest, found := strings.Cut(p, "/")
	switch {
	case found && host == "docker.io":
		p = rest
	case found && (strings.ContainsAny(host, `.:*?[\`) || host == "localhost"):
		return p // another registry, or any
	}
	if !strings.Contains(p, "/") {
		p = "library/" + p
	}
	return "index.docker.io/" + p
}

// MatchRef reports whether a normalized reference, or its repository, matches a pattern
// returned by RefPattern.
func MatchRef(pattern, ref string) bool {
	if ok, _ := path.Match(pattern, ref); ok {
		return true
	}
	if r, err := name.ParseReference(ref); err == nil {
		ok, _ := path.Match(pattern, r.Context().Name())
		return ok
	}
	return false
}
