package oci

import (
	"strings"
	"testing"
)

// FuzzBaseAnnotations: whatever an image's builder writes in the base annotations, what is
// kept is a bounded tag reference and a sha256 digest with its repository.
func FuzzBaseAnnotations(f *testing.F) {
	f.Add("registry.example.com/base:1", "sha256:"+strings.Repeat("a", 64))
	f.Add("registry.example.com/base@sha256:"+strings.Repeat("b", 64), "")
	f.Add("-x $(id)", "md5:00")
	f.Add("", "sha256:"+strings.Repeat("c", 64))
	f.Fuzz(func(t *testing.T, name, digest string) {
		var info ImageInfo
		info.baseAnnotations(map[string]string{AnnotationBaseName: name, AnnotationBaseDigest: digest})
		if len(info.BaseName) > 2*maxAnnotationValue || strings.HasPrefix(info.BaseName, "-") || strings.ContainsAny(info.BaseName, " \t\r\n@") {
			t.Fatalf("kept unsafe base name %q from %q", info.BaseName, name)
		}
		if info.BaseDigest != "" && (!sha256Digest.MatchString(info.BaseDigest) || info.BaseRepository == "") {
			t.Fatalf("kept digest %q without a valid form or repository %q", info.BaseDigest, info.BaseRepository)
		}
	})
}

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
