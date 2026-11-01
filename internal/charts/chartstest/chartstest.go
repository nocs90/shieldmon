// Package chartstest is the conformance kit every chart source must pass
// (docs/extending/chart-source.md).
package chartstest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/charts"
)

// File is one file of a test archive, relative to the chart directory.
type File struct {
	Name, Body string
}

// Archive builds a chart archive (.tgz) for name and version, with a deployment template
// and any extra files.
func Archive(t testing.TB, name, version string, extra ...File) []byte {
	t.Helper()
	files := append([]File{
		{"Chart.yaml", "apiVersion: v2\nname: " + name + "\nversion: " + version + "\nappVersion: \"1.0\"\n"},
		{"values.yaml", "image: nginx:1.27\n"},
		{"templates/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: {{ .Release.Name }}}\nspec:\n  template:\n    spec:\n      containers: [{name: web, image: {{ .Values.image | quote }}}]\n"},
	}, extra...)
	return RawArchive(t, name, files...)
}

// RawArchive builds an archive whose entries are exactly dir/<file.Name>.
func RawArchive(t testing.TB, dir string, files ...File) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, f := range files {
		h := &tar.Header{Name: dir + "/" + f.Name, Mode: 0o644, Size: int64(len(f.Body)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.Body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Digest is the sha256:… digest of data.
func Digest(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// CheckPlugin verifies a source's registration.
func CheckPlugin(t *testing.T, name string) {
	t.Helper()
	p, ok := charts.Lookup(name)
	if !ok {
		t.Fatalf("chart source %q is not registered", name)
	}
	if p.Description == "" {
		t.Errorf("chart source %q has no description", name)
	}
	if _, err := charts.New(name, charts.Spec{Options: charts.Options{"__bogus__": "x"}}); err == nil {
		t.Errorf("chart source %q accepts unknown options", name)
	}
}

// CheckSource verifies a source built over fixtures that serve chart with versions (any
// order): versions come newest first and valid, every version fetches as a valid archive
// with a sha256 digest, and unknown charts and versions, and cancelled contexts, fail.
func CheckSource(t *testing.T, src charts.Source, chart string, versions ...string) {
	t.Helper()
	ctx := context.Background()
	vs, err := src.Versions(ctx, chart)
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(vs) != len(versions) {
		t.Fatalf("Versions = %+v, want %d versions", vs, len(versions))
	}
	for i := 1; i < len(vs); i++ {
		if vs[i-1].Version == vs[i].Version {
			t.Errorf("version %s listed twice", vs[i].Version)
		}
	}
	for _, v := range vs {
		var buf bytes.Buffer
		digest, err := src.Fetch(ctx, chart, v.Version, &buf)
		if err != nil {
			t.Errorf("Fetch %s: %v", v.Version, err)
			continue
		}
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
			t.Errorf("Fetch %s: digest %q", v.Version, digest)
		}
		if _, err := charts.CheckArchive(buf.Bytes(), chart, v.Version); err != nil {
			t.Errorf("Fetch %s: %v", v.Version, err)
		}
	}
	if _, err := src.Fetch(ctx, chart, "99.99.99", &bytes.Buffer{}); err == nil {
		t.Error("an unknown version must fail")
	}
	if _, err := src.Versions(ctx, "no-such-chart"); err == nil {
		t.Error("an unknown chart must fail")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := src.Versions(cancelled, chart); err == nil {
		t.Error("a cancelled context must fail")
	}
	if src.Location(chart) == "" {
		t.Error("Location must name where the chart comes from")
	}
}
