package charts_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nocs90/shieldmon/internal/charts"
	"github.com/nocs90/shieldmon/internal/charts/chartstest"
)

// repo serves an HTTP chart repository: index.yaml and the archives of chart's versions.
func repo(t *testing.T, chart string, versions ...string) (*httptest.Server, map[string][]byte) {
	t.Helper()
	h, archives := repoHandler(t, chart, versions...)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, archives
}

// publicRepo serves the repository over TLS, and returns a client that reaches it as
// https://example.com: what remote content may name.
func publicRepo(t *testing.T, chart string, versions ...string) *http.Client {
	t.Helper()
	h, _ := repoHandler(t, chart, versions...)
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	c := srv.Client()
	tr := c.Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	c.Transport = tr
	return c
}

func repoHandler(t *testing.T, chart string, versions ...string) (http.Handler, map[string][]byte) {
	t.Helper()
	archives := map[string][]byte{}
	var idx strings.Builder
	idx.WriteString("apiVersion: v1\nentries:\n  " + chart + ":\n")
	for _, v := range versions {
		a := chartstest.Archive(t, chart, v)
		archives[v] = a
		fmt.Fprintf(&idx, "    - version: %s\n      appVersion: \"1.0\"\n      created: 2026-10-01T00:00:00Z\n      digest: %s\n      urls: [%s-%s.tgz]\n",
			v, strings.TrimPrefix(chartstest.Digest(a), "sha256:"), chart, v)
	}
	idx.WriteString("  other:\n    - version: 1.0.0\n      urls: [other-1.0.0.tgz]\n")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/charts/index.yaml" {
			_, _ = io.WriteString(w, idx.String())
			return
		}
		for v, a := range archives {
			if r.URL.Path == "/charts/"+chart+"-"+v+".tgz" {
				_, _ = w.Write(a)
				return
			}
		}
		http.NotFound(w, r)
	}), archives
}

func TestHTTPSource(t *testing.T) {
	chartstest.CheckPlugin(t, "http")
	srv, archives := repo(t, "web", "1.2.0", "1.10.0", "1.9.3", "2.0.0-rc.1")
	src, err := charts.New("http", charts.Spec{Options: charts.Options{"url": srv.URL + "/charts"}})
	if err != nil {
		t.Fatal(err)
	}
	chartstest.CheckSource(t, src, "web", "1.2.0", "1.10.0", "1.9.3", "2.0.0-rc.1")
	vs, _ := src.Versions(context.Background(), "web")
	var order []string
	for _, v := range vs {
		order = append(order, v.Version)
	}
	if strings.Join(order, " ") != "2.0.0-rc.1 1.10.0 1.9.3 1.2.0" || vs[1].Digest != chartstest.Digest(archives["1.10.0"]) {
		t.Errorf("newest first by SemVer, with the index's digest: %+v", vs)
	}
	for what, url := range map[string]string{"plain http": "http://charts.example.com", "credentials": "https://u:p@charts.example.com", "relative": "/charts"} {
		if _, err := charts.New("http", charts.Spec{Options: charts.Options{"url": url}}); err == nil {
			t.Errorf("%s accepted", what)
		}
	}
}

// A version listed twice keeps its first entry in Versions and Fetch alike: the digest that
// Versions reports is the one Fetch verifies.
func TestHTTPSourceDuplicateVersions(t *testing.T) {
	a := chartstest.Archive(t, "web", "1.0.0")
	idx := fmt.Sprintf("entries:\n  web:\n    - {version: 1.0.0, digest: %s, urls: [web.tgz]}\n    - {version: 1.0.0, digest: %s, urls: [web.tgz]}\n",
		strings.TrimPrefix(chartstest.Digest(a), "sha256:"), strings.Repeat("ab", 32))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.yaml" {
			_, _ = io.WriteString(w, idx)
			return
		}
		_, _ = w.Write(a)
	}))
	defer srv.Close()
	src, err := charts.New("http", charts.Spec{Options: charts.Options{"url": srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	vs, err := src.Versions(context.Background(), "web")
	if err != nil || len(vs) != 1 || vs[0].Digest != chartstest.Digest(a) {
		t.Fatalf("versions: %+v %v", vs, err)
	}
	if d, err := src.Fetch(context.Background(), "web", "1.0.0", io.Discard); err != nil || d != vs[0].Digest {
		t.Errorf("fetch: %s %v", d, err)
	}
}

func TestHTTPSourceRefusesTamperedArchives(t *testing.T) {
	good := chartstest.Archive(t, "web", "1.0.0")
	evil := chartstest.Archive(t, "web", "1.0.0", chartstest.File{Name: "templates/x.yaml", Body: "kind: Pod"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.yaml":
			fmt.Fprintf(w, "entries:\n  web:\n    - {version: 1.0.0, digest: %s, urls: [web.tgz]}\n  far:\n    - {version: 1.0.0, urls: [\"http://elsewhere.example.com/far.tgz\"]}\n  big:\n    - {version: 1.0.0, urls: [big.tgz]}\n",
				strings.TrimPrefix(chartstest.Digest(good), "sha256:"))
		case "/web.tgz":
			_, _ = w.Write(evil)
		case "/big.tgz":
			_, _ = w.Write(bytes.Repeat([]byte("x"), charts.MaxArchiveBytes+1))
		}
	}))
	defer srv.Close()
	src, err := charts.New("http", charts.Spec{Options: charts.Options{"url": srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	for chart, want := range map[string]string{"web": "the index says", "far": "https", "big": "larger than"} {
		if _, err := src.Fetch(context.Background(), chart, "1.0.0", io.Discard); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", chart, err)
		}
	}
}

// fakeOCI holds chart archives by repository:tag.
type fakeOCI map[string][]byte

func (f fakeOCI) Tags(ctx context.Context, repo string, _ int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var tags []string
	for ref := range f {
		if r, tag, _ := strings.Cut(ref, ":"); r == repo {
			tags = append(tags, tag)
		}
	}
	if tags == nil {
		return nil, errors.New("repository not found")
	}
	return append(tags, "latest", "sha256-abc.sig"), nil
}

func (f fakeOCI) Fetch(ctx context.Context, ref string, maxBytes int64, w io.Writer) (string, error) {
	a, ok := f[ref]
	if !ok {
		return "", errors.New("manifest unknown")
	}
	if int64(len(a)) > maxBytes {
		return "", errors.New("too large")
	}
	_, err := w.Write(a)
	return chartstest.Digest(a), err
}

func TestOCISource(t *testing.T) {
	chartstest.CheckPlugin(t, "oci")
	reg := fakeOCI{
		"ghcr.io/acme/charts/web:1.0.0":      chartstest.Archive(t, "web", "1.0.0"),
		"ghcr.io/acme/charts/web:1.1.0_meta": chartstest.Archive(t, "web", "1.1.0+meta"),
	}
	src, err := charts.New("oci", charts.Spec{Options: charts.Options{"repository": "oci://ghcr.io/acme/charts"}, OCI: reg})
	if err != nil {
		t.Fatal(err)
	}
	chartstest.CheckSource(t, src, "web", "1.0.0", "1.1.0+meta")
	if src.Location("web") != "oci://ghcr.io/acme/charts/web" {
		t.Errorf("location %q", src.Location("web"))
	}
	if _, err := src.Versions(context.Background(), "../x"); err == nil {
		t.Error("a chart name is a single path component")
	}
	for _, repo := range []string{"", "ghcr.io", "GHCR.io/x", "https://ghcr.io/x"} {
		if _, err := charts.New("oci", charts.Spec{Options: charts.Options{"repository": repo}, OCI: reg}); err == nil {
			t.Errorf("repository %q accepted", repo)
		}
	}
}

func TestArtifactHubSource(t *testing.T) {
	chartstest.CheckPlugin(t, "artifacthub")
	public := publicRepo(t, "web", "1.0.0", "1.1.0")
	// What Artifact Hub answers is remote content: the repository it names must be public.
	answers := map[string]string{
		"web":      "https://example.com/charts",
		"loop":     "http://127.0.0.1:8080/charts",
		"private":  "https://10.0.0.7/charts",
		"meta":     "https://169.254.169.254/latest",
		"internal": "oci://192.168.1.10:5000/charts",
		"local":    "https://localhost/charts",
	}
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/packages/helm/acme/")
		if u, ok := answers[name]; ok {
			fmt.Fprintf(w, `{"name":%q,"repository":{"name":"acme","url":%q},"readme":"…"}`, name, u)
			return
		}
		http.NotFound(w, r)
	}))
	defer hub.Close()
	src, err := charts.New("artifacthub", charts.Spec{Options: charts.Options{"repository": "acme", "url": hub.URL + "/api/v1"}, Public: public, OCI: fakeOCI{}})
	if err != nil {
		t.Fatal(err)
	}
	chartstest.CheckSource(t, src, "web", "1.0.0", "1.1.0")
	if src.Location("web") != "https://example.com/charts web" {
		t.Errorf("the location is the chart's own repository: %q", src.Location("web"))
	}
	for _, name := range []string{"loop", "private", "meta", "internal", "local"} {
		if _, err := src.Versions(context.Background(), name); err == nil {
			t.Errorf("%s: Artifact Hub sent ShieldMon to %s", name, answers[name])
		}
	}
}

func TestPublicRegistry(t *testing.T) {
	for host, want := range map[string]bool{
		"index.docker.io": true, "ghcr.io": true, "registry.k8s.io:443": true, "8.8.8.8:5000": true,
		"localhost:5000": false, "registry.localhost": false, "127.0.0.1": false, "10.0.0.12:2379": false,
		"192.168.1.1": false, "[::1]:5000": false, "169.254.169.254": false, "100.64.0.1": false,
		"registry": false, "kubernetes.default.svc": false, "harbor.svc.cluster.local": false,
		"nexus.corp": false, "printer.local": false, "Registry.Internal:443": false,
		"localhost.:5000": false, "metadata.google.internal.": false, "x.svc.cluster.local.": false,
		"127.1:5000": false, "0x7f.1": false, "10.1": false, "ghcr.io.": true, "registry.xn--p1ai": true,
	} {
		if got := charts.PublicRegistry(host); got != want {
			t.Errorf("PublicRegistry(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestRemoteContentReachesPublicAddressesOnly(t *testing.T) {
	// A trusted repository's index points elsewhere: only https to public hosts.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.yaml" {
			_, _ = io.WriteString(w, "entries:\n"+
				"  loop:\n    - {version: 1.0.0, urls: [\"http://127.0.0.1:15000/admin\"]}\n"+
				"  meta:\n    - {version: 1.0.0, urls: [\"https://169.254.169.254/latest/meta-data\"]}\n"+
				"  reg:\n    - {version: 1.0.0, urls: [\"oci://10.1.2.3:5000/charts/reg:1.0.0\"]}\n"+
				"  odd:\n    - {version: 1.0.0, digest: \"sha512:abcd\", urls: [odd.tgz]}\n")
		}
	}))
	defer srv.Close()
	src, err := charts.New("http", charts.Spec{Options: charts.Options{"url": srv.URL}, OCI: fakeOCI{}})
	if err != nil {
		t.Fatal(err)
	}
	for chart, want := range map[string]string{"loop": "https", "meta": "not public", "reg": "not public", "odd": "not a SHA-256"} {
		if _, err := src.Fetch(context.Background(), chart, "1.0.0", io.Discard); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", chart, err)
		}
	}
	// The guarded client refuses private addresses even behind a public-looking name.
	c := charts.PublicClient()
	for _, u := range []string{"https://127.0.0.1:1/", "https://[::1]:1/", "https://10.0.0.1:1/"} {
		resp, err := c.Get(u)
		if err == nil {
			resp.Body.Close()
		}
		if !errors.Is(err, charts.ErrNotPublic) {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestCheckArchive(t *testing.T) {
	good := chartstest.Archive(t, "web", "1.0.0")
	if m, err := charts.CheckArchive(good, "web", "1.0.0"); err != nil || m.AppVersion != "1.0" {
		t.Fatalf("%+v %v", m, err)
	}
	for what, c := range map[string]struct {
		data          []byte
		name, version string
	}{
		"other version":   {good, "web", "1.0.1"},
		"other chart":     {good, "api", "1.0.0"},
		"not gzip":        {[]byte("PK\x03\x04"), "web", "1.0.0"},
		"no Chart.yaml":   {chartstest.RawArchive(t, "web", chartstest.File{Name: "values.yaml", Body: "a: 1"}), "web", "1.0.0"},
		"escaping path":   {chartstest.RawArchive(t, "web/../..", chartstest.File{Name: "Chart.yaml", Body: "name: web\nversion: 1.0.0"}), "web", "1.0.0"},
		"two top dirs":    {append(chartstest.Archive(t, "web", "1.0.0"), chartstest.RawArchive(t, "evil", chartstest.File{Name: "x", Body: "y"})...), "web", "1.0.0"},
		"name mismatch":   {chartstest.RawArchive(t, "web", chartstest.File{Name: "Chart.yaml", Body: "name: api\nversion: 1.0.0"}), "web", "1.0.0"},
		"too much inside": {chartstest.RawArchive(t, "web", chartstest.File{Name: "Chart.yaml", Body: "name: web\nversion: 1.0.0"}, chartstest.File{Name: "big", Body: strings.Repeat("a", charts.MaxUnpackedBytes+1)}), "web", "1.0.0"},
	} {
		if _, err := charts.CheckArchive(c.data, c.name, c.version); !errors.Is(err, charts.ErrArchive) {
			t.Errorf("%s: %v", what, err)
		}
	}
}

// linkArchive is a chart directory holding a symbolic link.
func linkArchive(t *testing.T, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	body := "name: " + name + "\nversion: 1.0.0\n"
	_ = tw.WriteHeader(&tar.Header{Name: name + "/Chart.yaml", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte(body))
	_ = tw.WriteHeader(&tar.Header{Name: name + "/templates/x.yaml", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func TestCheckArchiveSubchartsAndKeys(t *testing.T) {
	sub := chartstest.Archive(t, "redis", "18.0.0")
	withSub := chartstest.Archive(t, "web", "1.0.0", chartstest.File{Name: "charts/redis-18.0.0.tgz", Body: string(sub)})
	if _, err := charts.CheckArchive(withSub, "web", "1.0.0"); err != nil {
		t.Fatalf("a bundled subchart is fine: %v", err)
	}
	nest := func(depth int) []byte {
		a := chartstest.Archive(t, "leaf", "1.0.0")
		for i := range depth {
			a = chartstest.Archive(t, fmt.Sprintf("level%d", i), "1.0.0", chartstest.File{Name: "charts/x.tgz", Body: string(a)})
		}
		return chartstest.Archive(t, "web", "1.0.0", chartstest.File{Name: "charts/x.tgz", Body: string(a)})
	}
	if _, err := charts.CheckArchive(nest(1), "web", "1.0.0"); err != nil {
		t.Errorf("two levels: %v", err)
	}
	for what, data := range map[string][]byte{
		"a link in a subchart": chartstest.Archive(t, "web", "1.0.0", chartstest.File{Name: "charts/evil-1.0.0.tgz", Body: string(linkArchive(t, "evil"))}),
		"a broken subchart":    chartstest.Archive(t, "web", "1.0.0", chartstest.File{Name: "charts/evil.tgz", Body: "not gzip"}),
		"nested too deep":      nest(charts.MaxSubchartDepth + 1),
		"a case-folded key":    chartstest.RawArchive(t, "web", chartstest.File{Name: "Chart.yaml", Body: "name: web\nversion: 1.0.0\nVersion: 9.9.9\n"}),
		"a lookalike key":      chartstest.RawArchive(t, "web", chartstest.File{Name: "Chart.yaml", Body: "NAME: evil\nname: web\nversion: 1.0.0\n"}),
		"a duplicate entry": chartstest.RawArchive(t, "web",
			chartstest.File{Name: "Chart.yaml", Body: "name: web\nversion: 1.0.0\n"}, chartstest.File{Name: "Chart.yaml", Body: "name: evil\nversion: 9.9.9\n"}),
	} {
		if _, err := charts.CheckArchive(data, "web", "1.0.0"); !errors.Is(err, charts.ErrArchive) {
			t.Errorf("%s: %v", what, err)
		}
	}
}
