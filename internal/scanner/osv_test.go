package scanner

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

// fakeRun is what the fake osv-scanner does for one kind of scan.
type fakeRun struct {
	output, stderr string
	status         int
	// downloads are the databases a --download-offline-databases run creates.
	downloads []string
}

// fakeOSV is an osv-scanner stand-in: --version prints a version; a scan logs its
// arguments, keeps a copy of the -L file, and behaves as match or (with
// --download-offline-databases) as update says.
func fakeOSV(t *testing.T, match, update fakeRun) (Binary, string, func() []string) {
	t.Helper()
	dir := t.TempDir()
	log, bin := filepath.Join(dir, "log"), filepath.Join(dir, "osv-scanner")
	behave := func(name string, r fakeRun) string {
		out, errf := filepath.Join(dir, name+".out"), filepath.Join(dir, name+".err")
		if err := os.WriteFile(out, []byte(r.output), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(errf, []byte(r.stderr), 0o600); err != nil {
			t.Fatal(err)
		}
		s := ""
		for _, e := range r.downloads {
			// Like osv-scanner, an unchanged database is left as it is.
			f := `"$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY/osv-scalibr/` + e + `/all.zip"`
			s += `[ -e ` + f + ` ] || { mkdir -p "$(dirname ` + f + `)" && : > ` + f + `; }` + "\n"
		}
		return s + "cat " + out + "; cat " + errf + " >&2; exit " + strconv.Itoa(r.status) + "\n"
	}
	script := `#!/bin/sh
if [ "$1" = --version ]; then echo "osv-scanner version: 2.7.0"; echo "commit: n/a"; exit 0; fi
printf '%s ' "$@" >> ` + log + `; echo >> ` + log + `
prev=""; for a in "$@"; do [ "$prev" = -L ] && cp "$a" ` + filepath.Join(dir, "input.json") + `; prev="$a"; done
case " $* " in *" --download-offline-databases "*)
` + behave("update", update) + `;;
esac
` + behave("match", match)
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return Binary{Name: "osv-scanner", Path: bin}, filepath.Join(dir, "input.json"), func() []string {
		b, _ := os.ReadFile(log)
		_ = os.Remove(log)
		if len(b) == 0 {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
}

// placeDB creates an ecosystem's database file under the runner's cache directory.
func placeDB(t *testing.T, cache, ecosystem string, mtime time.Time) {
	t.Helper()
	f := filepath.Join(cache, "osv-scanner", "osv-scalibr", ecosystem, "all.zip")
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(f, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func writeSBOM(t *testing.T, purls ...string) string {
	t.Helper()
	var comps []string
	for i, p := range purls {
		comps = append(comps, `{"type":"library","bom-ref":"c`+strconv.Itoa(i)+`","name":"n","version":"1","purl":"`+p+`"}`)
	}
	p := filepath.Join(t.TempDir(), "syft.cyclonedx-json.json")
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"img"}},"components":[` +
		strings.Join(comps, ",") + `],"dependencies":[{"ref":"c0","dependsOn":["c1"]}]}`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const osvOutput = `{"results":[{"source":{"path":"/x/sbom.cdx.json","type":"sbom"},"packages":[
 {"package":{"name":"busybox","version":"1.36.0-r9","ecosystem":"Alpine:v3.18","purl":"pkg:apk/alpine/busybox@1.36.0-r9?distro=alpine-3.18.0"},
  "vulnerabilities":[{"id":"ALPINE-CVE-2023-42363","upstream":["CVE-2023-42363"],"details":"A use-after-free in busybox awk.\nMore.",
    "affected":[{"package":{"ecosystem":"Alpine:v3.17","name":"busybox"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.35.0-r30"}]}]},
                {"package":{"ecosystem":"Alpine:v3.18","name":"busybox"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.36.1-r6"}]}]}]}],
  "groups":[{"ids":["ALPINE-CVE-2023-42363"],"aliases":["ALPINE-CVE-2023-42363"],"max_severity":"5.5"}]},
 {"package":{"name":"requests","version":"2.0.0","ecosystem":"PyPI","purl":"pkg:pypi/requests@2.0.0"},
  "vulnerabilities":[{"id":"GHSA-x84v-xcm2-53pg","aliases":["CVE-2018-18074"],"summary":"Insufficiently protected credentials",
    "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],"database_specific":{"severity":"HIGH"},
    "affected":[{"package":{"ecosystem":"PyPI","name":"requests"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.20.0"}]}]}]},
   {"id":"PYSEC-2018-28","aliases":["CVE-2018-18074","GHSA-x84v-xcm2-53pg"],"summary":"","details":"Requests sends credentials on redirect."}],
  "groups":[{"ids":["GHSA-x84v-xcm2-53pg","PYSEC-2018-28"],"aliases":["CVE-2018-18074","GHSA-x84v-xcm2-53pg","PYSEC-2018-28"],"max_severity":"7.5"}]},
 {"package":{"name":"left-pad","version":"1.0.0","ecosystem":"npm","purl":"pkg:npm/left-pad@1.0.0"},
  "vulnerabilities":[{"id":"GHSA-aaaa-bbbb-cccc","database_specific":{"severity":"MODERATE"}}],
  "groups":[{"ids":["GHSA-aaaa-bbbb-cccc"],"aliases":["GHSA-aaaa-bbbb-cccc"],"max_severity":""}]},
 {"package":{"name":"bash","version":"5.2","ecosystem":"","purl":"pkg:rpm/redhat/bash@5.2"}}
]}]}`

func TestParseOSV(t *testing.T) {
	res, reported, err := parseOSV([]byte(osvOutput))
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int{"Alpine": 1, "PyPI": 1, "npm": 1}; !maps.Equal(reported, want) {
		t.Errorf("packages per ecosystem = %v, want %v (an empty one is not looked up)", reported, want)
	}
	for what, out := range map[string]string{
		"a vulnerability in no group":          `{"results":[{"packages":[{"package":{"name":"a","version":"1","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-1"}],"groups":[]}]}]}`,
		"vulnerabilities without an ecosystem": `{"results":[{"packages":[{"package":{"name":"a","version":"1","ecosystem":""},"vulnerabilities":[{"id":"GHSA-1"}],"groups":[{"ids":["GHSA-1"]}]}]}]}`,
	} {
		if _, _, err := parseOSV([]byte(out)); err == nil {
			t.Errorf("%s must fail the parse", what)
		}
	}
	if len(res.Matches) != 3 {
		t.Fatalf("one match per group: %+v", res.Matches)
	}
	bb, req, pad := res.Matches[0], res.Matches[1], res.Matches[2]
	if bb.Scanner != "osv-scanner" || bb.VulnID != "ALPINE-CVE-2023-42363" || !slices.Contains(bb.Aliases, "CVE-2023-42363") {
		t.Errorf("distro record keeps its upstream CVE as an alias: %+v", bb)
	}
	if !slices.Equal(bb.FixVersions, []string{"1.36.1-r6"}) || bb.FixState != "fixed" {
		t.Errorf("fix of the package's release only: %+v", bb)
	}
	if bb.Severity != model.SeverityMedium || bb.CVSSScore != 5.5 || bb.Title != "A use-after-free in busybox awk." {
		t.Errorf("busybox: %+v", bb)
	}
	if req.VulnID != "GHSA-x84v-xcm2-53pg" || !slices.Contains(req.Aliases, "PYSEC-2018-28") || !slices.Contains(req.Aliases, "CVE-2018-18074") {
		t.Errorf("a group is one match with every ID as alias: %+v", req)
	}
	if req.Severity != model.SeverityHigh || !strings.HasPrefix(req.CVSSVector, "CVSS:3.1/") || req.Title != "Insufficiently protected credentials" {
		t.Errorf("requests: %+v", req)
	}
	if pad.Severity != model.SeverityMedium || pad.CVSSScore != 0 || pad.FixState != "" {
		t.Errorf("without a score the database's label rates it: %+v", pad)
	}
	if pad.PkgType != "npm" || pad.DataSource != "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc" {
		t.Errorf("left-pad: %+v", pad)
	}
}

var imagePURLs = []string{
	"pkg:apk/alpine/busybox@1.36.0-r9?arch=x86_64&distro=alpine-3.18.0",
	"pkg:pypi/requests@2.0.0",
	"pkg:npm/left-pad@1.0.0",
	"pkg:rpm/redhat/bash@5.2",
	"pkg:generic/thing@1",
}

func TestOSVMatchesOfflineAndChecksItsDatabases(t *testing.T) {
	bin, input, runs := fakeOSV(t, fakeRun{output: osvOutput, status: 1}, fakeRun{})
	cache := t.TempDir()
	built := time.Date(2026, 10, 30, 6, 0, 0, 0, time.UTC)
	o := &OSV{Bin: bin, Runner: Runner{CacheDir: cache, TempDir: t.TempDir()}, Ecosystems: []string{"Alpine", "PyPI", "npm"}}
	sbom := writeSBOM(t, imagePURLs...)

	if _, err := o.Match(context.Background(), sbom); err == nil || !strings.Contains(err.Error(), "Alpine, PyPI, npm") {
		t.Fatalf("matching without the databases must fail, naming them: %v", err)
	}
	placeDB(t, cache, "Alpine", built.Add(time.Hour))
	placeDB(t, cache, "PyPI", built)
	if _, err := o.Match(context.Background(), sbom); err == nil || !strings.Contains(err.Error(), "npm") || strings.Contains(err.Error(), "PyPI") {
		t.Fatalf("a result depending on a missing database is incomplete: %v", err)
	}
	if got := runs(); got != nil {
		t.Errorf("missing databases are found before scanning: %q", got)
	}
	placeDB(t, cache, "npm", built.Add(2*time.Hour))
	res, err := o.Match(context.Background(), sbom)
	if err != nil {
		t.Fatalf("exit status 1 means vulnerabilities found: %v", err)
	}
	if len(res.Matches) != 3 || res.Tool.Name != "osv-scanner" || res.Tool.Version != "2.7.0" || !res.Tool.DBBuilt.Equal(built) {
		t.Errorf("result %+v, tool %+v: DBBuilt is the oldest database used", res.Matches, res.Tool)
	}
	for _, run := range runs() {
		if !strings.HasPrefix(run, "scan source --offline --all-packages --verbosity error ") || strings.Contains(run, "--download-offline-databases") ||
			!strings.HasSuffix(strings.TrimSpace(run), "/sbom.cdx.json") {
			t.Errorf("matching is offline, on a copy named for osv-scanner's CycloneDX parser: %q", run)
		}
	}
	b, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var staged struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
		Metadata     json.RawMessage `json:"metadata"`
		Dependencies json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &staged); err != nil {
		t.Fatal(err)
	}
	var purls []string
	for _, c := range staged.Components {
		purls = append(purls, c.PURL)
	}
	if !slices.Equal(purls, imagePURLs[:3]) || staged.Metadata == nil || staged.Dependencies != nil {
		t.Errorf("osv-scanner sees only the packages ShieldMon checks it can match: %s", b)
	}
	if entries, _ := os.ReadDir(o.Runner.TempDir); len(entries) != 0 {
		t.Errorf("staged copies are removed: %v", entries)
	}
}

func TestOSVRefusesIncompleteResults(t *testing.T) {
	cache := t.TempDir()
	for _, e := range []string{"Alpine", "PyPI", "npm"} {
		placeDB(t, cache, e, time.Now())
	}
	sbom := writeSBOM(t, imagePURLs...)
	for what, c := range map[string]struct {
		run  fakeRun
		want string
	}{
		"an error logged while finding vulnerabilities": {fakeRun{output: osvOutput, status: 1, stderr: "could not load db for PyPI ecosystem: zip: not a valid zip file\n"}, "could not load db for PyPI"},
		"a failure status":                 {fakeRun{output: osvOutput, status: 127}, "exit status 127"},
		"an ecosystem nobody asked for":    {fakeRun{output: strings.ReplaceAll(osvOutput, `"ecosystem":"npm"`, `"ecosystem":"Bitnami"`), status: 1}, "Bitnami"},
		"output that is not osv-scanner's": {fakeRun{output: "<html>", status: 0}, "decode"},
		// A package osv-scanner skipped without an error: its absence must not pass for a fix.
		"a package skipped silently": {fakeRun{output: withoutPackage(osvOutput, "left-pad"), status: 1}, "npm: 0 of 1"},
	} {
		bin, _, _ := fakeOSV(t, c.run, fakeRun{})
		o := &OSV{Bin: bin, Runner: Runner{CacheDir: cache, TempDir: t.TempDir()}, Ecosystems: []string{"Alpine", "PyPI", "npm"}}
		if _, err := o.Match(context.Background(), sbom); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", what, err)
		}
	}

	bin, _, runs := fakeOSV(t, fakeRun{output: osvOutput, status: 1}, fakeRun{})
	o := &OSV{Bin: bin, Runner: Runner{CacheDir: cache, TempDir: t.TempDir()}, Ecosystems: []string{"Alpine", "npm"}}
	if _, err := o.Match(context.Background(), sbom); err == nil || !strings.Contains(err.Error(), "PyPI") || runs() != nil {
		t.Errorf("packages of a supported but unconfigured ecosystem fail before scanning: %v", err)
	}
	for what, s := range map[string]string{"rpm-based image": writeSBOM(t, "pkg:rpm/redhat/bash@5.2", "pkg:generic/x@1"), "no packages": writeSBOM(t)} {
		res, err := o.Match(context.Background(), s)
		if err != nil || len(res.Matches) != 0 || res.Tool.DBBuilt.IsZero() {
			t.Errorf("%s: nothing osv-scanner matches is an empty, dated result: %+v, %v", what, res, err)
		}
		if got := runs(); got != nil {
			t.Errorf("%s: not scanned (osv-scanner fails without packages): %q", what, got)
		}
	}
}

// withoutPackage removes one package's entry from osv-scanner output, as if it had skipped it.
func withoutPackage(out, name string) string {
	var doc struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		panic(err)
	}
	for _, r := range doc.Results {
		ps, _ := r["packages"].([]any)
		r["packages"] = slices.DeleteFunc(ps, func(p any) bool {
			pkg, _ := p.(map[string]any)["package"].(map[string]any)
			return pkg["name"] == name
		})
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// probeOutput is osv-scanner's --all-packages answer to the probe SBOM of ecosystems.
func probeOutput(ecosystems ...string) string {
	var ps []string
	for _, e := range ecosystems {
		ps = append(ps, `{"package":{"name":"shieldmon db-probe","version":"0.0.0","ecosystem":"`+e+`"}}`)
	}
	return `{"results":[{"packages":[` + strings.Join(ps, ",") + `]}]}`
}

func TestOSVDatabaseLinksAreRefused(t *testing.T) {
	cache := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(cache, "osv-scanner", "osv-scalibr", "npm", "all.zip")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	bin, _, _ := fakeOSV(t, fakeRun{}, fakeRun{})
	o := &OSV{Bin: bin, Runner: Runner{CacheDir: cache, TempDir: t.TempDir()}, Ecosystems: []string{"npm"}}
	if _, err := o.Tool(context.Background()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a database that is a link: %v", err)
	}
}

func TestOSVUpdatesConfiguredDatabases(t *testing.T) {
	cache := t.TempDir()
	bin, input, runs := fakeOSV(t, fakeRun{}, fakeRun{output: probeOutput("Alpine", "Go"), downloads: []string{"Alpine", "Go"}})
	o := &OSV{Bin: bin, Runner: Runner{CacheDir: cache, TempDir: t.TempDir()}, DBAutoUpdate: true, Ecosystems: []string{"Alpine", "Go"}}
	old := time.Now().Add(-48 * time.Hour)
	placeDB(t, cache, "Go", old) // unchanged upstream: osv-scanner keeps the file
	start := time.Now().Add(-time.Second)
	if err := o.UpdateDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := runs()
	if len(got) != 1 || !strings.Contains(got[0], "--offline --download-offline-databases --all-packages --verbosity error") {
		t.Errorf("update runs = %q", got)
	}
	probe, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{OSVEcosystems["Alpine"], OSVEcosystems["Go"], `"name":"shieldmon db-probe"`} {
		if !strings.Contains(string(probe), p) {
			t.Errorf("probe SBOM lacks %s: %s", p, probe)
		}
	}
	tool, err := o.Tool(context.Background())
	if err != nil || tool.DBBuilt.Before(start) {
		t.Errorf("a verified database is current as of the update: %+v, %v", tool, err)
	}

	o.Ecosystems = []string{"Alpine", "Go", "Maven"}
	if err := o.UpdateDB(context.Background()); err == nil || !strings.Contains(err.Error(), "Maven") {
		t.Errorf("an ecosystem left without a database fails the update: %v", err)
	}
	if _, err := o.Tool(context.Background()); err == nil {
		t.Error("doctor reports a missing database")
	}

	o.Ecosystems = []string{"Alpine", "Go"}
	for what, r := range map[string]fakeRun{
		"a logged download error":          {output: probeOutput("Alpine", "Go"), stderr: "could not load db for Debian ecosystem: db host returned 503\n"},
		"vulnerabilities found (status 1)": {output: osvOutput, status: 1},
		"a probe matched with status 0":    {output: osvOutput},
		"a failure":                        {status: 127},
		// A probe osv-scanner did not map was never looked up: its database was not checked.
		"a probe not reported": {output: probeOutput("Alpine")},
	} {
		bin, _, _ := fakeOSV(t, fakeRun{}, r)
		o.Bin = bin
		placeDB(t, cache, "Alpine", old)
		if err := o.UpdateDB(context.Background()); err == nil {
			t.Errorf("%s must fail the update", what)
		}
		if tool, _ := o.Tool(context.Background()); tool.DBBuilt.After(old.Add(time.Minute)) {
			t.Errorf("%s: a failed update marks nothing verified: %v", what, tool.DBBuilt)
		}
	}

	o.DBAutoUpdate = false
	runs()
	if err := o.UpdateDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := runs(); got != nil {
		t.Errorf("databases managed out of band are not updated: %q", got)
	}
}

func TestOSVEcosystemOfPURL(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:apk/alpine/musl@1.2.4-r0?distro=alpine-3.18.0": "Alpine",
		"pkg:apk/wolfi/glibc@2.40":                          "Wolfi",
		"pkg:apk/postmarketos/x@1":                          "",
		"pkg:deb/debian/libc6@2.36?distro=debian-12":        "Debian",
		"pkg:deb/ubuntu/bash@5.1":                           "Ubuntu",
		"pkg:golang/golang.org/x/net@v0.1.0":                "Go",
		"pkg:maven/org.apache/commons@1":                    "Maven",
		"pkg:rpm/redhat/openssl@3":                          "",
		"pkg:bitnami/redis@7":                               "",
		"not a purl":                                        "",
	} {
		if got := osvEcosystem(purl); got != want {
			t.Errorf("%s: %q, want %q", purl, got, want)
		}
	}
	for e, p := range OSVEcosystems {
		if got := osvEcosystem(p); got != e {
			t.Errorf("probe of %s maps to %q", e, got)
		}
	}
}

func TestOSVRejectsUnsafeInputs(t *testing.T) {
	o := &OSV{}
	for _, e := range []string{"../etc", "a/b", "", ".hidden", strings.Repeat("x", 80)} {
		if _, err := o.dbFile("/cache", e); err == nil {
			t.Errorf("ecosystem %q must not become a path", e)
		} else if len(err.Error()) > 120 {
			t.Errorf("error repeats hostile input unbounded: %d bytes", len(err.Error()))
		}
	}
	if _, err := o.dbFile("/cache", "crates.io"); err != nil {
		t.Error(err)
	}
	if _, err := osvProbe([]string{"Alpine", "Bogus"}); err == nil {
		t.Error("unknown ecosystem in the probe")
	}
	if _, err := (&OSV{Bin: Binary{Path: "/bin/true"}}).Match(context.Background(), "/nonexistent"); err == nil {
		t.Error("no cache directory, no offline databases")
	}
}

func TestOSVPluginOptions(t *testing.T) {
	p, _ := Lookup("osv-scanner")
	inst, err := p.New(Spec{})
	if err != nil {
		t.Fatal(err)
	}
	o := inst.(*OSV)
	if !o.DBAutoUpdate || !slices.Equal(o.Ecosystems, DefaultOSVEcosystems()) {
		t.Errorf("defaults: %+v", o)
	}
	inst, err = p.New(Spec{Options: Options{"ecosystems": []any{"npm", "Alpine"}, "db_auto_update": false}})
	if err != nil || !slices.Equal(inst.(*OSV).Ecosystems, []string{"npm", "Alpine"}) || inst.(*OSV).DBAutoUpdate {
		t.Errorf("configured: %+v, %v", inst, err)
	}
	for _, bad := range []any{[]any{}, []any{"npm", "npm"}, []any{"Bogus"}, []any{1}, "npm"} {
		if _, err := p.New(Spec{Options: Options{"ecosystems": bad}}); err == nil {
			t.Errorf("ecosystems %v must be refused", bad)
		}
	}
}

func TestRunnerAcceptsDeclaredExitCodes(t *testing.T) {
	r := Runner{OKExitCodes: []int{1}}
	out, stderr, err := r.RunWithStderr(context.Background(), "/bin/sh", "-c", "printf found; printf warn >&2; exit 1")
	if err != nil || string(out) != "found" || string(stderr) != "warn" {
		t.Errorf("declared status: %q %q, %v", out, stderr, err)
	}
	if _, err := r.Run(context.Background(), "/bin/sh", "-c", "exit 2"); err == nil {
		t.Error("undeclared status must fail")
	}
	if _, err := (Runner{}).Run(context.Background(), "/bin/sh", "-c", "exit 1"); err == nil {
		t.Error("status 1 fails unless declared")
	}
	r.Timeout = 100 * time.Millisecond
	if _, err := r.Run(context.Background(), "/bin/sh", "-c", "sleep 5"); err == nil {
		t.Error("a killed process is not a declared status")
	}
}
