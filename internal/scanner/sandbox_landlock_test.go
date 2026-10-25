package scanner

import (
	"reflect"
	"slices"
	"testing"
)

func TestLandlockCommandRoundTrip(t *testing.T) {
	l := landlock{self: "/usr/local/bin/shieldmon"}
	p := Policy{
		ReadOnly: []string{"/data/sboms/x.json", "/data/cache"},
		Writable: []string{"/data/tmp/scan-1/syft"},
		Scratch:  "/data/tmp/proc-1",
	}
	launch, err := l.Command(p, "/opt/scanners/grype", []string{"sbom:/data/sboms/x.json", "--", "-o"})
	if err != nil {
		t.Fatal(err)
	}
	if len(launch.Files) != 0 {
		t.Error("the launcher builds its own seccomp filter and needs no file descriptors")
	}
	argv := launch.Argv
	if !slices.Equal(argv[:2], []string{"/usr/local/bin/shieldmon", landlockExecArg}) {
		t.Fatalf("the launcher is ShieldMon itself: %q", argv)
	}
	spec, err := parseLaunch(argv[2:])
	if err != nil {
		t.Fatal(err)
	}
	want := launchSpec{
		ro: p.ReadOnly, rw: p.Writable, scratch: p.Scratch,
		// Arguments after the scanner path are the scanner's, even if they look like ours.
		argv: []string{"/opt/scanners/grype", "sbom:/data/sboms/x.json", "--", "-o"},
	}
	if !reflect.DeepEqual(spec, want) {
		t.Errorf("parsed %+v, want %+v", spec, want)
	}

	launch, err = l.Command(Policy{Network: true}, "/usr/bin/grype", []string{"db", "update"})
	if err != nil {
		t.Fatal(err)
	}
	if spec, err := parseLaunch(launch.Argv[2:]); err != nil || !spec.net || spec.ro != nil {
		t.Errorf("a network policy must reach the launcher: %+v %v", spec, err)
	}
}

func TestLandlockRefusesUnsafePolicy(t *testing.T) {
	l := landlock{self: "/usr/local/bin/shieldmon"}
	for _, p := range []Policy{{Writable: []string{"/"}}, {ReadOnly: []string{""}}, {Scratch: "/"}} {
		if _, err := l.Command(p, "/usr/bin/grype", nil); err == nil {
			t.Errorf("policy %+v must be refused", p)
		}
	}
	if _, err := (landlock{}).Command(Policy{}, "/usr/bin/grype", nil); err == nil {
		t.Error("a launcher without its executable must refuse")
	}
}

func TestParseLaunchRejects(t *testing.T) {
	for _, args := range [][]string{
		{},                            // neither -- nor --check
		{"--ro=/in"},                  // no scanner
		{"--", "grype"},               // relative scanner path
		{"--"},                        // nothing after --
		{"--rw", "/out", "--", "/x"},  // flag without =
		{"--seccomp=0", "--", "/bin"}, // unknown flag
	} {
		if _, err := parseLaunch(args); err == nil {
			t.Errorf("parseLaunch(%q) must fail", args)
		}
	}
	if s, err := parseLaunch([]string{"--check"}); err != nil || !s.check {
		t.Errorf("--check alone is the availability probe: %+v %v", s, err)
	}
}

func TestAutoTriesLandlockAfterBwrap(t *testing.T) {
	order := map[string]int{}
	for _, b := range SandboxBackends() {
		order[b.Name] = b.Auto
	}
	if order["bwrap"] <= 0 || order["landlock"] <= order["bwrap"] {
		t.Errorf("auto order = %v: bwrap first, then landlock", order)
	}
}
