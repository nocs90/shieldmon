package scanner

import (
	"reflect"
	"slices"
	"testing"
)

func TestLauncherArgsRoundTrip(t *testing.T) {
	p := Policy{
		ReadOnly:     []string{"/data/sboms/x.json", "/data/cache"},
		Writable:     []string{"/data/tmp/scan-1/syft"},
		Scratch:      "/data/tmp/proc-1",
		MaxFileBytes: 1 << 30,
	}
	argv, err := landlock{self: "/usr/local/bin/shieldmon"}.Command(p, "/opt/scanners/grype", []string{"sbom:/data/sboms/x.json", "--", "-o"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(argv[:2], []string{"/usr/local/bin/shieldmon", launcherArg}) {
		t.Fatalf("the launcher is ShieldMon itself: %q", argv)
	}
	spec, err := parseLaunch(argv[2:])
	if err != nil {
		t.Fatal(err)
	}
	want := launchSpec{
		ro: p.ReadOnly, rw: p.Writable, scratch: p.Scratch, maxFileBytes: 1 << 30,
		// Arguments after the scanner path are the scanner's, even if they look like ours.
		argv: []string{"/opt/scanners/grype", "sbom:/data/sboms/x.json", "--", "-o"},
	}
	if !reflect.DeepEqual(spec, want) {
		t.Errorf("parsed %+v, want %+v", spec, want)
	}

	argv, err = launcherArgs("/s", Policy{Network: true, Scratch: "/data/tmp/proc-2"},
		launcherFlags{scratchAs: "/tmp", landlockOptional: true, proc: true}, "/usr/bin/grype", []string{"db", "update"})
	if err != nil {
		t.Fatal(err)
	}
	spec, err = parseLaunch(argv[2:])
	want = launchSpec{scratch: "/tmp", net: true, landlockOptional: true, proc: true, argv: []string{"/usr/bin/grype", "db", "update"}}
	if err != nil || !reflect.DeepEqual(spec, want) {
		t.Errorf("backend flags: parsed %+v (%v), want %+v", spec, err, want)
	}
}

func TestLauncherRefusesUnsafePolicy(t *testing.T) {
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
		{"--max-file-bytes=0", "--", "/bin/x"},
		{"--max-file-bytes=1G", "--", "/bin/x"},
		{"--landlock=off", "--", "/bin/x"}, // Landlock can be optional, never off
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
