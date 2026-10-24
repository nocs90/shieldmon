package scanner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSelectSandboxByName(t *testing.T) {
	name, sb, err := SelectSandbox("none")
	if err != nil || name != "none" {
		t.Fatalf("none: %q %v", name, err)
	}
	l, err := sb.Command(Policy{}, "/usr/bin/grype", []string{"version"})
	if err != nil || !reflect.DeepEqual(l, Launch{Argv: []string{"/usr/bin/grype", "version"}}) {
		t.Fatalf("none must run the scanner as is: %+v %v", l, err)
	}
	if _, _, err := SelectSandbox("chroot"); err == nil || !strings.Contains(err.Error(), "unknown backend") {
		t.Fatalf("unknown backend must be a configuration error: %v", err)
	}
}

func TestSelectAutoPrefersFirstAvailable(t *testing.T) {
	ok := func() error { return nil }
	noUserns := func() error { return errors.New("user namespaces disabled") }
	all := []SandboxBackend{
		{Name: "landlock", Auto: 2, Available: ok},
		{Name: "bwrap", Auto: 1, Available: noUserns},
		{Name: "none", Available: ok},
	}
	b, err := selectAuto(all)
	if err != nil || b.Name != "landlock" {
		t.Fatalf("auto picked %q, %v; want landlock", b.Name, err)
	}

	all[0].Available = noUserns
	_, err = selectAuto(all)
	if !errors.Is(err, ErrNoSandbox) {
		t.Fatalf("auto must refuse when no backend is available, got %v", err)
	}
	for _, want := range []string{"bwrap: user namespaces disabled", "backend: none"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q lacks %q", err, want)
		}
	}
}

type recordingSandbox struct{ got Policy }

func (s *recordingSandbox) Command(p Policy, bin string, args []string) (Launch, error) {
	s.got = p
	// The script also reads fd 3, which the Runner must pass from Launch.Files.
	argv := append([]string{"/bin/sh", "-c", `printf 'confined:%s ' "$@"; cat <&3`, "sh", bin}, args...)
	return Launch{Argv: argv, Files: [][]byte{[]byte("fd3")}}, nil
}

func TestRunnerRunsThroughSandbox(t *testing.T) {
	sb := &recordingSandbox{}
	want := Policy{ReadOnly: []string{"/data/sboms/x.json"}}
	ctx := WithPolicy(context.Background(), want)
	out, err := Runner{Sandbox: sb}.Run(ctx, "/usr/bin/grype", "sbom:/data/sboms/x.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != "confined:/usr/bin/grype confined:sbom:/data/sboms/x.json fd3" {
		t.Errorf("scanner did not run through the sandbox: %q", got)
	}
	if !reflect.DeepEqual(sb.got, want) {
		t.Errorf("sandbox got policy %+v, want %+v", sb.got, want)
	}
}

func TestRunnerRefusesWithoutSandbox(t *testing.T) {
	refuse := refusing{err: ErrNoSandbox}
	_, err := Runner{Sandbox: refuse}.Run(context.Background(), "/bin/sh", "-c", "echo ran")
	if !errors.Is(err, ErrNoSandbox) {
		t.Fatalf("an unavailable sandbox must stop the scanner from starting, got %v", err)
	}
}
