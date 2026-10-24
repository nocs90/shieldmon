# Writing a scanner adapter

## 1. Implement the interfaces

```go
// internal/scanner/osv.go
type OSV struct {
	Bin    Binary
	Runner Runner
}

func (o *OSV) Name() string      { return "osv" }
func (o *OSV) Generator() string { return "syft" } // whose SBOM it is validated against

func (o *OSV) Match(ctx context.Context, sbomPath string) (Result, error) {
	bin, err := o.Bin.Resolve() // honours the configured SHA-256 pin
	if err != nil {
		return Result{}, err
	}
	out, err := o.Runner.Run(ctx, bin, "scan", "--format", "json", "--sbom", sbomPath)
	if err != nil {
		return Result{}, fmt.Errorf("osv: %w", err)
	}
	return ParseOSV(out) // pure, fuzzed, fixture-tested
}
```

A generator implements `Generator` (`Name`, `Tool`, `Generate`) and receives a local,
digest-verified OCI layout — never a registry reference or credentials.

`Generate` and `Match` run **without network** and with the DB cache read-only
([ADR 0011](../adr/0011-scanner-sandbox.md)): pass the scanner's flags that stop it from
downloading DBs or calling external APIs while it scans. A matcher with a local DB also
implements `DBUpdater`; `UpdateDB` is the only step that gets network, never receives image
content or SBOMs, and does nothing when an option says the DB is managed out of band:

```go
func (o *OSV) UpdateDB(ctx context.Context) error {
	if o.Offline {
		return nil
	}
	bin, err := o.Bin.Resolve()
	if err != nil {
		return err
	}
	_, err = o.Runner.Run(ctx, bin, "db", "update")
	return err
}
```

`Runner.Confined()` reports whether the process runs in a sandbox, for behaviour that is
only forced there (trivy's `--offline-scan`).

## 2. Register it

```go
func init() {
	Register(Plugin{
		Name:        "osv",
		Description: "OSV-Scanner matcher on syft SBOMs",
		Options:     []string{"offline"},
		New: func(s Spec) (any, error) {
			offline, err := s.Options.Bool("offline", false)
			if err != nil {
				return nil, err
			}
			return &OSV{Bin: s.Bin, Runner: s.Runner, Offline: offline}, nil
		},
	})
}
```

Configuration then selects it:

```yaml
scanners:
  matchers: [grype, trivy, osv]
  tools:
    osv: { sha256: "…", options: { offline: true } }
```

Unknown option keys and wrongly typed values are rejected at startup.

## 3. Prove it

- Trim real output into `internal/scanner/testdata/osv-alpine-3.18.0.json`.
- `scannertest.CheckPlugin(t, "osv")` and
  `scannertest.CheckParser(t, "osv", ParseOSV, "testdata/osv-alpine-3.18.0.json")`.
- `FuzzParseOSV` seeded with the fixture; add it to `FUZZ_TARGETS` in the Makefile.
- Parity numbers (matches on its preferred SBOM vs others) in an ADR — see ADR 0003 for
  why this matters.
- Pin the binary in `scripts/install-scanners.sh` with the official checksum.
