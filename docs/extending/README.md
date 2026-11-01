# Extending ShieldMon

ShieldMon is a small domain core — digest identity, finding lifecycle, evidence, audit,
storage — surrounded by **extension points**. Each extension point is a Go interface with
an in-process registry (like `database/sql` drivers): an adapter registers itself from an
`init` function, configuration selects it by name, and a **conformance kit** decides
whether it is fit to merge. `shieldmon plugins` lists what is registered.

The core never imports an adapter; adapters never touch the lifecycle or storage.

| Extension point | Interface | Registry | Conformance | Built-in | Status |
|---|---|---|---|---|---|
| SBOM generator | `scanner.Generator` | `scanner.Register` | `scannertest.CheckPlugin` | syft, trivy | ✅ |
| Vulnerability matcher | `scanner.Matcher` | `scanner.Register` | `scannertest.CheckPlugin`, `CheckParser`, `CheckMatcher` | grype, trivy | ✅ |
| Report format / exporter | `report.Format` | `report.RegisterFormat` | golden tests | md, json, csv | ✅ |
| Scanner sandbox | `scanner.Sandbox` | `scanner.RegisterSandbox` | `scannertest.CheckSandbox` | none, bwrap, landlock | ✅ M2, [ADR 0011](../adr/0011-scanner-sandbox.md) |
| Registry provider | `oci.Provider` (keychain + listing) | `oci.RegisterProvider` | `ocitest.CheckProvider` | docker, ecr, google, gitlab | ✅ M3, [ADR 0013](../adr/0013-registry-providers.md) |
| Enricher (EPSS, KEV, CVSS) | `enrich.Enricher` | `enrich.Register` | `enrichtest.CheckEnricher` | kev (EPSS from grype's output) | ✅ M4, [ADR 0019](../adr/0019-enrichers.md) |
| Notifier | `notify.Notifier` | `notify.RegisterNotifier` | `notifytest.CheckNotifier` | webhook, smtp, slack, mattermost, matrix, github-issues, gitlab-issues | ✅ M4, [ADR 0015](../adr/0015-notifications.md) |
| Exporter (portfolio tools) | `export.Exporter` | `export.Register` | `exporttest.CheckExporter` | dependency-track, defectdojo | ✅ [ADR 0027](../adr/0027-exporters.md), [exporter.md](exporter.md) |
| Chart source | `charts.Source` | `charts.Register` | `chartstest.CheckPlugin`, `CheckSource` | http, oci, artifacthub | ✅ M7, [ADR 0032](../adr/0032-chart-sources.md) |
| Remediation advisor | `RemediationAdvisor` | planned | planned | fixed-in versions | ⬜ M7 |

Planned interfaces are designed in their epic issue before code (see ROADMAP), following
the same pattern: interface + registry + conformance kit + docs page + one built-in.

## Rules for every adapter

1. **Free software only.** The tool or service must be FOSS-compatible with AGPL-3.0.
2. **Hostile input.** Anything read from images, registries, scanners or remote APIs is
   bounded (size, time) and parsed into typed structs.
3. **Credentials** never leave the provider that owns them; errors pass through
   `internal/redact`.
4. **Processes** run only through `scanner.Runner`; no shell; telemetry and update checks
   off.
5. **Pinned.** External binaries are pinned by checksum (`scripts/install-scanners.sh`).
6. **Proven.** Real-output fixtures, a fuzz target for every parser, the conformance kit,
   and an ADR with parity evidence for scanners.

## Out-of-process plugins (future)

A later phase may load external plugins over an exec protocol (JSON on stdin/stdout, as
Helm and Trivy plugins do). They would run under the same sandbox, be pinned by checksum,
and pass the same conformance kit. Until then, adapters are compiled in — the simplest way
to keep the trust boundary small. See [ADR 0008](../adr/0008-extension-model.md).

## Guides

- [Scanner adapter](scanner-adapter.md)
- [Report format](report-format.md)
- [Registry provider](registry-provider.md)
- [Chart source](chart-source.md)
- [Notifier](notifier.md)
- [Enricher](enricher.md)
- [Conformance kit](conformance.md)
