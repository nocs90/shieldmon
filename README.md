<p align="center"><img src="docs/assets/logo.svg" alt="ShieldMon" width="420"></p>

# ShieldMon

> **ShieldMon** is an open-source Continuous Vulnerability Monitoring (ConMon) and remediation tracking platform for Docker images and container registries.

Designed with a strict **SBOM-first** and **evidence-based resolution** philosophy, ShieldMon helps security and DevOps teams continuously monitor container vulnerabilities, track fixes, generate automated compliance reports, and measurably improve their security posture without re-downloading images or relying on arbitrary manual overrides.

---

### Key Features & Design Principles

- 🔑 **Digest-Based Identity:** Tracks findings strictly by `Image Digest + PURL + Vulnerability ID`, eliminating ambiguity caused by mutable Docker tags.
- 📄 **SBOM-First Continuous Monitoring:** Generates an SBOM once per image digest and re-evaluates it daily against updated vulnerability feeds — saving bandwidth, disk I/O, and compute time.
- 📜 **Open VEX Standards:** Expresses *False Positives* and *Not Applicable* states natively via OpenVEX/CSAF standards instead of proprietary database flags.
- 🔄 **Multi-Scanner Deduplication:** Normalizes and deduplicates results across scanners (Grype, Trivy) by mapping aliases (CVE, GHSA, Distro-specific IDs).
- ✅ **Evidence-Based Finding Resolution:** Findings are closed **only** when subsequent scans confirm the package fix/removal — no manual "click-to-close" shortcuts.
- 🔒 **Zero-Trust Input Threat Model:** Treats image contents as hostile input, processing and parsing layer artifacts in isolated sandboxes.
- 📊 **Automated Reporting:** Generates clear weekly and monthly security posture reports to track mean-time-to-remediate (MTTR) and posture trends over time.

> **Status: M1 (early, pre-1.0).** The core monitoring loop works end to end; VEX
> import/export, native ECR/GitLab providers, Helm, notifications and compliance export
> profiles are on the [roadmap](ROADMAP.md). See [SPEC.md](SPEC.md) for exactly
> what is implemented.

## Quick start

Requirements: Go ≥ 1.27 to build; [syft](https://github.com/anchore/syft),
[grype](https://github.com/anchore/grype) and [trivy](https://github.com/aquasecurity/trivy)
in `PATH` (or `scripts/install-scanners.sh` on linux/amd64 for checksum-pinned versions).
No Docker daemon.

```sh
make build
./bin/shieldmon init                     # config template + database (macOS: --sandbox none)
./bin/shieldmon doctor                   # scanners, hashes for pinning, DB freshness
./bin/shieldmon scan alpine:3.18.0       # resolve → SBOM (once) → match → track
./bin/shieldmon targets add -f images.txt                 # more targets for the next cycle
./bin/shieldmon targets add-repo ghcr.io/org/app --latest 3 --dry-run
./bin/shieldmon findings list --severity high
./bin/shieldmon findings show 42         # details + full audit trail
./bin/shieldmon monitor                  # one ConMon cycle over every target (cron it)
./bin/shieldmon report monthly -o html --out report.html   # opened / fixed / MTTR / burndown / SLA / health
```

To see the full lifecycle (scan → triage → fix proven by evidence → report) on a local
throw-away registry, follow [docs/getting-started.md](docs/getting-started.md).

Public images on any registry work out of the box. Private Amazon ECR and Google
GCR/Artifact Registry use your ambient cloud credentials (IAM role, SSO, ADC); other
registries use `docker login` or credential helpers — see
[docs/processes/registries.md](docs/processes/registries.md). Credentials are used only by
ShieldMon itself; scanners never receive them.

### Daily operation

```sh
# crontab: one cycle per day; a gap > 1.5× the interval opens a health finding
17 3 * * *  shieldmon monitor --log-level info >> /var/log/shieldmon.log 2>&1
```

Each cycle re-resolves every target's tag. Unchanged digest → re-match the stored SBOMs
(no pull). New digest → fetch once, generate SBOMs, match, and close or carry over the
predecessor's findings based on what the new digest actually contains.

### Triage and decisions

```sh
shieldmon findings triage 12 --note "base image bump scheduled"
shieldmon findings remediate 12
shieldmon findings accept-risk 31 --author "jane@corp" --expires 2026-12-31 \
  --justification "not reachable: service has no network listener; RISK-118"
shieldmon findings not-affected 40 --author "jane@corp" \
  --justification "vulnerable_code_not_in_execute_path"
```

There is no command to mark a finding fixed: a later scan has to prove it.

### CI gate

```sh
shieldmon gate --policy ci/gate-policy.yaml -o sarif --out gate.sarif "registry.example.com/app@$DIGEST"
```

Exit status 0 on pass or warn, 2 on fail, 3 when the evidence cannot prove a pass (a matcher
failed, a stale DB), 1 on error. Findings are exempt only by recorded decisions or VEX
statements, never by an ignore list ([docs/processes/ci-gate.md](docs/processes/ci-gate.md)).

### Container image

`make image` builds it; the release pipeline will publish it pinned by digest. It is
distroless and non-root (65532), and writes only under `/data`, so the root filesystem can be
read-only. Scanners run in the `landlock` sandbox, which needs Linux ≥ 5.19 on the host or
node ([ADR 0012](docs/adr/0012-container-image.md)).

```sh
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v shieldmon-data:/data -v "$PWD/config.yaml:/config/shieldmon/config.yaml:ro" \
  shieldmon:dev scan alpine:3.18.0
```

## How it works

```
tag ──resolve──► digest ──(first time only) fetch → syft/trivy SBOMs ──► stored
                    │
                    └──every cycle──► grype + trivy on stored SBOMs ──► normalize/dedupe
                                                                   ──► lifecycle reconcile
                                                                   ──► append-only audit
```

- [ARCHITECTURE.md](ARCHITECTURE.md) — C4 diagrams, pipeline, data model
- [THREAT_MODEL.md](THREAT_MODEL.md) — STRIDE on ShieldMon itself
- [docs/adr/](docs/adr/) — design decisions and their evidence
- [docs/](docs/README.md) — every process: monitoring cycle, triage, reporting, health,
  contribution workflow, quality gates, issue management, releases, security response
- [docs/extending/](docs/extending/README.md) — plugin framework: scanners, report formats,
  and upcoming providers/notifiers/enrichers, with a conformance kit

## Development

```sh
make lint test-unit        # fast checks (golangci-lint included when installed)
make test-race
make cover                 # coverage floor
make fuzz                  # fuzz hostile-input parsers
make test-integration      # real scanners against a pinned digest (network)
make vuln                  # govulncheck on our dependencies
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE).
