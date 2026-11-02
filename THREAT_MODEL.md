# Threat model (STRIDE) — ShieldMon itself

ShieldMon processes attacker-influenced content (any image a registry serves) with
access to registry credentials and produces compliance evidence. It is therefore both a
**target** (credentials, a privileged vantage point) and a **source of truth** that must
not be falsifiable.

## Assets

| Asset | Why it matters |
|---|---|
| Registry credentials (ECR roles, GitLab tokens, docker config) | Read access to private images; often over-scoped. |
| Findings DB and audit trail | Compliance evidence (remediation plans, audit reports). Tampering hides risk. |
| SBOM store | Inventory of what runs in production. |
| Scanner binaries and their DBs | Code execution with access to everything above. |
| Host running ShieldMon | Runs scanners against hostile input. |

## Trust boundaries

1. Registry ↔ ShieldMon (network; registry responses are untrusted).
2. ShieldMon ↔ scanner processes (scanners parse hostile layers; their output is untrusted).
3. Scanner ↔ vulnerability DB mirrors (network; DB integrity is the scanner's job, freshness is ours).
4. Operator ↔ CLI (humans may make decisions, not closures).
5. Reports ↔ consumers (spreadsheets, Markdown renderers).

## STRIDE

| Threat | Scenario | Mitigation (status) |
|---|---|---|
| **S**poofing | Tag swapped to a different image between scans. | Identity is the digest; tags resolved every cycle, every change appended to `target_digests` ✅ |
| S | Registry serves different bytes than the requested digest. | Fetch by digest only; ggcr verifies manifest and blob digests; explicit digest re-check ✅ |
| S | A spoofed or truncated KEV feed (mirror, proxy) hides exploited vulnerabilities or floods findings. | HTTPS only (redirects to https, at most 3); size, entry and field validation; a catalog much smaller than the known one, inconsistent with its `count`, or largely malformed is refused and the previous data kept; enrichers only add facts; staleness and failures are health findings; cache outside the scanners' writable paths (ADR 0019) ✅ |
| S | Malicious scanner release (cf. trivy v0.69.4, CVE-2026-33634). | Optional SHA-256 pin per binary, mismatch aborts + health finding ✅; checksum-verified installer ✅; CI actions pinned by SHA ✅; release signatures verified with a pinned cosign against the exact release-workflow identities, the pinned SHA-256 required in the signed checksums, all-or-nothing installation (ADR 0006) ✅ |
| **T**ampering | Someone edits history to hide a finding or backdate a fix. | Append-only triggers on events/observations/decisions ✅; DB file 0600 ✅; hash-chained audit trail sealed in every write transaction, verified by monitor, anchored by exported digests and by every report (ADR 0018) ✅; reports and digests signed with minisign or cosign (documented, docs/processes/audit.md) ✅ |
| S/I | A hostile chart index or Artifact Hub entry sends ShieldMon to internal addresses (SSRF: cloud metadata, admin ports, cluster services). | URLs from remote content: HTTPS only, fetched by a client that dials public addresses only (checked on the dialled address), registry references to internal literals refused; configured URLs only follow at most 5 HTTPS redirects (ADR 0032) ✅; a public name resolving to an internal registry is a residual risk |
| T/D | A hostile chart archive (links, escaping paths, appended or nested archives, zip bombs, Chart.yaml readers disagree) misleads or exhausts what renders it. | `CheckArchive` before any rendering, subcharts included, on one budget: regular files only, no escape, no duplicates, 10,000 entries, 64 MiB unpacked (headers counted), depth 3, no trailing data, case-folded Chart.yaml keys refused; index and archive sizes bounded; digests verified (ADR 0032) ✅ |
| E/I | A hostile chart (templates run by helm, a crafted archive aimed at a helm bug) reaches the network (remote schemas, DNS), reads the host's files or kubeconfig, or exhausts it. | Only `helm template`, through `scanner.Runner` in the scanners' sandbox: no network, read access to the checked archive and the profile's values only, the DB cache hidden, scratch home under every backend, no `HELM_*`/`KUBECONFIG`/credentials, `--namespace` always given, no `--validate`/`--dependency-update`/`--enable-dns`/post-renderer, arguments as `--flag=value`; timeout, output bound, scratch quota; output through the manifest parser; run in CI with the real helm (ADR 0033) ✅; memory not bounded by the sandbox, unconfined under `backend: none` (warned) |
| T/R | Chart tracking is used to make findings disappear (a release that drops an image, a forged render) or to post hostile text upstream in ShieldMon's name. | Charts never change findings: dropped images stay targets until retired with a record; renders are append-only and sealed in the audit chain; neglect is a verdict from scan evidence only; upstream drafts are printed, never submitted, with every scanner or source value in a code span (no markup, links or mentions) (ADR 0034) ✅ |
| S/I/D | A chart's publisher uses `add_targets` to make ShieldMon contact internal registries with the operator's credentials (SSRF, confused deputy), flood the targets, or hold or bloat the monitor cycle (a hanging source, an index that changes digests every read). | Images become targets only on registries that look public or that the operator configured; at most 50 new targets per release unattended, more left to a person; a time budget per chart per cycle; at most 3 renders per profile a day; a version listed twice keeps its first entry; registry names judged without a trailing dot, no numeric shorthands; renders bounded (10,000 images, 512-byte references); refusals named in `chart_failed` (ADR 0034) ✅; a public name resolving to an internal registry is a residual risk, as for chart sources |
| S | Malicious helm release. | SHA-256 pinned in the installer and a good OpenPGP signature (no bad, expired or revoked one) by the pinned maintainer key, from `KEYS` at a pinned commit (ADR 0033) ✅ |
| T | A cluster tenant, or anyone who can write the delivery path of a cluster export, inflates or hides runtime context (fake exposure, huge objects, names with control characters, a future timestamp, a FIFO). | Runtime context only orders findings, never changes state, gate or exports; exports are regular files only, at most 256 MiB and 500,000 objects (counted while streaming), names truncated and escaped in every output; routes count only within their namespace; stale, future-dated or malformed exports are left out and listed in reports with the reason (ADR 0029) ✅ |
| T | A forged or careless VEX document suppresses real findings. | VEX is imported only by an explicit operator step, with `--dry-run`; every statement needs an author and a justification, records who imported it, is append-only and scoped; expired statements are refused; parsers bounded and fuzzed ✅; signed VEX verification ⬜ |
| T | Hostile image makes a scanner emit forged/huge output. | Output byte limit with process-tree kill ✅; SBOM size + shape validation ✅; JSON decoding into typed structs ✅ |
| T | Partial scan (one scanner down) closes findings by absence. | Absence counts only from *complete* scans ✅ |
| S | An image claims a fresh or trusted base (`org.opencontainers.image.base.*` annotations) it is not built on, to look "current". | Annotations bounded (512 bytes), validated as reference and sha256 digest, and only a claim: a base digest counts only when its config `diff_ids` are a prefix of the image's; configured bases win over annotations; labels never used; base age never taken from an implausible `created` time (ADR 0022) ✅ |
| T | Retiring a target to make its open findings disappear from reports. | Retirement never closes findings or counts as a fix; reports show "retired with the image" apart; append-only record with actor and reason; a digest still used by a monitored target stays in scope; restoring brings the findings back unchanged (ADR 0017) ✅ |
| **R**epudiation | "I didn't accept that risk." | Decisions require author + justification, stored append-only with timestamps ✅; authenticated identities (OIDC) in server mode ⬜ |
| **I**nformation disclosure | Credentials leak into logs, errors, health findings, reports. | Central redaction (headers, URL userinfo, AWS/GitLab/GitHub tokens, JWTs, signed URLs) ✅; scanners get an env allowlist without registry/cloud credentials ✅ |
| I | Scanner telemetry/update checks leak inventory. | `--disable-telemetry`, `--skip-version-check`, `*_CHECK_FOR_APP_UPDATE=false` ✅; `trivy.offline_scan` option ✅; DBs refreshed by a separate step that never sees image content, so scanning needs no network ✅; no network at all while scanning under a sandbox ✅ (`bwrap`) |
| I | Exports carry an API key (Dependency-Track, DefectDojo) to the wrong place, or SBOMs and findings to an endpoint the operator did not mean. | Same discipline as notifications: keys only from `*_env` variables, credential-shaped options refused, HTTPS only (HTTP to localhost), no redirect followed, errors name host and status only; endpoints only from the configuration; conformance kit checks a hostile batch and an echoing endpoint (ADR 0027) ✅ |
| I | Notifications carry a channel credential (webhook secret, token, signed URL) to the wrong place, or into logs. | Credentials only from environment variables named by `*_env` options, inline credential-shaped values refused; HTTPS only (http to localhost), redirects never followed; errors name host and status only, never URL or answer; redacted before health findings ✅ |
| T | Someone makes an issue look managed by ShieldMon (marker, label) to have it commented or closed. | Only issues labelled `shieldmon` whose description *starts* with the group marker are read (markers in hostile text sit inside code blocks); pull requests ignored; issue state never flows back into findings; labelling left to maintainers (docs) ✅ |
| T | Hostile package names or titles inject headers, markup or mentions into notifications. | Notifiers escape for their medium (JSON, `notify.Clean` for headers and plain text, Markdown/HTML escaping); conformance kit sends hostile events ✅ |
| I | SBOMs (full inventory) readable by other users. | data dir 0700, files 0600 ✅ |
| **D**enial of service | Decompression bomb / giant layers / thousands of layers. | Manifest-declared layer count/size/total limits before download ✅; scanner timeouts ✅; per-process scratch quota (bytes and entries) and free-disk floor, enforced by killing the scanner ✅; per-file size limit (`RLIMIT_FSIZE`) under both backends ✅; proven by the hostile fixture suite with real scanners ✅ |
| D | Scanner hangs or forks helpers. | Own process group, SIGKILL on timeout/overflow, `WaitDelay` ✅ |
| D | Two cycles race and corrupt state. | Exclusive data-dir lock ✅; immediate transactions ✅ |
| D | Silent stop: cron broken, DB stale, auth expired. | Self-health findings: `monitor_missed`, `db_stale`, `registry_auth`, `*_failed` ✅ (alerting ⬜ M4) |
| **E**levation of privilege | Image content executed. | Never run images; no Docker daemon; scanners only parse files ✅ |
| E | Argument/flag injection through image refs. | Strict reference parsing (rejects leading `-`, whitespace); no shell; digest refs passed to scanners as local paths ✅ |
| E | Scanner exploited by a crafted layer → host compromise. | Sandbox (ADR 0011): one launcher for both backends, W^X on everything a scanner can write (Landlock), `bwrap` on Linux hosts with seccomp deny-list (no new namespaces, ptrace, mounts, bpf, io_uring, keyrings, userfaultfd, modules) and no sockets while handling image content ✅; `landlock` backend for containers ✅; sandbox by default (`auto`, refuses to scan without a backend) ✅ |
| E | Over-scoped registry credentials. | `deploy/iam/shieldmon-readonly.json` grants exactly the ECR calls ShieldMon makes, enforced by a test ✅; trust policies pinned by `aud`/`sub`, source account or external ID ✅; short-lived credentials only, from the environment ✅ |
| Report injection | Package names like `=HYPERLINK(...)` or Markdown/HTML in titles. | CSV formula neutralization, Markdown/HTML escaping ✅ |

## Residual risks (accepted for M1, tracked in ROADMAP)

- Scanners are sandboxed by default (`auto`: `bwrap` on Linux hosts, `landlock` in
  containers; ADR 0011). `backend: none` runs them as the invoking user, with its files
  and network; while it is set, a `scanner_unsandboxed` health finding stays open.
  Mitigation for hosts without a backend: run ShieldMon in a dedicated, unprivileged
  container with no other secrets.
- Under `landlock` on kernels before Landlock ABI 6, a scanner can still signal the
  user's other processes.
- On Ubuntu ≥ 23.10 the `bwrap` backend needs an AppArmor profile for bwrap. AppArmor's
  `bwrap-userns-restrict`, recommended for shared hosts, keeps what bwrap starts without
  capabilities; `deploy/apparmor/shieldmon-bwrap`, for dedicated hosts and CI, lets every
  local user who can run bwrap create user namespaces with them (ADR 0011).
- A scanner can overshoot its scratch quota by what it writes in 100 ms; the free-disk
  floor absorbs it. A kernel-enforced total needs a size-limited filesystem for the
  scratch space, which the deployment provides (`deploy/scratch`, reported by `doctor`).
- `bwrap` on a kernel without Landlock cannot stop a scanner from executing files it
  writes; a `scanner_sandbox_degraded` health finding stays open while it runs so.
- Vulnerability DB integrity relies on the scanners' own verification.
- Integrity of `install-scanners.sh` pins relies on the release's checksum file
  (same trust domain as the artifact); cosign/sigstore verification is planned.
