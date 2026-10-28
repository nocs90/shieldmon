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
| S | Malicious scanner release (cf. trivy v0.69.4, CVE-2026-33634). | Optional SHA-256 pin per binary, mismatch aborts + health finding ✅; checksum-verified installer ✅; CI actions pinned by SHA ✅; signature verification ⬜ |
| **T**ampering | Someone edits history to hide a finding or backdate a fix. | Append-only triggers on events/observations/decisions ✅; DB file 0600 ✅; hash-chained audit log + signed report exports ⬜ |
| T | Hostile image makes a scanner emit forged/huge output. | Output byte limit with process-tree kill ✅; SBOM size + shape validation ✅; JSON decoding into typed structs ✅ |
| T | Partial scan (one scanner down) closes findings by absence. | Absence counts only from *complete* scans ✅ |
| **R**epudiation | "I didn't accept that risk." | Decisions require author + justification, stored append-only with timestamps ✅; authenticated identities (OIDC) in server mode ⬜ |
| **I**nformation disclosure | Credentials leak into logs, errors, health findings, reports. | Central redaction (headers, URL userinfo, AWS/GitLab/GitHub tokens, JWTs, signed URLs) ✅; scanners get an env allowlist without registry/cloud credentials ✅ |
| I | Scanner telemetry/update checks leak inventory. | `--disable-telemetry`, `--skip-version-check`, `*_CHECK_FOR_APP_UPDATE=false` ✅; `trivy.offline_scan` option ✅; DBs refreshed by a separate step that never sees image content, so scanning needs no network ✅; no network at all while scanning under a sandbox ✅ (`bwrap`) |
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
