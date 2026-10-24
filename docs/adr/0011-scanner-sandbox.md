# 0011 — Scanners run in a pluggable sandbox, offline when they touch image content

- Status: accepted
- Date: 2026-10-24

## Context

- Scanners parse hostile layers and run unsandboxed as the invoking user, with that user's
  filesystem and network (THREAT_MODEL.md, residual risks; ADR 0006, consequences). A
  parser bug in syft, grype or trivy is therefore a host compromise, and upstream scanner
  releases have been compromised before (CVE-2026-33634, cited in ADR 0006).
- Uncompressed layer size is bounded only by the scanner and the disk (THREAT_MODEL.md).
- The same process that parses a layer can reach the network today: grype refreshes its DB
  (`GRYPE_DB_AUTO_UPDATE`, default true), trivy downloads its DB unless `skip_db_update`, and
  trivy queries Maven Central unless `offline_scan` (`internal/scanner/grype.go`, `trivy.go`).
  Network reach is what turns a parser compromise into exfiltration of SBOMs and findings.
- ShieldMon runs in two places with different kernel facilities:
  - Linux hosts (systemd timer). User namespaces are available, so bubblewrap can build
    a full mount/PID/network sandbox without root. Ubuntu ≥ 23.10, including the
    `ubuntu-24.04` runners used by CI, restricts unprivileged user namespaces through
    AppArmor, and the distro `bwrap` package ships the profile that allows it.
  - Containers (Kubernetes CronJob, #7). The runtime's default seccomp profile refuses
    `unshare(CLONE_NEWUSER)` without `CAP_SYS_ADMIN`, so neither bubblewrap nor a nested
    rootless OCI runtime starts without weakening the pod. Landlock (Linux ≥ 5.13 for
    filesystem rules, ≥ 6.7 / ABI 4 for TCP connect/bind rules) is unprivileged, needs no
    namespace, and is inherited across `execve`.
- macOS and other non-Linux development hosts have neither.

## Decision

1. **Extension point.** `scanner.Sandbox` (interface + `scanner.RegisterSandbox` registry +
   `scannertest.CheckSandbox` conformance kit), selected by `scanners.sandbox.backend` in
   config. `scanner.Runner` is the only caller; adapters do not change. No `switch` on
   backend names in core code.
2. **Every scanner process gets a policy, not a backend-specific command:** read-only
   inputs (OCI layout or SBOM, scanner binary, DB cache), one writable output directory,
   a writable scratch directory, network on/off, and limits. Backends translate the policy.
3. **Hostile content is processed offline.** SBOM generation and matching always run
   with network off. Vulnerability DBs are refreshed by a separate `db update` step that
   runs with network on but never receives image content or SBOMs. When a sandbox is
   active, ShieldMon forces `GRYPE_DB_AUTO_UPDATE=false`, trivy `--skip-db-update` and
   `--offline-scan`. This is stricter than "network only to DB mirrors" and needs no
   egress proxy.
4. **Backends.**
   - `bwrap` (Linux hosts): new user, mount, PID, IPC, UTS and (when offline) network
     namespaces; system directories bound read-only, policy paths bound as declared;
     `/tmp` is a tmpfs with a size quota; `--die-with-parent`, `--new-session`,
     `--cap-drop ALL`; seccomp filter passed with `--seccomp`.
   - `landlock` (containers, and Linux hosts without user namespaces): ShieldMon re-executes
     itself as a launcher (`shieldmon sandbox-exec`, hidden) that applies Landlock filesystem
     rules from the policy, Landlock network rules (deny all TCP when offline; requires
     ABI ≥ 4 or the launcher refuses), `RLIMIT_FSIZE`/`RLIMIT_NOFILE`, `no_new_privs` and the
     seccomp filter, then `execve`s the scanner. The disk quota is the container's
     ephemeral-storage limit (documented in the deployment examples, #11).
   - `none`: today's behaviour, chosen explicitly. While it is active, every cycle keeps a
     `scanner_unsandboxed` health finding open (severity high) so that reports show it,
     and `doctor` fails.
   - Default `auto`: `bwrap` if it starts, else `landlock` if supported, else refuse to
     scan with an error naming `backend: none` as the opt-out. Nothing falls back to
     unsandboxed silently.
5. **Seccomp.** One deny-list profile shared by both backends, modelled on the container
   runtimes' default profile: no `ptrace`, `mount`/`umount2`, `unshare`/`setns`,
   `keyctl`/`add_key`, `bpf`, `perf_event_open`, kernel module or `kexec` calls,
   `userfaultfd`, `personality` changes. Generated in pure Go (the binary is built with
   `CGO_ENABLED=0`).
6. **Proof.** `CheckSandbox` probes each backend from inside the sandbox: it cannot read a
   file outside the policy, cannot write outside the output and scratch directories,
   cannot open a TCP connection when offline, is stopped at the scratch quota, and is
   killed with the process group on timeout. The hostile fixture suite (#10) runs every
   case under the default backend in CI.

## Consequences

- A parser compromise is contained to the scratch directory and the declared inputs, with
  no network: the residual risks in THREAT_MODEL.md move from "unsandboxed" to the
  kernel attack surface left by the seccomp profile.
- New dependencies for pure-Go Landlock and seccomp BPF generation (candidates:
  `github.com/landlock-lsm/go-landlock`, MIT; `github.com/elastic/go-seccomp-bpf`,
  Apache-2.0; both AGPL-3.0-compatible). `go.mod` changes need review.
- Offline matching costs trivy's Maven Central lookups for Java artifacts without
  embedded metadata; this was already the `offline_scan` trade-off, and it becomes the
  default when sandboxed.
- DB freshness now depends on the `db update` step running before each cycle; `monitor`
  runs it first, and `db_stale` health findings already cover a failed update.
- macOS development hosts need `backend: none` and see the open health finding; sandbox
  tests are Linux-only and run in CI.
- To verify while implementing: whether the `bwrap` shipped
  with Ubuntu 24.04 supports `--size` for tmpfs quotas (older releases do not; fallback:
  scratch on a `landlock`-style `RLIMIT_FSIZE`), and whether the CI runner's AppArmor
  profile allows `bwrap` without changing sysctls.
- This replaces the "rootless OCI runtime in containers" backend named in epic #1: it
  needs the same user namespaces that container runtimes deny by default.

## Implementation notes

- 2026-10-24, `bwrap` backend:
  - `--size` exists since bubblewrap 0.7 and Ubuntu 24.04 ships 0.9, so the tmpfs quota is
    available. Whether the `ubuntu-24.04` runner's AppArmor policy lets `bwrap` start is
    checked by ci/test (`SHIELDMON_TEST_SANDBOX=bwrap`).
  - Scratch space is a per-process directory under `<data_dir>/tmp`, mounted at `/tmp`
    and removed when the process exits, not a tmpfs. SBOM generators can unpack layers
    into `TMPDIR`, so a RAM-backed `/tmp` big enough for real images would let a
    decompression bomb exhaust host memory. The tmpfs with `--size` is used only for
    processes without scratch space. A disk quota for scratch space is still open.
    `RLIMIT_FSIZE` from the `landlock` launcher will bound single files.
  - Scanner DBs and caches move from the user's cache directory to `<data_dir>/cache`
    (`XDG_CACHE_HOME`, `GRYPE_DB_CACHE_DIR`, `TRIVY_CACHE_DIR`). The cache is read-only
    to every process without network. trivy keeps its scan cache in memory
    (`--cache-backend memory`), so results derived from hostile layers are never reused.
    Existing DBs under `~/.cache` are not migrated: the first run downloads them again.
  - Until the `db update` step lands, the confined matchers cannot refresh their DBs.
    `bwrap` needs `db_auto_update: false` and `skip_db_update: true`, with DBs refreshed
    by a run under `backend: none`.
