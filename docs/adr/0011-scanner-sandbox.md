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
    AppArmor. (The distro `bwrap` package does not ship a profile that allows it; see the
    implementation notes.)
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
     ABI ≥ 4 or the launcher refuses — changed to ABI ≥ 2 with sockets denied by seccomp,
     see the implementation notes of 2026-10-25), `RLIMIT_FSIZE`/`RLIMIT_NOFILE`, `no_new_privs` and the
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
- 2026-10-24, `db update` step, `none` posture, conformance kit:
  - Matchers implement the optional `scanner.DBUpdater`. `Engine.Preflight` runs it before
    matching with `Policy{Network: true}` (`monitor` when it has targets, `scan`,
    `rematch`, and `shieldmon db update` on its own). Scanning never updates a DB, under
    every backend including `none`: grype always gets `GRYPE_DB_AUTO_UPDATE=false`, trivy
    always gets `--skip-db-update --skip-java-db-update`. `db_auto_update: false` and
    `skip_db_update: true` now mean "the DB is managed out of band": the update step does
    nothing. `--offline-scan` is forced only when confined, so unconfined Java coverage
    is unchanged.
  - trivy's Java index DB, which it used to fetch lazily while cataloging JARs, is now
    downloaded by the update step for every setup (trivy fetches it only when its copy is
    due). Cataloging cannot fetch it from inside a sandbox.
  - A failed update opens `db_update_failed` (medium) instead of relying on `db_stale`
    alone: it is a failure of the monitoring process (I6), visible before the DB ages out.
  - While `none` is selected, every preflight keeps `scanner_unsandboxed` (high) open and
    `doctor` fails. A backend that cannot run here is not `none`: it refuses to start
    scanners, which fails the scan instead.
  - `scannertest.CheckSandbox` is the kit for backends. Its probe is the test binary
    re-executing itself inside the sandbox, so it needs no shell or `nc` there and works
    the same for `landlock`. The scratch quota is not probed yet: no backend enforces one.
- 2026-10-24, AppArmor on Ubuntu hosts and CI:
  - The `bubblewrap` package of Ubuntu 24.04 ships no AppArmor profile, and
    `kernel.apparmor_restrict_unprivileged_userns=1` gives the user namespace of an
    unprofiled program no capabilities: bwrap fails with `loopback: Failed RTM_NEWADDR:
    Operation not permitted` (it broke ci/test from the first `bwrap` commit). The context
    above assumed the opposite.
  - `deploy/apparmor/shieldmon-bwrap` grants `userns` to `/usr/bin/bwrap` and nothing else
    (`flags=(unconfined)`, the pattern Ubuntu documents). ci/test loads it before the tests;
    hosts install it once. The `bwrap` availability error names it when the sysctl is set.
  - Rejected: `sysctl kernel.apparmor_restrict_unprivileged_userns=0`, which lifts the
    restriction for every program on the host instead of one.
  - Residual risk: every local user who can run bwrap may create user namespaces. Scanners
    inside get no capabilities (`--cap-drop ALL`), and the seccomp filter (decision 5)
    will also deny them `unshare`/`setns`.
- 2026-10-25, seccomp filter (#45):
  - No new module: `internal/scanner/seccomp.go` emits the classic BPF program itself (four
    instruction kinds) from a syscall table per architecture (amd64, arm64; any other
    architecture has no filter, so no backend runs there). The table is checked against
    `golang.org/x/sys/unix` on Linux, which therefore became a direct requirement (it was
    already in the module graph). The candidate libraries named under Consequences are not
    needed; Landlock (#46) uses `x/sys/unix` too.
  - Denied syscalls return `EPERM`, so a scanner reports an error instead of dying.
    `clone` is allowed without `CLONE_NEW*` flags (threads and processes);
    `clone3` returns `ENOSYS`, because its flags are in memory the filter cannot read
    and glibc then falls back to `clone`. `personality` accepts only the values the
    container runtimes allow. Another ABI (i386 on amd64) or the x32 ABI kills the process.
  - `Sandbox.Command` returns a `Launch`: argv plus data the Runner passes as fds 3, 4, ...
    (unlinked temporary files). bwrap gets the filter with `--seccomp 3` and applies it
    right before exec'ing the scanner. The availability probe runs with the filter, so
    the kernel validates the program before a scan does.
  - `scannertest.CheckSandbox` proves the filter is in place: a probe can neither start a
    child in a new user namespace (`clone`; `unshare(CLONE_NEWUSER)` fails with EINVAL in
    any multithreaded process, so it proves nothing) nor turn off ASLR with `personality`.
- 2026-10-25, `landlock` backend (#46):
  - The launcher is ShieldMon re-executing itself (`shieldmon sandbox-exec`), caught in
    `init` before `main`, so it works in any binary that links `internal/scanner`, test
    binaries included. On one locked thread it sets `no_new_privs` (which an unprivileged
    `landlock_restrict_self` and seccomp filter both require), applies the Landlock
    ruleset, `RLIMIT_NOFILE` (hard limit 65536: Go programs raise the soft limit to it)
    and the seccomp filter, then execs the scanner in place, which keeps
    the Runner's process group and timeout kill.
  - The Landlock rules mirror the `bwrap` view: system directories read and execute; the
    same `/etc` files (resolver files only with network); `/dev/null`, `/dev/zero`,
    `/dev/urandom`, `/dev/random`; the scanner binary read and execute; the policy's
    read-only paths read; writable paths and scratch space everything. No `/proc` or
    `/sys`: `/proc/<pid>/cmdline` of other processes would be readable. `HOME` points at
    the scratch directory.
  - **Changed from decision 4:** the minimum is Landlock ABI 2 (Linux 5.19), not 4. ABI 4
    (Linux 6.7) would exclude most Kubernetes nodes in use (6.1 kernels), and Landlock's
    network rules cover TCP only, not UDP or Unix sockets (a host's Docker socket, for
    example). Instead the seccomp filter denies `socket(2)` to every offline process,
    under both backends: no network of any kind on any kernel. Where ABI ≥ 4, Landlock's
    TCP rules are added as a second wall. ABI 1 is refused because it denies every rename
    across directories, which DB updates need.
  - Below ABI 3 Landlock cannot restrict `truncate(2)` by path, so the seccomp filter
    denies it there (`ftruncate` needs a file already opened for writing).
  - Below ABI 6 a confined scanner can still signal processes of the same user outside
    its domain (bwrap prevents it with a PID namespace); ABI 6 scopes signals and
    abstract Unix sockets. Accepted residual risk for older kernels.
  - `RLIMIT_FSIZE` moves to the scratch quota (#47), which needs the same limit.
  - `SHIELDMON_TEST_SANDBOX` is now a comma-separated list; ci/test requires
    `bwrap,landlock`.
- 2026-10-25, scratch quota and free-disk floor (#47):
  - The `Runner` watches every process it starts, whatever the backend (`none` included):
    every 100 ms it measures the scratch directory (allocated blocks, so sparse files are
    not overcounted; at most 2^20 entries, which also bounds inode use and the walk) and
    the free space under the data dir's `tmp`. Over `limits.max_scratch_bytes` (default
    32 GiB) or under `limits.min_free_disk_bytes` (default 2 GiB) it kills the process
    group: `ErrScratchQuota` / `ErrDiskSpace`, so the scan fails with the generator's or
    matcher's health finding. The floor is what keeps the disk from filling even when a
    process writes outside its scratch space (`none`, or its output directory).
  - Overshoot between two checks is bounded by 100 ms of writing; the floor absorbs it.
    No quota filesystem: a size-limited mount needs privileges neither backend has, and a
    tmpfs would put the bytes in memory.
  - `landlock` also sets `RLIMIT_FSIZE` to the quota for offline processes, so no single
    file can outgrow it, even outside the scratch directory. bwrap cannot set rlimits on
    the process it starts, so it relies on the watch. DB updates are not limited: DBs can
    be larger than a small quota, and the update never reads image content.
  - The quota is a property of the Runner, not of a backend, so it is tested in the
    scanner package (portable) rather than in `scannertest.CheckSandbox`; the landlock
    file size limit has a Linux test.
- 2026-10-25, one confinement path, W^X, degraded bwrap (#53). Supersedes, from the notes
  above, bwrap's `--seccomp 3` and `Launch` (seccomp filter note), "bwrap cannot set
  rlimits" and "the quota is tested in the scanner package rather than in the kit"
  (quota note):
  - `bwrap` runs the scanner through the launcher inside its namespaces:
    `bwrap … -- shieldmon sandbox-exec --scratch=/tmp --proc --landlock=optional … -- scanner`.
    `no_new_privs`, rlimits (`RLIMIT_FSIZE` included), Landlock and seccomp now come from
    one place for both backends; `Sandbox.Command` returns argv only again. `--proc`
    grants read access to bwrap's private `/proc`, which holds only the sandbox's
    processes; the `landlock` backend never gets it.
  - W^X: Landlock never grants `EXECUTE` on a writable path (scratch space, output
    directories, the DB cache during updates). A dropped binary or script cannot run.
  - Inside bwrap, Landlock is optional: bwrap's mount namespace already confines paths,
    and Landlock adds W^X. Without Landlock ABI ≥ 2, bwrap keeps working; the backend
    implements `scanner.Degrader`, `doctor` warns, and every preflight keeps a
    `scanner_sandbox_degraded` health finding (medium) open — visible like
    `scanner_unsandboxed`, but it does not lock out older kernels, where refusing would
    leave `backend: none` as the only option. Rejected: requiring Landlock for bwrap
    (excludes Ubuntu 22.04's GA kernel and similar hosts) and degrading silently.
  - `scannertest.CheckSandbox` runs its probes through a Runner with a scratch quota, as
    in production, and checks W^X (skipped with a log line when the backend reports
    itself degraded), the scratch quota (`ErrScratchQuota`), the file size limit, and that
    a DB update may still write a file larger than the quota.
  - Still open: the total scratch quota is enforced by the Runner's watch, not by the
    kernel. Only a size-limited filesystem can do that, and creating one needs
    privileges neither backend has; only the deployment can provide one.
- 2026-10-25, dedicated scratch filesystem (#55): recommended, not required.
  `deploy/scratch` has a host example (loop image or LV with a systemd mount unit) and a
  Kubernetes one (generic ephemeral volume; mount options from the storage class), sized
  for one OCI layout, one scanner's scratch space and the free-space floor. Mounted
  `noexec,nosuid,nodev`, it is also W^X at mount level for everything scanners write,
  which covers `bwrap` without Landlock. `doctor` reports whether `<data_dir>/tmp` is its
  own filesystem, its size, and missing mount options, as information and warnings.
  Rejected: requiring it, which would make every installation, development and CI
  included, need root before the first scan, while the watch and the floor already keep
  the disk from filling.
