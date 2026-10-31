# Deployment: a scheduled monitoring cycle

`shieldmon monitor` runs one cycle and exits; a scheduler runs it daily. Two copy-paste setups
ship with the repository:

| Where | Files | Sandbox for scanners |
|---|---|---|
| Linux host with systemd | [deploy/systemd](../../deploy/systemd) | `bwrap` (Ubuntu ≥ 23.10: [deploy/apparmor](../../deploy/apparmor/README.md)), or `landlock` |
| Kubernetes | [deploy/kubernetes](../../deploy/kubernetes) | `landlock` in ShieldMon's image ([ADR 0012](../adr/0012-container-image.md)) |

Both keep the same layout: a persistent data dir (the database with its audit trail, SBOMs,
vulnerability DBs, scratch space), a configuration file without credentials, a
`targets.txt` with one image reference per line, added before each cycle (`targets add -f`
adds what is missing and never removes: retire decommissioned images with `targets retire`),
and JSON logs ([monitoring-cycle.md](monitoring-cycle.md#logs)).

## systemd

```sh
sudo useradd --system --home-dir /var/lib/shieldmon --shell /usr/sbin/nologin shieldmon
sudo install -m 0755 bin/shieldmon /usr/local/bin/        # and the scanners: scripts/install-scanners.sh
sudo install -d -m 0750 -g shieldmon /etc/shieldmon
sudo -u shieldmon shieldmon --config /etc/shieldmon/config.yaml --data-dir /var/lib/shieldmon init   # or write it
sudo install -m 0640 -g shieldmon /dev/null /etc/shieldmon/targets.txt   # then list images in it
sudo cp deploy/systemd/shieldmon-monitor.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now shieldmon-monitor.timer
systemctl start shieldmon-monitor.service && journalctl -u shieldmon-monitor -o cat   # a first cycle now
```

The service runs as an unprivileged user without capabilities, with the file system read-only
except `/var/lib/shieldmon` (`ProtectSystem=strict`) and no access to home directories. Some
hardening options are left out on purpose, because the `bwrap` sandbox the scanners run in
needs what they forbid (namespaces, `mount`, `pivot_root`); the unit says which and why.
Check the result with `systemd-analyze security shieldmon-monitor.service`, and that the
sandbox runs with `sudo -u shieldmon shieldmon plugins` (and `shieldmon health` after a cycle:
no `scanner_unsandboxed`).

A size-limited, `noexec` scratch filesystem for `/var/lib/shieldmon/tmp` is a mount unit away:
[deploy/scratch](../../deploy/scratch/README.md).

## Kubernetes

```sh
kubectl create namespace shieldmon
kubectl apply -k deploy/kubernetes -n shieldmon       # after setting the image and targets.txt
kubectl create job --from=cronjob/shieldmon-monitor first-cycle -n shieldmon
kubectl logs -n shieldmon job/first-cycle -c monitor -f
```

- **Image**: ShieldMon's own, pinned by digest (the `images:` entry of `kustomization.yaml`);
  releases publish it as `ghcr.io/nocs90/shieldmon`, signed and with provenance: verify it by
  digest as [release.md](release.md#verifying-a-release) shows. Before the first release, build
  it with `make image` and push it to
  your registry. It runs as 65532 with a read-only root file system, no capabilities and the
  runtime's default seccomp profile; the nodes need Linux ≥ 5.19 for Landlock.
- **CronJob**: `concurrencyPolicy: Forbid` (the data dir is locked), no retries
  (`backoffLimit: 0`: the next cycle runs on schedule and health findings say what failed),
  a 6-hour deadline. An init container adds the targets of `targets.txt`.
- **Storage**: a `ReadWriteOnce` claim of 64 GiB (`pvc.yaml` explains the size). It holds the
  evidence: back it up like a database.
- **Identity**: the service account mounts no token. For Amazon ECR annotate it for IRSA (or
  use Pod Identity) with [deploy/iam](../../deploy/iam/README.md); for other registries mount a
  docker config Secret and set `DOCKER_CONFIG`. Notification credentials come from a Secret
  as environment variables named by the configuration's `*_env` options.
- **Reports**: run them as one-off Jobs on the same claim, or copy the database out
  (`kubectl cp`) and run `shieldmon report` elsewhere; while a cycle runs, the data dir is
  locked.

## After deploying

- `shieldmon health` after the first cycles: nothing should stay open, in particular
  `scanner_unsandboxed`, `db_stale`, `monitor_missed`.
- `shieldmon report inventory`: every image from `targets.txt` is there, without evidence gaps.
- Back up the data dir before upgrading ShieldMon: migrations change the schema forward only.
