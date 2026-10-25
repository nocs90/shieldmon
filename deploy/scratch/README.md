# A dedicated filesystem for scanner scratch space

Scanners unpack hostile image layers into `<data_dir>/tmp`, which also holds the OCI layout
ShieldMon downloads and every scanner's output. ShieldMon bounds that space itself: each
process's scratch directory is watched against `limits.max_scratch_bytes`, and a scanner is
killed when free space drops below `limits.min_free_disk_bytes`
([ADR 0011](../../docs/adr/0011-scanner-sandbox.md)). Between two checks a scanner can still
write for 100 ms.

A dedicated, size-limited filesystem at `<data_dir>/tmp` turns that into a bound the kernel
enforces, and mounted `noexec,nosuid,nodev` it also makes everything a scanner writes
non-executable, including under `bwrap` on kernels without Landlock. Creating it needs root,
so it is part of the deployment, not of ShieldMon. It is recommended, not required.

`shieldmon doctor` reports what it finds:

```text
• scratch /var/lib/shieldmon/tmp: dedicated filesystem, 50.0 GiB
! scratch filesystem is not mounted noexec
```

## Size

The filesystem holds, at most, one image's OCI layout, one scanner's scratch space, and the
free-space floor:

```text
size ≥ limits.max_total_bytes + limits.max_scratch_bytes + limits.min_free_disk_bytes
     = 16 GiB + 32 GiB + 2 GiB with the defaults
```

Smaller is fine if you lower the limits to match: a scan that does not fit fails with a
health finding instead of filling the disk.

## Linux host (systemd)

A loop-mounted image on the data dir's disk; a logical volume (`lvcreate -L 50G -n
shieldmon-scratch <vg>`) works the same way and avoids the loop device.

```sh
sudo fallocate -l 50G /var/lib/shieldmon-scratch.img
sudo mkfs.ext4 -q -m 0 /var/lib/shieldmon-scratch.img
sudo install -m 0644 deploy/scratch/var-lib-shieldmon-tmp.mount /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now var-lib-shieldmon-tmp.mount
sudo chown shieldmon: /var/lib/shieldmon/tmp && sudo chmod 0700 /var/lib/shieldmon/tmp
```

The unit's name must match its mount point: for another data dir, rename it with
`systemd-escape -p --suffix=mount <data_dir>/tmp` and change `Where=`. The service that runs
`shieldmon monitor` should declare `RequiresMountsFor=<data_dir>/tmp`, so that it never runs
on the unbounded directory underneath.

## Kubernetes

A generic ephemeral volume is a real filesystem of the requested size, created with the pod
and deleted with it:

```yaml
spec:
  containers:
    - name: shieldmon
      volumeMounts:
        - name: scratch
          mountPath: /data/tmp        # <data_dir>/tmp
  volumes:
    - name: scratch
      ephemeral:
        volumeClaimTemplate:
          spec:
            accessModes: [ReadWriteOnce]
            storageClassName: shieldmon-scratch
            resources:
              requests:
                storage: 50Gi
```

Mount options come from the storage class, if its CSI driver honours them:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: shieldmon-scratch
provisioner: <your CSI driver>
mountOptions: [noexec, nosuid, nodev]
reclaimPolicy: Delete
```

An `emptyDir` with `sizeLimit` is not a bound of the same kind: the kubelet measures it
periodically and evicts the pod afterwards, as ShieldMon's own watch does.
