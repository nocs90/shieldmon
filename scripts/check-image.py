#!/usr/bin/env python3
"""Check a ShieldMon container image without running it (docs/adr/0012-container-image.md).

For every platform: the process runs as 65532:65532, the entrypoint is ShieldMon with /data
as data dir, TMPDIR is under /data, and shieldmon, syft, grype and trivy are present and are
static ELF executables for that platform.

Usage: scripts/check-image.py CRANE IMAGE
"""

import io
import json
import subprocess
import sys
import tarfile

PLATFORMS = {"linux/amd64": 62, "linux/arm64": 183}  # ELF e_machine: EM_X86_64, EM_AARCH64
BINARIES = ["usr/local/bin/" + b for b in ("shieldmon", "syft", "grype", "trivy")]


def crane(*args):
    return subprocess.run([CRANE, *args], check=True, capture_output=True).stdout


def check(platform, machine):
    problems = []
    cfg = json.loads(crane("config", "--platform", platform, IMAGE)).get("config", {})
    if cfg.get("User") != "65532:65532":
        problems.append(f"user is {cfg.get('User')!r}, want 65532:65532")
    if cfg.get("Entrypoint") != ["/usr/local/bin/shieldmon", "--data-dir", "/data"]:
        problems.append(f"entrypoint is {cfg.get('Entrypoint')!r}")
    if "TMPDIR=/data/tmp" not in cfg.get("Env", []):
        problems.append("TMPDIR is not /data/tmp: a read-only root filesystem has no /tmp")

    found = {}
    with tarfile.open(fileobj=io.BytesIO(crane("export", "--platform", platform, IMAGE, "-"))) as tar:
        for m in tar:
            if m.name in BINARIES and m.isfile():
                found[m.name] = tar.extractfile(m).read(20)
    for name in BINARIES:
        head = found.get(name)
        if head is None:
            problems.append(f"{name} is missing")
        elif head[:4] != b"\x7fELF":
            problems.append(f"{name} is not an ELF executable")
        elif int.from_bytes(head[18:20], "little") != machine:
            problems.append(f"{name} is built for ELF machine {int.from_bytes(head[18:20], 'little')}, want {machine}")
    return problems


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    CRANE, IMAGE = sys.argv[1], sys.argv[2]
    failed = False
    for platform, machine in PLATFORMS.items():
        problems = check(platform, machine)
        for p in problems:
            print(f"{platform}: {p}", file=sys.stderr)
        failed = failed or bool(problems)
        print(f"{platform}: {'FAIL' if problems else 'ok'}")
    sys.exit(1 if failed else 0)
