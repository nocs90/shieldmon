#!/usr/bin/env python3
"""End-to-end ConMon scenario on a multi-stage UBI 9 + Node.js image.

  1. release 1.0.0: old UBI 9 base images + vulnerable npm deps (lodash, minimist)
  2. scan: OS (RPM) and application (npm) findings, deduplicated across scanners
  3. triage the npm findings; record a vendor-dependency deviation for a
     "won't fix" RPM finding; check that the remediation policy refuses
     acceptances that would outlive the remediation deadline
  4. release 1.1.0: bumped npm deps, rebuilt on the *latest* Node 20 base,
     pushed to the same tag (what a CI pipeline or a Renovate merge does)
  5. monitor: ShieldMon sees the new digest and closes what the new image no
     longer contains, with the new scan as evidence; many fixable OS findings
     remain because Node 20 is end of life and its base image is no longer rebuilt
  6. release 1.2.0: migrate to the Node 22 base (rebuilt monthly) and monitor again
  7. reports: HTML, Markdown and a remediation-plan CSV

Builders:
  --builder docker  real `docker build` of the multi-stage Dockerfile (CI)
  --builder crane   no daemon: append the final stage (app + node_modules,
                    exactly what COPY --from=builder produces) onto the runtime
                    base with crane. For laptops without Docker/Podman.

Requires: shieldmon (bin/shieldmon), syft, grype, trivy; crane (both modes:
registry for --builder crane, pushes in both); docker for --builder docker.
Standard library only.
"""

import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

UBI = "registry.access.redhat.com/ubi9"
REGISTRY_IMAGE = "docker.io/library/registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
RELEASES = {
    # version: (builder image, runtime image, app dir)
    "1.0.0": (f"{UBI}/nodejs-20:1-1736398249", f"{UBI}/nodejs-20-minimal:1-1736729465", "app"),          # Jan 2025
    "1.1.0": (f"{UBI}/nodejs-20:1-1778648167", f"{UBI}/nodejs-20-minimal:1-1778604817", "remediation"),  # May 2026, last Node 20 build (EOL)
    "1.2.0": (f"{UBI}/nodejs-22:1-1792441643", f"{UBI}/nodejs-22-minimal:1-1791924375", "remediation"),  # Oct 2026, Node 22
}

failures = []


def step(title):
    print(f"\n\033[1m=== {title}\033[0m", flush=True)


def check(cond, msg):
    print(("  \033[32m✓\033[0m " if cond else "  \033[31m✗\033[0m ") + msg, flush=True)
    if not cond:
        failures.append(msg)


def run(*cmd, ok=True, capture=True):
    print("  $ " + " ".join(str(c) for c in cmd), flush=True)
    res = subprocess.run([str(c) for c in cmd], capture_output=capture, text=True)
    if ok and res.returncode != 0:
        sys.exit(f"command failed ({res.returncode}): {res.stderr or res.stdout}")
    return res


class Shieldmon:
    def __init__(self, binary, data):
        self.base = [binary, "--data-dir", data, "--config", os.path.join(data, "config.yaml")]

    def __call__(self, *args, ok=True):
        return run(*self.base, *args, ok=ok)

    def json(self, *args):
        return json.loads(self(*args, "-o", "json").stdout)


def npm_layer(app_dir, out_tar):
    """Build the final-stage layer: /opt/app-root/src with node_modules installed
    from package-lock.json (tarballs verified against their sha512 integrity)."""
    lock = json.loads((app_dir / "package-lock.json").read_text())
    with tarfile.open(out_tar, "w") as tar:
        def add(path, data, mode=0o644):
            ti = tarfile.TarInfo("opt/app-root/src/" + path)
            ti.size, ti.mode, ti.uid, ti.gid, ti.mtime = len(data), mode, 1001, 0, 0
            tar.addfile(ti, io.BytesIO(data))
        for f in ("server.js", "package.json", "package-lock.json"):
            add(f, (app_dir / f).read_bytes())
        for path, meta in lock["packages"].items():
            if not path.startswith("node_modules/"):
                continue
            with urllib.request.urlopen(meta["resolved"], timeout=60) as r:  # noqa: S310 (https registry URL from lockfile)
                tgz = r.read()
            algo, want = meta["integrity"].split("-", 1)
            got = base64.b64encode(hashlib.new(algo, tgz).digest()).decode()
            if got != want:
                sys.exit(f"integrity mismatch for {path}")
            with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as pkg:
                for m in pkg.getmembers():
                    if not m.isfile():
                        continue
                    rel = m.name.split("/", 1)[1]  # strip "package/"
                    if ".." in rel.split("/"):
                        sys.exit(f"refusing path traversal in {path}: {m.name}")
                    add(f"{path}/{rel}", pkg.extractfile(m).read())


def build(builder, crane, version, ref):
    builder_img, runtime_img, app = RELEASES[version]
    step(f"Build release {version}: runtime base {runtime_img.split('/')[-1]}, deps from {app}/package-lock.json")
    if builder == "docker":
        run("docker", "build", "--platform", "linux/amd64", "-f", HERE / "Dockerfile",
            "--build-arg", f"BUILDER_IMAGE={builder_img}", "--build-arg", f"RUNTIME_IMAGE={runtime_img}",
            "--build-arg", f"APP_DIR={app}", "-t", ref, HERE, capture=False)
        run("docker", "push", ref, capture=False)
        return
    with tempfile.TemporaryDirectory() as tmp:
        layer = os.path.join(tmp, "app.tar")
        npm_layer(HERE / app, layer)
        run(crane, "append", "--platform", "linux/amd64", "-b", runtime_img, "-f", layer, "-t", ref)
        run(crane, "mutate", ref, "--cmd", "node,server.js", "--user", "1001", "--workdir", "/opt/app-root/src",
            "-l", f"org.opencontainers.image.version={version}", "-t", ref)


def findings(sc, digest=None):
    args = ["findings", "list", "--all"]
    if digest:
        args += ["--digest", digest]
    return sc.json(*args)


def by_vuln(fs, pkg, vuln):
    return [f for f in fs if f["pkg_name"] == pkg and (f["vuln_id"] == vuln or vuln in (f.get("aliases") or []))]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--builder", choices=["crane", "docker"], default="crane")
    ap.add_argument("--registry", default="localhost:5001", help="registry host:port (started automatically with --builder crane)")
    ap.add_argument("--start-registry", action="store_true",
                    help="with --builder docker: run a throw-away registry:2 container on --registry's port and remove it at the end")
    ap.add_argument("--shieldmon", default=str(ROOT / "bin" / "shieldmon"))
    ap.add_argument("--crane", default=shutil.which("crane") or str(ROOT / "bin" / "crane"))
    ap.add_argument("--out", default=str(ROOT / "dist" / "e2e-ubi9-node"), help="data dir and reports")
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    ref = f"{args.registry}/demo/ubi9-node:prod"
    sc = Shieldmon(args.shieldmon, str(out / "data"))

    registry = None
    container = None
    if args.builder == "crane":
        registry = subprocess.Popen([args.crane, "registry", "serve", "--address", args.registry],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    elif args.start_registry:
        port = args.registry.rsplit(":", 1)[1]
        container = "shieldmon-e2e-registry"
        run("docker", "rm", "-f", container, ok=False)
        run("docker", "run", "-d", "--rm", "--name", container, "-p", f"127.0.0.1:{port}:5000", REGISTRY_IMAGE)
        time.sleep(2)
    try:
        sc("init")

        # 1-2. First release and scan.
        build(args.builder, args.crane, "1.0.0", ref)
        step("Scan release 1.0.0")
        res = sc.json("scan", ref)[0]
        print(f"  digest {res['digest']}: {res['matches']} findings, SBOMs by {', '.join(res.get('sboms_created') or [])}")
        check(res["status"] == "complete", "scan complete with both matchers")
        v1 = res["digest"]
        fs = findings(sc, v1)
        npm = [f for f in fs if f["pkg_type"] == "npm" or f["purl"].startswith("pkg:npm/")]
        rpm = [f for f in fs if f["purl"].startswith("pkg:rpm/")]
        print(f"  OS (rpm) findings: {len(rpm)} · application (npm) findings: {len(npm)}")
        check(len(rpm) > 0, "OS package vulnerabilities found in the UBI 9 base")
        lodash = by_vuln(fs, "lodash", "CVE-2021-23337")
        minimist = by_vuln(fs, "minimist", "CVE-2021-44906")
        check(len(lodash) == 1, "lodash 4.17.20 command injection (CVE-2021-23337) detected once (deduplicated)")
        check(len(minimist) == 1, "minimist 1.2.5 prototype pollution (CVE-2021-44906) detected once (deduplicated)")
        both = [f for f in fs if len(f.get("scanners") or []) == 2]
        print(f"  confirmed by both grype and trivy: {len(both)}/{len(fs)}")

        # 3. Triage and decisions under the remediation policy (standard SLA profile).
        step("Triage and decisions (SLA profile standard: critical/high 30 d, medium 90 d, low 180 d)")
        for f in lodash + minimist:
            sc("findings", "triage", f["ID"], "--note", "bump npm dependency in the next release", "--actor", "dev-team")
        late = (dt.date.today() + dt.timedelta(days=400)).isoformat()
        if lodash:
            r = sc("findings", "accept-risk", lodash[0]["ID"], "--author", "secops", "--expires", late,
                   "--justification", "input never reaches lodash.template", ok=False)
            check(r.returncode != 0, "plain risk acceptance beyond the SLA deadline is refused")
            print("    " + (r.stderr.strip().splitlines() or [""])[-1])
            r = sc("findings", "accept-risk", lodash[0]["ID"], "--deviation", "vendor-dependency", "--author", "secops",
                   "--justification", "waiting for upstream", ok=False)
            check(r.returncode != 0, "vendor dependency is refused when a fix exists (lodash 4.17.21)")
        wontfix = [f for f in rpm if f["fix_state"] == "wont_fix" and f["State"] == "open"]
        print(f"  RPM findings marked won't fix by the vendor: {len(wontfix)}")
        accepted = None
        if wontfix:
            accepted = sorted(wontfix, key=lambda f: -f["cvss_score"])[0]
            r = sc("findings", "accept-risk", accepted["ID"], "--deviation", "vendor-dependency", "--author", "secops",
                   "--justification", f"Red Hat will not fix {accepted['vuln_id']} in UBI 9; reviewed monthly (vendor dependency)")
            print("    " + r.stdout.strip())
            check("vendor_dependency" in r.stdout, "won't-fix finding accepted as a vendor dependency (30-day review)")
        else:
            print("  (no won't-fix findings in today's vulnerability data: skipping the vendor-dependency step)")

        # 4-5. Remediation by rebuild, detected by monitoring.
        build(args.builder, args.crane, "1.1.0", ref)
        step("Monitor: the tag now points to release 1.1.0")
        run_ = sc.json("monitor")
        check(run_["status"] == "ok", f"monitor run #{run_['run_id']} status ok")
        mon = run_["results"][0]
        v2 = mon["digest"]
        print(f"  digest changed {mon.get('previous_digest', '')[:19]} → {v2[:19]}; transitions {mon.get('transitions')}")
        check(mon["digest_changed"], "new digest detected for the same tag")
        check(mon.get("transitions", {}).get("fixed", 0) > 0, "findings closed as fixed with the new scan as evidence")
        after = {f["ID"]: f for f in findings(sc)}
        for f in lodash + minimist:
            check(after[f["ID"]]["State"] == "fixed", f"{f['pkg_name']} {f['vuln_id']} → fixed (dependency bumped)")
        if accepted:
            succ = [f for f in after.values() if f.get("PredecessorID") == accepted["ID"]]
            if succ:
                check(succ[0]["State"] in ("risk_accepted", "reopened"),
                      f"vendor-dependency decision followed {accepted['vuln_id']} to the new digest ({succ[0]['State']})")
            else:
                check(after[accepted["ID"]]["State"] == "fixed", f"{accepted['vuln_id']} no longer present after the rebuild")
        def open_on(digest):
            return [f for f in findings(sc, digest) if f["State"] in ("open", "reopened", "triaged", "in_remediation")]

        def fixable(fs):
            return [f for f in fs if f["fix_state"] == "fixed"]

        open_v2 = open_on(v2)
        print(f"  open on release 1.1.0: {len(open_v2)}, of which {len(fixable(open_v2))} already have a fix upstream "
              "(the Node 20 base is end of life: rebuilding on it cannot pick them up)")

        # 6. Migrate the base image lineage.
        build(args.builder, args.crane, "1.2.0", ref)
        step("Monitor: the tag now points to release 1.2.0 (Node 22 base)")
        run2 = sc.json("monitor")
        mon2 = run2["results"][0]
        v3 = mon2["digest"]
        print(f"  digest changed → {v3[:19]}; transitions {mon2.get('transitions')}")
        open_v3 = open_on(v3)
        print(f"  open on release 1.2.0: {len(open_v3)}, of which {len(fixable(open_v3))} have a fix upstream")
        check(mon2["digest_changed"], "new digest detected for release 1.2.0")
        check(len(fixable(open_v3)) < len(fixable(open_v2)), "migrating to a maintained base removed fixable findings")

        # 7. Reports.
        step("Reports")
        for fmt, name in (("html", "report.html"), ("md", "report.md"), ("csv", "remediation-plan.csv")):
            sc("report", "monthly", "-o", fmt, "--out", out / name)
        check((out / "report.html").stat().st_size > 1000, f"HTML report written to {out / 'report.html'}")
    finally:
        if registry:
            registry.send_signal(signal.SIGTERM)
            registry.wait(timeout=10)
        if container:
            run("docker", "rm", "-f", container, ok=False)

    step("Result")
    if failures:
        print(f"{len(failures)} check(s) failed:\n  - " + "\n  - ".join(failures))
        sys.exit(1)
    print(f"all checks passed · reports in {out}")


if __name__ == "__main__":
    main()
