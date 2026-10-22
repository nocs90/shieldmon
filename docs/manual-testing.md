# Manual testing with Docker

A hands-on session on your own machine: build images with Docker (the example's
multi-stage Dockerfile, then your own), push them to a local registry, and drive the
whole ConMon loop by hand — scan, triage, decisions, remediation by rebuild, reports.

ShieldMon itself never uses the Docker daemon: it reads images from a **registry** by
digest. Docker is only your build tool here, exactly as in a real CI pipeline.

## 0. One-time setup

```sh
# Docker: Docker Desktop, or on macOS the lightweight alternative
brew install colima docker docker-buildx && colima start

# ShieldMon and its scanners
make build
brew install syft grype trivy        # or scripts/install-scanners.sh on linux/amd64
```

A local registry and an isolated ShieldMon data dir:

```sh
docker run -d --name registry -p 127.0.0.1:5001:5000 registry:2    # port 5000 is taken by AirPlay on macOS

export SC_DATA=/tmp/shieldmon-manual
alias sc='./bin/shieldmon --data-dir $SC_DATA --config $SC_DATA/config.yaml'
sc init
sc doctor
```

> **Apple Silicon.** The commands below build `linux/amd64` images (emulated, slower).
> For speed build `--platform linux/arm64` and scan with `sc scan --platform linux/arm64 …`;
> UBI images are multi-arch. Use the same platform for build and scan.

## 1. Release 1.0.0: an old base and vulnerable dependencies

```sh
cd examples/ubi9-node
docker build --platform linux/amd64 \
  --build-arg BUILDER_IMAGE=registry.access.redhat.com/ubi9/nodejs-20:1-1736398249 \
  --build-arg RUNTIME_IMAGE=registry.access.redhat.com/ubi9/nodejs-20-minimal:1-1736729465 \
  --build-arg APP_DIR=app \
  -t localhost:5001/demo/api:prod .
docker push localhost:5001/demo/api:prod
cd -
```

Scan it:

```sh
sc scan localhost:5001/demo/api:prod
sc targets list
sc findings list --severity high                 # FIX column: versions, "won't fix", "no fix yet"
sc findings list --vuln CVE-2021-23337           # lodash, from package-lock.json
sc findings show <ID>                            # details, SLA due date, audit trail
sc sbom list 1                                   # the SBOMs stored for target #1
sc sbom export 1 --format spdx-json > /tmp/api.spdx.json
```

Things to observe: OS (RPM) and npm findings in one list; most confirmed by both grype and
trivy; a second `sc scan` of the same tag is a rematch (no pull, seconds).

## 2. Triage and decisions

```sh
sc findings triage <lodash ID> --note "bump lodash in the next release"
sc findings remediate <lodash ID>

# refused: a plain acceptance cannot outlive the SLA deadline (high = 30 days)
sc findings accept-risk <lodash ID> --author you --expires 2027-12-31 --justification "not reachable"

# refused: a fix exists, so this is not a vendor dependency
sc findings accept-risk <lodash ID> --deviation vendor-dependency --author you --justification "waiting"

# accepted for 30 days, reopens by itself if the vendor ships a fix
sc findings list --all -o csv | grep wont_fix | head -3
sc findings accept-risk <won't-fix ID> --deviation vendor-dependency --author you \
  --justification "vendor will not fix; reviewed monthly"

sc findings show <won't-fix ID>
```

## 3. Remediate by rebuilding, then by migrating the base

Release 1.1.0 bumps the npm dependencies and rebuilds on the latest Node 20 base:

```sh
cd examples/ubi9-node
docker build --platform linux/amd64 \
  --build-arg BUILDER_IMAGE=registry.access.redhat.com/ubi9/nodejs-20:1-1778648167 \
  --build-arg RUNTIME_IMAGE=registry.access.redhat.com/ubi9/nodejs-20-minimal:1-1778604817 \
  --build-arg APP_DIR=remediation \
  -t localhost:5001/demo/api:prod .
docker push localhost:5001/demo/api:prod
cd -
sc monitor                      # or: sc scan localhost:5001/demo/api:prod
sc findings show <lodash ID>    # "absent from successor digest (evidence: scan #…)"
sc findings list --target 1 -o csv | cut -d, -f7 | sort | uniq -c    # fix_state of what is still open
```

Many findings with an upstream fix remain: Node 20 is end of life and its base image is
no longer rebuilt. Release 1.2.0 migrates to the maintained Node 22 base:

```sh
cd examples/ubi9-node
docker build --platform linux/amd64 \
  --build-arg BUILDER_IMAGE=registry.access.redhat.com/ubi9/nodejs-22:1-1792441643 \
  --build-arg RUNTIME_IMAGE=registry.access.redhat.com/ubi9/nodejs-22-minimal:1-1791924375 \
  --build-arg APP_DIR=remediation \
  -t localhost:5001/demo/api:prod .
docker push localhost:5001/demo/api:prod
cd -
sc monitor
```

## 4. Reports

```sh
sc report monthly -o html --out $SC_DATA/report.html && open $SC_DATA/report.html
sc report monthly -o md
sc report monthly -o csv --out $SC_DATA/remediation-plan.csv
sc health --all
```

## 5. Your own Dockerfile

Any Dockerfile works; the loop is always build → push the same tag → scan/monitor.

```sh
docker build --platform linux/amd64 -t localhost:5001/myteam/myapp:prod -f path/to/Dockerfile path/to/context
docker push localhost:5001/myteam/myapp:prod
sc scan localhost:5001/myteam/myapp:prod
sc findings list --target localhost:5001/myteam/myapp:prod --severity high
# … change the Dockerfile (base image, packages, dependencies), rebuild, push, then:
sc monitor
```

Tips:

- Tag what you deploy (`:prod`, `:staging`): ShieldMon tracks the tag and follows its digests.
- Scan several images at once: `sc scan img1 img2 img3`; `sc monitor` re-checks them all.
- Real registries work the same way: `sc scan docker.io/library/nginx:1.27`, private ECR or
  GCR with your cloud credentials (see [processes/registries.md](processes/registries.md)).

## 6. Provoke the self-health checks

| Do this | Expect in `sc health` |
|---|---|
| `docker stop registry`, then `sc monitor` | `resolve_failed`; monitor run degraded/failed |
| `docker start registry`, `sc monitor` | resolved automatically |
| set `health.db_max_age: 1m` in `$SC_DATA/config.yaml`, `sc monitor` | `db_stale` |
| set `scanners.tools.grype.sha256: "0000…"` | `scanner_checksum_mismatch` (treated as possible compromise) |

## Scripted version

The same scenario, with assertions, runs unattended:

```sh
python3 examples/ubi9-node/e2e.py --builder docker --start-registry --registry localhost:5001
```

## Clean up

```sh
docker rm -f registry
rm -rf $SC_DATA
```
