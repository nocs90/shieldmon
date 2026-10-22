# Example: multi-stage UBI 9 + Node.js service

A realistic image to learn the whole ConMon loop on, and the end-to-end quality gate that
CI runs on every main build (`e2e-ubi9-node` job).

```
Dockerfile
 ├─ stage "builder": registry.access.redhat.com/ubi9/nodejs-20        npm ci --omit=dev
 └─ final stage:     registry.access.redhat.com/ubi9/nodejs-20-minimal + /opt/app-root/src
app/          release 1.0.0 — lodash 4.17.20, minimist 1.2.5 (known CVEs)
remediation/  releases 1.1.0 / 1.2.0 — lodash 4.18.1, minimist 1.2.8
```

Only the final stage ships, so only its content is scanned: the UBI 9 minimal base (RPM
packages) plus the application and its `node_modules` (npm packages). Whatever the builder
stage adds (compilers, caches, dev dependencies) never reaches production and never shows up
as findings — one of the reasons to build multi-stage. The runtime base itself still ships
the npm CLI, though (see the lessons below).

## Run the scenario

By hand, step by step with Docker (recommended to learn the tool, and the way to try
your own Dockerfile): [docs/manual-testing.md](../../docs/manual-testing.md).

Scripted, with assertions:

```sh
make build

# with Docker (what CI does): real multi-stage build, throw-away local registry
python3 examples/ubi9-node/e2e.py --builder docker --start-registry --registry localhost:5001

# without Docker/Podman: crane appends the final-stage layer onto the runtime base
go build -o bin/crane github.com/google/go-containerregistry/cmd/crane
python3 examples/ubi9-node/e2e.py --builder crane
```

Reports land in `dist/e2e-ubi9-node/` (`report.html`, `report.md`, `remediation-plan.csv`), and the
ShieldMon data dir is `dist/e2e-ubi9-node/data` — explore it afterwards:

```sh
alias sc='./bin/shieldmon --data-dir dist/e2e-ubi9-node/data --config dist/e2e-ubi9-node/data/config.yaml'
sc targets list
sc findings list --severity high
sc findings list --state risk_accepted
sc findings show <ID>
```

## What the scenario does (and what to look for)

| Step | ShieldMon | What it shows |
|---|---|---|
| Release 1.0.0 (Jan 2025 bases, vulnerable npm deps) | `scan` | OS and npm findings in one list, deduplicated across grype and trivy; fix versions or *won't fix* per finding; SLA due dates (standard profile) |
| Triage | `findings triage` | who is on it; audit trail |
| Try to accept lodash's risk for a year | `findings accept-risk --expires +400d` | **refused**: a plain acceptance cannot outlive the 30-day deadline |
| Try "vendor dependency" for lodash | `--deviation vendor-dependency` | **refused**: a fix (4.17.21) exists |
| Accept a Red Hat *won't fix* RPM finding | `--deviation vendor-dependency` | accepted for 30 days (monthly review); reopens by itself if Red Hat ships a fix |
| Release 1.1.0 (bumped deps, rebuilt on the *latest* Node 20 base), same tag | `monitor` | new digest detected; findings absent from it → **fixed** with the scan as evidence; the rest carried over with their state and original detection date. Hundreds of OS findings with an upstream fix remain: Node 20 is end of life and Red Hat stopped rebuilding its image in May 2026 |
| Release 1.2.0 (migrated to the Node 22 base, rebuilt monthly) | `monitor` | findings with an upstream fix drop from ~245 to ~24 (run of 2026-10-21): remediation sometimes means moving to a maintained base lineage, not just rebuilding. What remains is mostly *no fix yet* / *won't fix* from the vendor — the queue for decisions |
| Reports | `report monthly -o html\|md\|csv` | MTTR, burndown, SLA, accepted risks with deviation type |

## Lessons the scenario makes visible

- **Rebuilding is not enough on an end-of-life base.** Check that the base image you
  rebuild on is still being rebuilt by its vendor.
- **The base image brings its own application packages.** Many npm findings on the
  Node.js images (`tar`, `minimatch`, `pacote`, …) belong to the npm CLI shipped in the
  base, not to your app. Removing tooling you do not need at runtime shrinks the list.
- **"Won't fix" is a vendor decision, not a scanner bug.** Track it as a vendor
  dependency with a monthly review instead of suppressing it forever.

## Remediating your own image

Change the source (base image tag or digest in the Dockerfile, dependency versions in the
lockfile), rebuild, push the same tag, then `shieldmon scan <ref>` or wait for the next
`monitor` cycle. See [docs/processes/remediation.md](../../docs/processes/remediation.md).
