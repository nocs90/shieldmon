# Remediation: how fixes happen and how ShieldMon tracks them

ShieldMon **never changes an image** and there is no "mark as fixed" button. It observes.
A fix exists for ShieldMon when the tag it monitors points to a new digest that no
longer contains the vulnerable package — whatever produced that digest.

```
 finding opened ──► you change the source ──► CI builds + pushes the same tag ──► next monitor cycle
   (scan N)          (Dockerfile / lockfile)      (new digest)                     resolves tag → new digest
                                                                                   absent  → fixed   (evidence: scan N+1)
                                                                                   present → carried over (state kept)
```

## Who changes the image?

| Way | What changes | ShieldMon's role |
|---|---|---|
| **Rebuild on a newer base** (`docker build --pull`, nightly rebuild) | OS packages from the base image (e.g. a new `ubi9/nodejs-20-minimal` tag) | detects the new digest, closes what disappeared |
| **Bump the base image reference** (Renovate/Dependabot PR on `FROM … @sha256:`) | base image digest pinned in the Dockerfile | same; Renovate makes the change reviewable |
| **Bump application dependencies** (Renovate on `package-lock.json`, `go.mod`, …) | language packages copied into the image | same |
| **OS package upgrade in the Dockerfile** (`microdnf upgrade <pkg>`) | individual RPM/DEB/APK packages | same |
| **Copacetic patch** (planned, M7) | OS packages patched without a rebuild | proposes the patch; the patched digest is evidence like any other |

Renovate or Dependabot are the recommended way to *automate the change* (pinned base
digests + lockfiles, reviewed PRs, tests). ShieldMon's job is the *tracking*: proving that
the change reached the image that is actually deployed, measuring time to remediate, and
keeping the audit trail. It does not open PRs itself today; remediation proposals and
base-image upgrade candidates are planned (issues #35, #36).

## Rebuild or migrate?

A rebuild only picks up fixes that the base image vendor has already published *in that
base lineage*. When the lineage is end of life it stops being rebuilt, and no amount of
rebuilding helps: in the UBI 9 example, the last `ubi9/nodejs-20-minimal` (Node 20 EOL,
May 2026) still carries hundreds of findings with upstream fixes that
`ubi9/nodejs-22-minimal` (rebuilt monthly) does not. Check the age of the newest tag of
your base before planning a remediation; detecting stale lineages automatically is
tracked in the backlog.

## Making detection immediate

The scheduled `monitor` cycle picks up a new digest within one interval (24h by default).
To close findings right after a release, call ShieldMon from the pipeline after the push:

```sh
docker push registry.example.com/team/api:prod
shieldmon scan registry.example.com/team/api:prod   # resolves the new digest now
```

## What a human still does

- **Triage** (`findings triage`, `findings remediate`): who is working on it.
- **Decide** what will not be fixed in time, under the remediation policy
  ([triage-and-decisions.md](triage-and-decisions.md)): VEX `not-affected`, risk
  acceptance within the SLA, or a deviation (vendor dependency / operational requirement).

A worked example with a multi-stage UBI 9 + Node.js image, including the rebuild that
closes the findings, is in [examples/ubi9-node](../../examples/ubi9-node/README.md).
