# CI gate: pass, warn or fail an image on policy

Normative rules: [ADR 0021](../adr/0021-policy-gate.md). This page is the runbook.

```sh
shieldmon gate registry.example.com/app:1.4.2                       # scan, then decide
shieldmon gate --policy ci/gate-policy.yaml -o sarif --out gate.sarif registry.example.com/app:1.4.2
shieldmon gate --no-scan registry.example.com/app:prod              # decide on stored evidence
```

`gate` scans the image as `shieldmon scan` does (SBOMs once per digest, both matchers,
enrichers), then evaluates the findings of its digest. `--no-scan` takes a target ID, an
image reference or a digest prefix of an image already scanned and contacts no registry and
no scanner: a deploy step can ask the monitoring instance whether what runs in production
still meets the policy.

## Verdicts and exit codes

| Verdict | When | Exit status (default) |
|---|---|---|
| `pass` | no finding is flagged, and the evidence is complete and fresh | 0 |
| `warn` | only `warn` rules match, and the evidence is complete and fresh | 0 (`exit_codes.warn`) |
| `fail` | a `fail` rule matches a finding that is not exempt, whatever the evidence | 2 (`exit_codes.fail`) |
| `indeterminate` | nothing fails, but the evidence cannot prove a pass (below) | 3 (`exit_codes.indeterminate`) |
| — | an error: bad arguments or policy, the image cannot be resolved, storage | 1 |

The verdict fails closed. Without a violation it is `indeterminate` when:

- the scan is `partial` or `failed` (a matcher failed: findings may be missing);
- a matcher's vulnerability DB is older than `max_db_age` (default: `health.db_max_age`), or
  the matcher did not report its DB's age;
- with `--no-scan`: the image was never scanned, or its latest scan is older than
  `max_evidence_age` (default 24h; `shieldmon monitor` rescans every target daily).

Treat `indeterminate` as "retry or look at `shieldmon health`", not as a pass. To show it as a
warning instead of a failure, use your CI's exit-status mapping (GitLab
`allow_failure: exit_codes: [3]`) rather than setting its code to 0, which validation refuses.

## The policy

The `gate` section of the configuration, or a file given with `--policy` with the same keys
(unknown keys are refused; at most 1 MiB). Without either, this built-in policy applies:

```yaml
gate:
  rules:
    - { name: exploited, action: fail, when: { kev: true } }
    - { name: critical, action: fail, when: { severity: critical } }
    - { name: past-deadline, action: fail, when: { sla_breached: true } }
    - { name: high, action: warn, when: { severity: high } }
  exempt: [not_affected, risk_accepted]
  # max_db_age: 72h       # default: health.db_max_age
  max_evidence_age: 24h
  exit_codes: { warn: 0, fail: 2, indeterminate: 3 }
```

A rule matches a finding when **all** its conditions hold; `when: {}` matches every finding.
A finding takes the strongest action of the rules it matches (`fail` over `warn`), and the
output lists every rule that matched.

| Condition | Matches when the finding… |
|---|---|
| `severity: high` | is at least this severe (critical, high, medium, low, negligible); unknown severity matches no severity condition |
| `cvss: 7.0` | has a CVSS base score of at least this |
| `epss: 0.1` | has an EPSS probability of at least this (0–1) |
| `priority: 70` | has a priority score of at least this ([ADR 0020](../adr/0020-priority-score.md)) |
| `age_days: 30` | was first detected at least this many days ago (inherited across rebuilds) |
| `kev: true` | is (or, with `false`, is not) in CISA KEV |
| `fixable: true` | has (or does not have) a known fixed version |
| `sla_breached: true` | is past its remediation deadline under `sla.profile` |

Examples:

```yaml
rules:
  # Block what can be fixed by an upgrade today; warn on the rest of high and critical.
  - { name: fixable-severe, action: fail, when: { severity: high, fixable: true } }
  - { name: exploited, action: fail, when: { kev: true } }
  - { name: likely-exploited, action: fail, when: { epss: 0.1, severity: medium } }
  - { name: severe, action: warn, when: { severity: high } }
```

```yaml
rules:
  # A release gate: nothing past its deadline, nothing in KEV, nothing scoring 70 or more.
  - { name: past-deadline, action: fail, when: { sla_breached: true } }
  - { name: exploited, action: fail, when: { kev: true } }
  - { name: urgent, action: fail, when: { priority: 70 } }
exempt: [not_affected]      # accepted risks do not pass this gate
```

Keep the policy where the people it constrains cannot loosen it: in the configuration of the
monitoring instance, or in a policy file owned by the security team (CODEOWNERS), not in a
file the gated repository can edit in the same change.

## Exemptions are decisions

There is no ignore list. A finding the team will not fix now is exempt only through a
decision in force, recorded with an author, a justification and an expiry
([triage-and-decisions.md](triage-and-decisions.md)):

- `findings accept-risk` (if `risk_accepted` is in `exempt`), within the SLA policy;
- `findings not-affected`, or a VEX statement (`shieldmon vex import`), for findings that do
  not apply. A VEX statement scoped to a repository covers every image of it, including
  images built in CI that the monitoring instance has never seen.

An expired decision exempts nothing, even before `shieldmon monitor` reopens the finding.
Exempt findings are listed with their decision in every output (suppressed results in SARIF).

## In a pipeline

A CI job has its own data directory, so it sees only the decisions it is given: import the
team's VEX documents first. The job needs the shieldmon binary and the scanners (the
container image, or `make build` and `scripts/install-scanners.sh`), and registry credentials
for the image, which never reach the scanners.

GitLab CI, with `indeterminate` shown as a warning:

```yaml
image-gate:
  stage: test
  script:
    - shieldmon init --sandbox auto
    - shieldmon vex import security/vex/app.openvex.json
    - shieldmon gate --policy "$SHIELDMON_POLICY" -o sarif --out gate.sarif "$CI_REGISTRY_IMAGE@$IMAGE_DIGEST"
  allow_failure:
    exit_codes: [3]
  artifacts:
    when: always
    paths: [gate.sarif]
```

GitHub Actions, uploading the result to code scanning (pin actions by full commit SHA, as
this repository does):

```yaml
- run: shieldmon gate -o sarif --out gate.sarif "ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}"
- uses: github/codeql-action/upload-sarif@<full commit SHA>
  if: always()
  with:
    sarif_file: gate.sarif
```

Gate the digest the pipeline built (`name@sha256:…`), not a tag that can move between the
gate and the deployment.

## Output

- Table (default): verdict, policy, evidence (scan, matchers and DB dates), why a pass is
  unproven, flagged findings (fail first, then by priority), exemptions, and the exit status.
- `-o json`: the same, for scripts.
- `-o sarif`: SARIF 2.1.0 with the rules and fingerprints of the monthly SARIF report:
  flagged findings as results (`error` for fail, `warning` for warn), exempt findings as
  suppressed results with their decision; findings no rule flags are not results.
- `--out FILE` writes the chosen format to a file (mode 0600) and prints the table to stdout.

The gate changes no finding state. In the default mode the image becomes a target, as with
`shieldmon scan`: on a monitoring instance, retire images that were only gated
(`shieldmon targets retire`), or gate with an ephemeral data directory.
