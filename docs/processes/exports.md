# Exports: Dependency-Track and DefectDojo

Normative rules: [ADR 0027](../adr/0027-exporters.md). This page is the runbook.

ShieldMon stays where findings are closed (by scan evidence) and decisions are recorded;
exports mirror that state into the portfolio tools teams already use.

```yaml
exports:
  - name: dtrack
    exporter: dependency-track
    options: { url: https://dtrack.example.com, api_key_env: SHIELDMON_DTRACK_KEY }
  - name: dojo
    exporter: defectdojo
    options: { url: https://defectdojo.example.com, api_key_env: SHIELDMON_DOJO_KEY,
               product_type: Container images, engagement: ShieldMon }
```

```sh
shieldmon export                       # every export, every monitored target
shieldmon export dojo                  # one export
shieldmon export --dry-run ./payloads  # write what would be sent (files 0600), send nothing
```

Run it after each cycle: `ExecStartPost=/usr/local/bin/shieldmon … export` in the systemd
service, or a second container after `monitor` in the CronJob. `shieldmon plugins` lists the
exporters and their options.

## What each tool gets

| Exporter | Per target | Notes |
|---|---|---|
| `dependency-track` | the stored CycloneDX SBOM of the current digest (syft's), `POST /api/v1/bom` with `autoCreate`, project = repository, version = tag (and platform when the reference is monitored on several) | Dependency-Track ≥ 5.1 reads the CycloneDX 1.7 that current syft writes; older servers answer 400 |
| `defectdojo` | the open and risk-accepted findings as a Generic Findings Import, `POST /api/v2/reimport-scan/` with `close_old_findings`: product = repository (in `product_type`), engagement = `engagement`, test = target | findings ShieldMon closed close at the next export; not_affected findings are not sent; risk acceptances arrive with `risk_accepted`; tags `remedy:…` and `owner:…` |

DefectDojo's findings carry the severity, CVE and aliases, package and version, CVSS, EPSS,
KEV, the fixed version and the remediation deadline (`planned_remediation_date`). Their
`unique_id_from_tool` is the problem (vulnerability and package), stable across rebuilds.

## Credentials

API keys come from the environment variables the `*_env` options name, never from the
configuration (a credential-shaped option value is refused). Dependency-Track needs a key with
`BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`; DefectDojo a user's API v2 key allowed to import
into the product type. Requests go over HTTPS (HTTP only to localhost), follow no redirect,
and errors name the host and the status only.

## When an export fails

The command lists each target that failed and exits non-zero; an `export_failed` health
finding (subject: the export's name) stays open until an export succeeds
([health-findings.md](health-findings.md)). Nothing in ShieldMon depends on the exports: the
next run sends the current state again.

Decisions taken in DefectDojo or Dependency-Track do not flow back: record them in ShieldMon
(`findings accept-risk`, `findings not-affected`, VEX), and the next export carries them.
