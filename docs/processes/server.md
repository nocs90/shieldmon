# Running `shieldmon serve`: API and scheduler

Normative rules: [ADR 0031](../adr/0031-server-mode.md). This page is the runbook.

`shieldmon serve` replaces the cron/systemd timer of `shieldmon monitor` (it runs a cycle at
start and every `health.monitor_interval`) and serves an API for people and tools that triage
without a shell on the host.

## 1. Tokens

```sh
shieldmon serve token alice --role triager
# secret (shown once, give it to alice): smt_…
# server.tokens entry:
#   - { name: alice, role: triager, sha256: "…" }
```

Add the entry under `server.tokens` and give the secret to its holder over a channel fit for
secrets. Roles: `viewer` reads; `triager` also triages and records decisions, as their author;
`admin` also starts cycles. To revoke, remove the entry and restart.

## 2. Listen

```yaml
server:
  listen: 127.0.0.1:8484     # loopback: a reverse proxy terminates TLS
  # listen: 0.0.0.0:8443     # any other address needs:
  # tls_cert: /etc/shieldmon/tls.crt
  # tls_key: /etc/shieldmon/tls.key
  schedule: true
```

Stop the `shieldmon-monitor` timer or CronJob when the server schedules cycles: both take the
same lock, so a cycle that finds it held is skipped (`last_status: failed`, `last_error`
names the lock) rather than run twice.

## 3. Use

```sh
T=smt_…
curl -s -H "Authorization: Bearer $T" 'https://shieldmon.example.com/api/v1/findings?sort=priority&limit=20'
curl -s -H "Authorization: Bearer $T" 'https://shieldmon.example.com/api/v1/reports/monthly?format=html' > report.html
curl -s -H "Authorization: Bearer $T" -X POST https://shieldmon.example.com/api/v1/findings/42/decision \
  -d '{"state":"risk_accepted","justification":"no network listener; RISK-12"}'
curl -s -H "Authorization: Bearer $T" https://shieldmon.example.com/api/v1/status
```

- Decisions follow the decision policy (deadlines, deviations, maximum days) exactly as
  `findings accept-risk` and `findings not-affected` do; the author is `api:<token name>`
  (`api:alice`), a prefix the command line refuses, so `findings show` tells API decisions
  from typed ones.
- `sort=priority` ranks the 20,000 most severe matches (`truncated: true` when there are more);
  ranking and reports run two at a time.
- Transitions are limited to `triaged`, `in_remediation` and `open`: a finding closes only on
  scan evidence.
- `/healthz` needs no token, for liveness probes.

## Operations

- Logs (`--log-format json`) record each cycle and every failed authentication (address and
  path, never the token).
- A secret leaked: remove its entry, restart, and review the decisions it authored
  (`findings show`, the audit trail).
- Back up the data dir as for `monitor` (docs/processes/deployment.md).
