# 0031 — Server mode, first step: scheduler, API and role-checked API tokens

- Status: accepted
- Date: 2026-11-01

## Context

- Multi-user operation needs decisions made by authenticated identities, not by whatever
  `--author` a shell user types (#33, M6): a risk acceptance is an accountable statement.
- Cron, systemd timers and CronJobs run `shieldmon monitor` today (docs/processes/deployment.md);
  a long-running process can schedule cycles itself and answer queries between them.
- OIDC login is the target for people. Verifying ID tokens well (discovery, JWKS rotation,
  audience and issuer checks, clock skew) is a library's job (`coreos/go-oidc`), a new
  dependency that is a reviewed change of its own. Machines (CI jobs, dashboards) need
  non-interactive credentials in any case.
- SQLite is the store (ADR 0005); a single process serving reads while it runs cycles works
  through its single connection; PostgreSQL (#32) is for several replicas.

## Decision

- `shieldmon serve` serves a JSON API (`internal/server`) and, with `server.schedule`
  (default), runs a monitoring cycle at start and every `health.monitor_interval`, under the
  same data dir lock as `shieldmon monitor`: a cycle that finds the lock held is skipped and
  reported in `/api/v1/status`, never run twice at once.
- Endpoints (all but `/healthz` need a token):

  | Endpoint | Role |
  |---|---|
  | `GET /api/v1/findings` (`state`, `severity`, `digest`, `vuln`, `sort=priority`, `limit`), `GET /api/v1/findings/{id}` (with events and decisions) | viewer |
  | `GET /api/v1/targets`, `GET /api/v1/health`, `GET /api/v1/status`, `GET /api/v1/reports/monthly?month=&format=` | viewer |
  | `POST /api/v1/findings/{id}/transition` (`triaged`, `in_remediation`, `open`) | triager |
  | `POST /api/v1/findings/{id}/decision` (`risk_accepted`, `not_affected`, under the decision policy) | triager |
  | `POST /api/v1/cycles` | admin |

  Roles include the ones below them. No endpoint closes a finding: closure needs scan
  evidence (`lifecycle.Reconcile`).
- The author of a transition or decision is the authenticated identity, recorded as
  `api:<name>`; a request cannot name one (unknown fields are refused), and every other way to
  name an author (the command line's `--author` and `--by`, the authors of VEX statements and
  their importer) refuses names that could read as one (`lifecycle.ReservedAuthor`: "api"
  then anything but a letter, digit, `-` or `_`, whatever the case or surrounding space, so
  look-alike colons too), so the audit trail tells a token holder from any other name.
  `engine`, the actor of automatic transitions, is no token name and no decision author.
- Refusals by the lifecycle rules or the decision policy (`lifecycle.ErrRefused`) are answered
  with their reason (409/422); any other failure is a logged 500 without details.
- Authentication is an interface. The first implementation is API tokens: `shieldmon serve
  token NAME --role ROLE` prints a random 256-bit secret (`smt_…`, redacted everywhere) once,
  and the configuration keeps only its SHA-256 with the name and role. The server compares a
  bearer token's hash with every configured one in constant time; a hash configured twice
  matches none.
- Bearer tokens never travel in clear text beyond the host: a non-loopback `server.listen`
  needs `server.tls_cert` and `server.tls_key` (TLS 1.2+), or a TLS proxy on 127.0.0.1.
- Hardening: header, read, write and idle timeouts; 32 KiB headers, 64 KiB bodies; at most
  1,000 findings per page and 20,000 ranked per priority request; two expensive requests
  (priority ranking, reports) at a time; report months from 2000 to the current one. JSON only,
  `nosniff`, `no-store`, a `default-src 'none'` CSP (the HTML report gets inline styles, no
  form, base or script, sandboxed), HSTS over TLS, spreadsheets as attachments. Report media
  types come from the format registry (`report.Format.MediaType`), not from the server.
  Failed authentications are logged with the address and path, never the header. The address
  checked is the one bound, not the name configured. A TLS key pair is loaded before the
  scheduler starts.

## Consequences

- Decisions through the API are attributable to a token holder (`api:<name>`); the audit chain
  (ADR 0018) records them like any other. Whoever has a shell on the host or the database can
  still record a decision under any other name: the CLI's `--author` stays a declaration, and
  host access stays a trust boundary.
- Tokens are long-lived until removed from the configuration (a restart applies it): rotate
  them like any secret. OIDC for people, with groups mapped to roles, is the next step and
  plugs into the same interface once its dependency is reviewed.
- One server per data dir; more replicas wait for PostgreSQL (#32).
- No web UI: reports are served as they render (HTML, Markdown, JSON, CSV, SARIF).
