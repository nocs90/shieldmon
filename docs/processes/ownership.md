# Ownership: which team owns which images

Normative rules: [ADR 0024](../adr/0024-ownership.md). This page is the runbook.

Owners are declared in the configuration, reviewed like the rest of the policy:

```yaml
owners:
  - team: checkout                       # lowercase letters, digits, '.', '_', '-'
    contact: checkout-security@example.com
    targets: ["registry.example.com/payments/checkout"]
  - team: payments
    contact: payments-security@example.com
    targets: ["registry.example.com/payments/*"]
  - team: platform
    targets: ["registry.example.com/base/*", "nginx", "alpine:3.20"]
```

- A target belongs to the **first** team with a matching pattern: put specific patterns first.
- Patterns are matched against the target's reference as `targets list` shows it
  (`registry.example.com/payments/api:1.4`) and against its repository
  (`registry.example.com/payments/api`). `*` matches within one path segment:
  `registry.example.com/payments/*` does not match `registry.example.com/payments/team/api`
  (add `registry.example.com/payments/*/*`).
- A pattern without wildcards is a reference: a repository owns all its tags (`nginx` is
  `index.docker.io/library/nginx`), a reference with a tag only that tag.
- Targets no pattern matches are **unowned**, shown as `-`: check the list after
  `targets add-repo`.

## Where owners show

| Where | What |
|---|---|
| `shieldmon targets list` | OWNER column |
| `shieldmon findings list --owner payments` | a team's findings (`--owner -` for unowned ones), with `--sort priority` and `--limit` |
| Monthly report | "Open findings by owner" (open, critical, high, past deadline, KEV per team, unowned last); `owners` per row and `owner` per target in JSON |
| Remediation plan | `owner` column: the team and its contact, the point of contact of each item |

Reports use the owners configured when they are generated.

## Team channels

A notification channel with `owners` receives only the finding and base events of those teams'
targets, and no health events (those are about the monitoring itself):

```yaml
notifications:
  channels:
    - name: payments-team
      notifier: slack
      owners: [payments, checkout]
      events: [finding_new_kev, finding_new_critical, sla_breached, sla_due_soon]
      options: { webhook_url_env: SHIELDMON_SLACK_PAYMENTS }
    - name: secops            # no owners: everything, as before
      notifier: webhook
      options: { url: https://hooks.example.com/shieldmon, secret_env: SHIELDMON_WEBHOOK_SECRET }
```

A finding on a digest used by targets of several teams reaches each of their channels.
