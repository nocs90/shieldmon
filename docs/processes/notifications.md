# Notifications

ShieldMon tells people what needs them after each `shieldmon monitor` cycle
([ADR 0015](../adr/0015-notifications.md)). Without channels, nothing is sent.

## Events

| Event | When | Sent once per |
|---|---|---|
| `finding_new_kev` | a finding created since the previous cycle began, not carried over from a previous digest, in CISA KEV | finding |
| `finding_new_critical` | the same, critical and not in KEV | finding |
| `sla_breached` | an active finding (open, triaged, in remediation, reopened) past its remediation deadline | problem and deadline |
| `sla_due_soon` | an active finding within `notifications.due_soon_days` (default 7) of its deadline | problem and deadline |
| `health_opened` | an open health finding | health finding and opening |

A *problem* is followed across digests: when a new digest of a target still has the
vulnerability, its deadline events are not sent again. Risk-accepted and not-affected
findings get no deadline events.

## Channels

```yaml
notifications:
  due_soon_days: 7
  channels:
    - name: secops                 # lowercase letters, digits, - and _
      notifier: <name>             # 'shieldmon plugins' lists the notifiers
      events: [finding_new_kev, finding_new_critical, sla_breached, health_opened]  # default: all
      digest: false                # true: one summary per cycle
      options: { … }               # per notifier; credentials only through *_env options
```

- Each event reaches a channel **once**: what was sent is recorded (append-only) after the
  notifier confirms delivery.
- A channel receives events recorded from the cycle it first appears in: adding a channel
  does not replay history. Renaming a channel makes it a new channel.
- Without `digest`, each event is its own message; with it, one message per cycle (up to 100
  events per message). At most 50 messages per channel per cycle; the rest wait for the next.
- Before sending, pending events are checked against the current state: a problem fixed or
  a health finding resolved meanwhile is not announced.

## Built-in notifiers

### `webhook`

JSON over HTTPS (http only to localhost), signed per [Standard
Webhooks](https://www.standardwebhooks.com):

```yaml
- name: siem
  notifier: webhook
  options: { url: https://hooks.example.com/shieldmon, secret_env: SHIELDMON_WEBHOOK_SECRET }
```

- `secret_env` is required: a `whsec_` + base64 secret (as Standard Webhooks libraries
  generate) or any other value of at least 24 bytes.
- Headers: `webhook-id` (the same for a retry of the same events: drop duplicates by it),
  `webhook-timestamp` (Unix seconds: refuse old ones), `webhook-signature`
  (`v1,` + base64 HMAC-SHA256 of `id.timestamp.body`). Verify with any Standard Webhooks
  library, or:

  ```python
  expected = base64.b64encode(hmac.new(key, f"{id}.{timestamp}.".encode() + body, sha256).digest())
  ```

- Body: `{"version": 1, "subject": …, "channel": …, "digest": …, "events": [{"key", "kind",
  "finding": {…}} | {"key", "kind", "health": {…}}], "sent_at": …}`. Text fields come from
  scanner output: escape them where you render them.
- Redirects are not followed; any non-2xx answer is a failure.

### `smtp`

Plain-text e-mail through a relay, always over TLS:

```yaml
- name: secops-mail
  notifier: smtp
  digest: true
  options:
    host: smtp.example.com
    port: 587                # default 587 (starttls), 465 (implicit)
    tls: starttls            # starttls | implicit; there is no plaintext mode
    from: "ShieldMon <shieldmon@example.com>"
    to: [secops@example.com]
    username: shieldmon
    password_env: SHIELDMON_SMTP_PASSWORD
```

A server that does not offer STARTTLS is refused (no fallback), the certificate is verified
against the system roots, and credentials are sent only after TLS. The subject is
RFC 2047-encoded and every line is stripped of control characters, so scanner output cannot
add headers. Mails carry `Auto-Submitted: auto-generated` (no auto-replies) and
`X-ShieldMon-Delivery` (stable across retries).

### `slack`, `mattermost`

Incoming webhooks. Their URL is the credential, so it comes from an environment variable:

```yaml
- name: secops-slack
  notifier: slack                  # or mattermost
  digest: true
  events: [finding_new_kev, finding_new_critical, sla_breached, health_opened]
  options: { webhook_url_env: SHIELDMON_SLACK_WEBHOOK_URL }
```

Create the webhook for one channel (Slack: an app with *Incoming Webhooks*; Mattermost:
*Integrations → Incoming Webhooks*, locked to its channel). The heading is ShieldMon's own
text; package names, titles and targets go in a code block, where no formatting, link or
mention applies (Slack's `<`, `>`, `&` are escaped too), so scanner output cannot ping
`@channel`. A digest lists one line per event and says how many it leaves out beyond about
12,000 characters.

### `matrix`

`m.notice` events in one room, through the client-server API:

```yaml
- name: secops-matrix
  notifier: matrix
  options:
    homeserver: https://matrix.example.org
    room: "!AbCdEfGhIjKlMnOp:example.org"   # the room ID (room settings → Advanced), not an alias
    token_env: SHIELDMON_MATRIX_TOKEN       # access token of a bot account in the room
```

Messages carry an empty `m.mentions` (they mention nobody, whatever the text), an HTML body
with everything escaped, and the delivery ID as transaction ID: a retry of the same events
is deduplicated by the homeserver. Encrypted rooms are not supported; use a room without
end-to-end encryption, restricted to the people who should see findings.

## Failures

A channel that fails opens a `notify_failed` health finding (subject: the channel), the cycle
ends `degraded`, and its unsent events wait for the next cycle. The next successful send
resolves the health finding. Errors name the endpoint's host and HTTP status (or SMTP step and
reply code), never URLs, tokens or the endpoint's answer.

## Checking a channel

```sh
shieldmon notify test secops       # send a test message now
shieldmon notify preview           # what the next cycle would send, per channel (sends nothing)
shieldmon notify preview -o json --channel secops
```
