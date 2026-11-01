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
| `base_unmaintained` | a monitored image's base tag has not moved for longer than `bases.max_age` ([base-images.md](base-images.md)); opt-in | image digest and base digest |
| `base_rebuild_available` | a monitored image is built on an older digest of its base tag: a rebuild picks up the newer base; opt-in | image digest and base digest |
| `finding_fixed` | a finding closed as fixed by scan evidence since the previous cycle began (not in the first cycle); opt-in, except for issue trackers | finding |

A *problem* is followed across digests: when a new digest of a target still has the
vulnerability, its deadline events are not sent again. Risk-accepted and not-affected
findings get no deadline events, nor do findings whose images are all retired.

## Channels

```yaml
notifications:
  due_soon_days: 7
  channels:
    - name: secops                 # lowercase letters, digits, - and _
      notifier: <name>             # 'shieldmon plugins' lists the notifiers
      events: [finding_new_kev, finding_new_critical, sla_breached, health_opened]  # default: all but the opt-in ones
      digest: false                # true: one summary per cycle
      # owners: [payments]         # only these teams' images, no health events (ownership.md)
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

### `github-issues`, `gitlab-issues`

One issue per **target and vulnerability**, kept in step with the findings:

```yaml
- name: app-issues
  notifier: github-issues               # or gitlab-issues
  options:
    repo: acme/app                      # gitlab-issues: project: acme/platform/app (or its ID)
    api_url: https://api.github.com     # GitHub Enterprise: https://ghe.example.com/api/v3;
                                        # gitlab-issues: https://gitlab.com or self-managed
    token_env: SHIELDMON_GITHUB_TOKEN   # GitHub: fine-grained token, Issues read/write on the
                                        # repository; GitLab: project access token, api scope,
                                        # Reporter role
    labels: [security]                  # added to "shieldmon"
```

| Event | Effect |
|---|---|
| `finding_new_kev`, `finding_new_critical` | open an issue for each of the finding's targets, or comment on the existing one; reopen it if closed (the problem is back) |
| `sla_due_soon`, `sla_breached` | the same: open, or comment with the deadline |
| `finding_fixed` | comment; close the issue when no package of the target has the vulnerability any more |

- Issues are only ever opened by a channel configured this way; trackers default to the
  events above (`health_opened` and `digest` do not apply).
- An issue is closed only when ShieldMon closes the finding by **scan evidence**. Risk
  acceptances and VEX statements do not close it (record them with `shieldmon findings` /
  `shieldmon vex`); closing the issue by hand does not change the finding, and a later event
  about the problem reopens it.
- ShieldMon reads and changes only issues labelled `shieldmon` whose description starts with
  its group marker (`<!-- shieldmon:group=… -->`); it lists them once per cycle and refuses to
  act beyond 2,000 of them rather than risk duplicates. Anyone who can label issues can make
  one look managed: keep labelling to maintainers.
- Package names and titles go in code blocks: no mention, reference or markup from scanner
  output applies.

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
