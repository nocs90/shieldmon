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

## Failures

A channel that fails opens a `notify_failed` health finding (subject: the channel), the cycle
ends `degraded`, and its unsent events wait for the next cycle. The next successful send
resolves the health finding. Errors name the endpoint's host and HTTP status, never URLs,
tokens or the endpoint's answer.

## Checking a channel

```sh
shieldmon notify test secops       # send a test message now
shieldmon notify preview           # what the next cycle would send, per channel (sends nothing)
shieldmon notify preview -o json --channel secops
```
