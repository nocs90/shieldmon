# 0015 — Notifications: events after each cycle, sent once per channel

- Status: accepted
- Date: 2026-10-27

## Context

- Nothing reaches humans unless they run the CLI: new critical or KEV findings, SLA deadlines
  and broken monitoring (health findings) wait to be noticed (F9).
- A notification that repeats every cycle is noise and gets muted; one that is lost because
  a channel was down is a monitoring gap (I6).
- Messages carry package names and titles from scanner output, which is hostile (I7), into
  JSON, e-mail headers, Markdown and HTML.
- Channel credentials (webhook secrets, SMTP passwords, chat tokens) must never sit in
  config, logs or errors (S2).

## Decision

1. **Extension point.** `notify.Notifier` (one method, `Send(ctx, Message)`), registered with
   `notify.RegisterNotifier` (name, description, option keys), selected by configuration,
   listed by `shieldmon plugins`, proven by `notifytest.CheckNotifier` (ADR 0008).
2. **Events, after each `monitor` cycle**, computed from the store:
   - `finding_new_critical`, `finding_new_kev`: findings first detected in the cycle (not a
     carried-over problem), critical or in CISA KEV; KEV wins when both;
   - `sla_due_soon` (within `notifications.due_soon_days`, default 7) and `sla_breached`:
     active findings by their remediation deadline (ADR 0010);
   - `health_opened`: open health findings;
   - `finding_fixed`: findings closed as fixed by scan evidence since the previous cycle
     began. Opt-in: a channel that lists no events gets the alerts above; a notifier may
     declare the kinds it handles and its defaults (issue trackers: the finding events, fixes
     included) and refuse digest mode.
3. **Sent once.** Each event has a key: the finding for new findings; the problem's lineage
   (package, vulnerability, first detection) for SLA events, so that a successor digest does
   not repeat them; the check, subject and opening time for health. `notifications`
   (append-only) records what each channel was sent; an event already recorded for a
   channel is not sent there again. Recording happens only after a successful send.
4. **Digest mode.** A channel with `digest: true` gets one message per cycle with all its
   events; otherwise one message per event.
5. **Failures are health findings.** A channel that fails opens `notify_failed` (subject:
   the channel), resolved by its next successful send. Its unsent events stay pending and
   are retried next cycle.
6. **Hostile text.** Messages carry structured events; each adapter escapes for its medium
   (JSON encoding, e-mail headers without CR/LF and RFC 2047-encoded, Markdown and HTML
   escaping), and terminal output escapes control characters.
7. **Secrets and transport.** Options name environment variables for credentials (`*_env`);
   option values that look like credentials are refused, as for registry providers. HTTP
   notifiers use HTTPS (HTTP only to localhost), follow no redirects (a redirect would carry
   the signature or token elsewhere), time out, and discard response bodies beyond a bound.
   Built in: `webhook` (HMAC-SHA256 over timestamp and body) and `smtp` (STARTTLS required,
   no plaintext fallback); adapters: Slack, Mattermost, Matrix, GitLab and GitHub issues.
8. **Issue trackers** keep one issue per target and vulnerability, found again by a marker
   at the start of its description (no local state): opened or commented on news, reopened
   when a problem comes back, closed only on `finding_fixed` with nothing of the
   vulnerability left on the target. ShieldMon's lifecycle stays the source of truth: issue
   state never flows back.

## Consequences

- A channel added later receives only events from then on (pending ones of the cycle).
- A channel that was down catches up on its next successful cycle; a digest then holds the
  backlog.
- Notifications follow `monitor`; `scan` and `rematch` do not notify.
