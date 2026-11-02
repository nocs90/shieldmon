# 0034 — Chart tracking: every release recorded, neglected charts from scan evidence

- Status: accepted
- Date: 2026-11-01

## Context

- F11 (#6) ends with tracking: which images each version of a followed chart runs, and
  whether a chart is neglected — it keeps shipping images with vulnerabilities that already
  have fixes, or it stopped releasing. ADR 0032 finds versions and archives, ADR 0033 renders
  them per profile.
- Findings belong to images, which are targets; charts do not change the finding lifecycle.
  Closure needs scan evidence (I-rules), so a new chart release fixes nothing by itself: its
  new images are scanned, and the old targets keep their findings until they are retired or
  rebuilt.
- #37 asks for upstream contributions for neglected charts: drafts that follow the project's
  rules, deduplicated, submitted only with human approval.

## Decision

- **Every render is recorded**, append-only and sealed in the audit chain
  (`chart_renders`, migration 9): chart, version, app version, release time as the source
  says it, archive digest, profile, a hash of the profile (release, namespace, values,
  capabilities), the images (valid references, in the form targets use, hooks marked;
  invalid ones and custom resources counted) and when. The latest row per chart and profile
  is what the chart runs now; the history is what it ran.
- **Monitor follows charts first** in every cycle, so that a new release's images are scanned
  in the cycle that finds it: for each followed chart, its newest release (newest SemVer,
  not a pre-release, not deprecated) is rendered with every profile the first time, and again
  only when its archive digest (as the index states it) or the profile changes. A failure —
  source, archive check, values, missing helm, a profile that does not render — opens
  `chart_failed` for that chart and degrades the cycle; the targets are still monitored, and
  the next success resolves it. `shieldmon charts track` does the same on demand.
- `add_targets: true` on a chart makes the images of its newest release targets (for the
  configured platform). The chart's publisher chooses those images, so ShieldMon then
  contacts registries it names, with the operator's credentials: an image is added only when
  its registry looks public (not a loopback, private, link-local or CGNAT literal, not
  `localhost`, not a single-label name, not `.local`, `.internal`, `.svc`, `.cluster.local`,
  `.lan`, `.home.arpa`, `.corp`, `.intranet`) or matches a host the operator configured in
  `registries:`; the others are recorded but not added, and named in `chart_failed`. A release
  adding more than `max_new_targets` (50) new targets adds none: a person reviews them with
  `targets add --chart NAME --dry-run`. Images a later release drops stay targets: retiring
  them is an operator's decision with its own record (ADR 0017); `charts history` shows what
  changed.
- Remote content cannot hold or flood the record: each chart has, per cycle, every profile's
  `helm.timeout` plus 5 minutes (at least 10 minutes) for listing, download and renders; a
  version listed twice by an index keeps its first entry everywhere (so it does not look
  changed on every read); at most 3 renders per profile are recorded for a chart in 24 hours
  (a source releasing or republishing more often opens `chart_failed` and waits for a
  person); a render records at most 10,000 images of at most 512 bytes each; a release time
  more than a day in the future is recorded as unknown. Only the latest render per profile is
  read each cycle. Registry names are judged without a trailing dot, and a name must end in a
  top-level domain of letters (no numeric shorthand such as `127.1`).
- Residual: a source that releases a version a day with new images can add up to
  `max_new_targets` targets a day through `add_targets`; they stay until retired.
- **Neglected** is a verdict on the newest recorded release, from evidence only
  (`charts.Assess`, pure): an active finding with a fix (a fixed version or a `fixed` state),
  of at least `chart_policy.min_severity` (high), detected more than
  `chart_policy.fixable_after` ago (30 days), in an image of the release; or no release for
  `chart_policy.stale_after` (180 days) when the source dates releases. Images that are not
  scanned targets are reported as unmonitored: a chart with some is "unknown", not clean. `shieldmon charts status`
  (table, JSON, Markdown) shows it.
- **Upstream drafts are drafts**: `shieldmon charts draft-issue NAME` prints a Markdown issue
  for the chart's maintainers with the overdue findings (at most 50), every value from
  scanners or sources in a code span (no markup, links or mentions), with control,
  bidirectional and invisible characters written out as `\uXXXX`. ShieldMon never
  submits anything: the person who submits it follows the project's contribution guidelines,
  searches for an existing issue and decides. Submission through an API (deduplication, rate
  limits, approval records) is left to #37.

## Consequences

- Charts never open, close or change findings; chart tracking adds targets at most.
- A chart rendered differently by a cluster (values not described by a profile, operators
  creating workloads) is only as complete as its profiles; custom resources are counted.
- The record grows by one row per version and profile rendered: a few rows a month per chart.
