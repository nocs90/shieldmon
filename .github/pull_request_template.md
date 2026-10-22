## What and why

<!-- Link the issue: Closes #123. One logical change per PR. -->

## How it was verified

<!-- Commands run, scenario covered, before/after numbers. -->

## Definition of done

- [ ] PR title follows Conventional Commits; commits are signed off (`git commit -s`)
- [ ] `make lint test-unit` passes locally (`make test-integration` if scanner/oci/engine changed)
- [ ] Tests added/updated; lifecycle changes covered in `internal/lifecycle` **and** `TestContinuousMonitoringLifecycle`
- [ ] No credentials can reach logs, errors, DB, reports or scanner env (`internal/redact`, env allowlist)
- [ ] Hostile input bounded (sizes, time, output) and escaped on output
- [ ] Docs updated (SPEC status, ARCHITECTURE, `docs/processes`, `docs/extending`); ADR for design changes
- [ ] New dependencies / actions / binaries are pinned and license-compatible (AGPL-3.0)

## Security impact

<!-- None / describe. Touches closure logic, credentials, or parsing of hostile input? -->
