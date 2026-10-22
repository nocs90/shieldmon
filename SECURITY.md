# Security policy

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on this repository. We aim to acknowledge
within 72 hours and to agree on a disclosure timeline with you.

Particularly interesting classes for this project:

- credential exposure (logs, errors, health findings, reports, scanner environment);
- ways to make ShieldMon close a finding without scan evidence, or to alter its audit trail;
- crafted images, SBOMs or registry responses that escape the size/time bounds;
- injection through image references or report output.

## Supported versions

Pre-1.0: only the latest `main` receives fixes.

## Operating ShieldMon safely

- Run it as a dedicated unprivileged user or container with no other secrets.
- Prefer short-lived registry credentials (credential helpers, OIDC, instance roles).
- Pin scanner binaries (`scanners.*.sha256`; `shieldmon doctor` prints current hashes).
- Keep `health` findings at zero: a stale DB or a missed cycle is a compliance gap.
