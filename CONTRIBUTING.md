# Contributing

Thanks for helping. ShieldMon is AGPL-3.0 free software.

Process docs: [contribution workflow](docs/processes/contribution-workflow.md) ·
[quality gates](docs/processes/quality-gates.md) ·
[issue management](docs/processes/issue-management.md) ·
[extending ShieldMon](docs/extending/README.md) · [governance](GOVERNANCE.md) ·
[code of conduct](CODE_OF_CONDUCT.md).

## Ground rules

- Read [SPEC.md](SPEC.md) (invariants I1–I7) and [THREAT_MODEL.md](THREAT_MODEL.md)
  before changing the pipeline, lifecycle or storage.
- Significant design changes come with an ADR (`docs/adr/NNNN-title.md`, copy
  `0000-template.md`).
- Every behaviour change has a test. Lifecycle rules are tested in
  `internal/lifecycle` (pure) and end to end in `internal/engine`.
- No new network calls, telemetry or dependencies without discussion.
- CI Actions and container images are pinned by full SHA / digest.

## Developer Certificate of Origin

Sign off every commit (`git commit -s`), certifying the
[DCO](https://developercertificate.org/):

```
Signed-off-by: Your Name <you@example.com>
```

## Workflow

```sh
make lint test-unit build   # must pass before you push (lint includes golangci-lint if installed)
make cover                  # coverage floor
make fuzz                   # when touching a parser of hostile input
make test-integration       # when touching scanners, oci or engine
```

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).

## Adding an adapter

Follow [docs/extending](docs/extending/README.md): implement the interface, register it,
pass the conformance kit, add a real-output fixture and a fuzz target, pin the binary.
Open an issue with the *New adapter* form first so the design can be discussed.
