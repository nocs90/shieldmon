# 0002 — Go, single static binary, no Docker daemon

- Status: accepted
- Date: 2026-10-20

## Context

The target environments are CI runners, Kubernetes CronJobs and hardened hosts. The
ecosystem (go-containerregistry, syft, grype, trivy, cosign, helm) is Go. Requiring a
Docker daemon would mean a root-equivalent socket next to registry credentials.

## Decision

- Go, `CGO_ENABLED=0`, one binary (`shieldmon`).
- Registry access through `github.com/google/go-containerregistry` (no daemon, no CLI).
- SQLite through `modernc.org/sqlite` (pure Go) to stay cgo-free.
- CLI with cobra; configuration in YAML with unknown-field rejection.

## Consequences

- Trivially containerized (distroless), cross-compiled, reproducible.
- modernc SQLite is slower than the C library; acceptable for single-node workloads,
  PostgreSQL covers server mode (ADR 0005).
