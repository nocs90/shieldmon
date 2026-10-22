# 0008 — Extension model: compiled-in plugins with registries and conformance kits

- Status: accepted
- Date: 2026-10-20

## Context

ShieldMon must grow many integrations (scanners, registries, enrichers, notifiers,
exporters, chart sources, remediation advisors) contributed by people who do not know the
lifecycle internals. Each integration touches hostile input or credentials. Options:

1. Hard-wired adapters selected by `switch` (M1 initial state): every addition edits core code.
2. Compiled-in plugins with registries (`database/sql` style).
3. Out-of-process plugins (exec + JSON, or hashicorp/go-plugin).

## Decision

- Phase 1 (now): option 2. Each extension point is an interface plus a registry; adapters
  self-register in `init`; configuration selects them by name with declared, validated
  options; `shieldmon plugins` lists them. Scanners and report formats are done; the other
  extension points follow the same shape when built.
- Every extension point ships a conformance kit (`<pkg>test`), used by built-ins and
  required for contributions.
- Phase 2 (later, own ADR): out-of-process plugins only once sandboxed execution (S1)
  exists, pinned by checksum and held to the same conformance kit.

## Consequences

- Adding an adapter touches no core code; review focuses on the adapter and the kit.
- The core stays small and audit-friendly; one binary to sign and pin.
- Third parties cannot ship plugins without a rebuild until phase 2 — acceptable for a
  security tool where the trust boundary matters more than dynamic loading.
