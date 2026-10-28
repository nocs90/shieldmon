# 0018 — Tamper-evident audit: a hash chain anchored by exported digests

- Status: accepted
- Date: 2026-10-28

## Context

- The audit tables (finding events, decisions, scan matches, digest history, VEX, target
  and notification records) are append-only through SQLite triggers (I5). Triggers stop
  mistakes, not someone with write access to the database file: drop the trigger, edit a
  decision, recreate the trigger (THREAT_MODEL: Tampering) (#31).
- Tamper-evident databases share one design: SQL Server ledger hashes every row with
  SHA-256, chains the hashes in blocks, and calls the latest block hash the *database
  digest*; digests are stored **outside** the database (immutable storage), and verification
  recomputes everything and compares it with them. A chain verified only against itself
  proves nothing: whoever rewrites rows can rewrite the chain. Microsoft also warns that
  ledgers are often deployed and never verified.
- Transparency logs (RFC 9162, Trillian, Rekor) add Merkle trees for efficient proofs to
  third parties. ShieldMon has one writer and one verifier, the operator; a linear chain
  verified in one pass is enough, and simpler to audit.

## Decision

1. **Chain.** `audit_chain` (append-only, migration 0006): one entry per audited row, in
   order: table, row key, column-set version, SHA-256 of the row's canonical encoding, and
   `hash = SHA-256(previous hash, sequence, table, key, version, row hash)`. The chain starts
   at the upgrade: rows written before it are sealed as they are then.
2. **Audited tables**: `finding_events`, `decisions`, `scan_matches`, `target_digests`,
   `sboms`, `scans` (once finished), `vex_statements`, `vex_applications`, `target_events`,
   `notification_events`, `notification_channels`, `notifications`. Mutable state
   (`findings`, `targets`, `health_findings`) is derived from them or is not evidence.
3. **Canonical row encoding**: the table's audited columns, fixed in code per column-set
   version (a later migration that adds a column adds a version, so old rows still verify),
   as JSON with sorted keys and typed values.
4. **Sealing** happens in the same transaction as every store write, so a committed audit
   row is chained atomically; rows written outside a transaction are sealed by the next one.
   Rows are found by a per-table high-water mark (row ID); tables keyed otherwise record their
   natural key, so that verification does not depend on row IDs.
5. **Digests are the anchor.** `shieldmon audit digest` prints the chain head (sequence,
   hash, time) to store outside the data directory (object lock, WORM, a ticket, a signed
   report); every monthly report carries it too. `shieldmon audit verify [--digest FILE…]`
   recomputes every row and link and checks the given digests are still in the chain: a
   rewrite after a digest left the machine is detected.
6. **Verification is scheduled**, not optional: `monitor` verifies the chain every
   `health.audit_verify_interval` (default 24h) and opens an `audit_chain_broken` health
   finding on failure.
7. **Signing** of exported reports and digests is done with the organization's tools
   (minisign, cosign: documented in docs/processes/audit.md). ShieldMon holds no signing
   key and adds no cryptographic dependency for it; native signing, if ever needed, uses a
   maintained library with interoperability tests against the real tools in CI, never a
   hand-written format.

## Consequences

- Editing, deleting or inserting an audited row out of band, or rewriting the chain after a
  digest was exported, fails verification and opens a health finding.
- Someone who controls the machine continuously can still rewrite rows and chain before any
  digest leaves it: the guarantee starts at the first exported digest, as with any ledger.
- Each write transaction also hashes its new audit rows: a small, bounded cost.
- `VACUUM` on the database may renumber the rows of tables without an integer key; sealing
  detects the mismatch and falls back to natural keys, and verification never relies on row
  IDs for those tables.
