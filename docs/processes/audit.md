# Tamper-evident audit trail

Everything a finding's history rests on (state changes, decisions, what each scan saw, the
digest history, VEX, retirements, notifications) is append-only. Since schema v6 it is also
**hash-chained**: changing, deleting or inserting a row behind ShieldMon's back — even with
the triggers dropped — is detected ([ADR 0018](../adr/0018-audit-chain.md)).

## How it works

- Every write transaction chains the audit rows it adds: each entry holds the SHA-256 of the
  row and a hash linking it to the previous entry.
- `monitor` verifies the whole chain every `health.audit_verify_interval` (default 24h); a
  failure opens the `audit_chain_broken` health finding (critical).
- A chain verified only against itself cannot detect a complete rewrite. **Digests** — the
  head of the chain at a point in time — are the anchor: once a digest has left the
  machine, any rewrite before it is detected.

## Routine

```sh
# Daily (or after each monitor run): export a digest where this machine cannot change it.
shieldmon audit digest -o "/mnt/worm/shieldmon/$(date +%F).json"

# Monthly, or when asked: verify the trail and that past digests are still in it.
shieldmon audit verify --digest /mnt/worm/shieldmon/2026-10-01.json --digest /mnt/worm/shieldmon/2026-10-28.json
```

Good places for digests: object storage with a retention lock (S3 Object Lock in
compliance mode, GCS bucket lock), a WORM share, a ticket or chat message, or the monthly
report itself — every report carries the chain head it was generated from ("Audit trail
anchor"), so distributing reports distributes anchors.

## When verification fails

| Problem | Meaning |
|---|---|
| `row_changed` | an audited row differs from what was sealed |
| `row_missing` | a sealed row was deleted |
| `row_inserted` | rows were inserted below the sealed mark without being sealed |
| `broken_link` | a chain entry was edited, deleted or reordered |
| `digest_differs` | the chain was rewritten after that digest was exported |
| `digest_ahead` | the chain is shorter than when that digest was exported: truncated |

Treat it as a security incident: keep the database file as evidence, compare it with
backups, and restore from the last backup whose chain verifies against your digests.
Verification lists the first 100 problems with their table and row key
(`shieldmon audit verify -o json`).

Do not run `VACUUM` on the database: it may renumber rows of tables without an integer key.
Verification does not depend on those numbers, but rows written afterwards could be
reported as inserted out of band.
