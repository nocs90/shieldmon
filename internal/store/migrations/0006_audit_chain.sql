-- v6: tamper-evident audit chain (docs/adr/0018-audit-chain.md).

-- APPEND-ONLY: one entry per audited row. hash = SHA-256 over the previous entry's hash and
-- this entry's fields; the latest entry's (seq, hash) is the digest exported as an anchor.
-- row_id is the row's rowid when sealed (the per-table high-water mark); row_key identifies
-- the row for verification (its integer key, or its natural key as a JSON array).
CREATE TABLE audit_chain (
    seq        INTEGER PRIMARY KEY,
    tbl        TEXT NOT NULL,
    row_key    TEXT NOT NULL,
    row_id     INTEGER NOT NULL,
    cols       INTEGER NOT NULL,
    row_hash   TEXT NOT NULL,
    hash       TEXT NOT NULL,
    sealed_at  TEXT NOT NULL,
    UNIQUE (tbl, row_key)
);
CREATE INDEX audit_chain_tbl_row ON audit_chain (tbl, row_id);

-- APPEND-ONLY: verifications of the chain (by monitor or 'shieldmon audit verify').
CREATE TABLE audit_verifications (
    id        INTEGER PRIMARY KEY,
    at        TEXT NOT NULL,
    head_seq  INTEGER NOT NULL,
    ok        INTEGER NOT NULL,
    problems  INTEGER NOT NULL
);

CREATE TRIGGER audit_chain_no_update BEFORE UPDATE ON audit_chain BEGIN SELECT RAISE(ABORT, 'audit_chain is append-only'); END;
CREATE TRIGGER audit_chain_no_delete BEFORE DELETE ON audit_chain BEGIN SELECT RAISE(ABORT, 'audit_chain is append-only'); END;
CREATE TRIGGER audit_verifications_no_update BEFORE UPDATE ON audit_verifications BEGIN SELECT RAISE(ABORT, 'audit_verifications is append-only'); END;
CREATE TRIGGER audit_verifications_no_delete BEFORE DELETE ON audit_verifications BEGIN SELECT RAISE(ABORT, 'audit_verifications is append-only'); END;
