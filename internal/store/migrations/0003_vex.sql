-- v3: VEX statements, scoped not_affected decisions (docs/adr/0014-vex.md).

-- One row per distinct statement (key = hash of its content, whatever document it came in).
-- The product is digest, or repository (every digest of it) when digest is ''. purl = ''
-- covers every package; any_version = 1 when the PURL was given without a version.
CREATE TABLE vex_statements (
    id            INTEGER PRIMARY KEY,
    key           TEXT NOT NULL UNIQUE,
    vuln_id       TEXT NOT NULL,
    aliases       TEXT NOT NULL DEFAULT '[]',
    digest        TEXT NOT NULL DEFAULT '',
    repository    TEXT NOT NULL DEFAULT '',
    purl          TEXT NOT NULL DEFAULT '',
    any_version   INTEGER NOT NULL DEFAULT 0,
    justification TEXT NOT NULL DEFAULT '',
    impact        TEXT NOT NULL DEFAULT '',
    notes         TEXT NOT NULL DEFAULT '',
    author        TEXT NOT NULL,
    stated_at     TEXT NOT NULL,
    expires_at    TEXT,
    source        TEXT NOT NULL DEFAULT '',
    imported_at   TEXT NOT NULL,
    imported_by   TEXT NOT NULL,
    CHECK (digest <> '' OR repository <> '')
);
CREATE INDEX vex_statements_vuln ON vex_statements (vuln_id);

-- The statement a decision came from (NULL for decisions taken by hand). Carried decisions
-- keep it, so that an export does not mistake them for manual ones.
ALTER TABLE decisions ADD COLUMN vex_statement_id INTEGER REFERENCES vex_statements (id);

-- A statement applies once per finding: a finding the engine reopens later is not
-- suppressed again by the same statement.
CREATE TABLE vex_applications (
    statement_id INTEGER NOT NULL REFERENCES vex_statements (id),
    finding_id   INTEGER NOT NULL REFERENCES findings (id),
    applied_at   TEXT NOT NULL,
    PRIMARY KEY (statement_id, finding_id)
);

CREATE TRIGGER vex_statements_no_update BEFORE UPDATE ON vex_statements BEGIN SELECT RAISE(ABORT, 'vex_statements is append-only'); END;
CREATE TRIGGER vex_statements_no_delete BEFORE DELETE ON vex_statements BEGIN SELECT RAISE(ABORT, 'vex_statements is append-only'); END;
CREATE TRIGGER vex_applications_no_update BEFORE UPDATE ON vex_applications BEGIN SELECT RAISE(ABORT, 'vex_applications is append-only'); END;
CREATE TRIGGER vex_applications_no_delete BEFORE DELETE ON vex_applications BEGIN SELECT RAISE(ABORT, 'vex_applications is append-only'); END;
