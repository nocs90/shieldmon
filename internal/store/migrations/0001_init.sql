-- ShieldMon schema v1. Timestamps are RFC 3339 UTC strings.
-- Tables marked APPEND-ONLY reject UPDATE and DELETE via triggers: they are
-- the audit trail that reports and closure evidence are derived from.

CREATE TABLE targets (
    id               INTEGER PRIMARY KEY,
    ref              TEXT NOT NULL,          -- normalized input reference (tag or digest)
    platform         TEXT NOT NULL,          -- os/arch[/variant]
    current_digest   TEXT,
    created_at       TEXT NOT NULL,
    last_resolved_at TEXT,
    UNIQUE (ref, platform)
);

CREATE TABLE artifacts (
    digest        TEXT PRIMARY KEY,          -- platform image manifest digest
    repository    TEXT NOT NULL,
    index_digest  TEXT,
    media_type    TEXT NOT NULL,
    platform      TEXT NOT NULL,
    first_seen_at TEXT NOT NULL
);

-- APPEND-ONLY: every digest a target has resolved to, in order.
CREATE TABLE target_digests (
    id              INTEGER PRIMARY KEY,
    target_id       INTEGER NOT NULL REFERENCES targets (id),
    digest          TEXT NOT NULL REFERENCES artifacts (digest),
    previous_digest TEXT,
    observed_at     TEXT NOT NULL
);
CREATE INDEX target_digests_target ON target_digests (target_id);

CREATE TABLE sboms (
    id                INTEGER PRIMARY KEY,
    digest            TEXT NOT NULL REFERENCES artifacts (digest),
    generator         TEXT NOT NULL,
    generator_version TEXT NOT NULL,
    format            TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    size              INTEGER NOT NULL,
    path              TEXT NOT NULL,          -- relative to the data directory
    created_at        TEXT NOT NULL,
    UNIQUE (digest, generator, format)
);

CREATE TABLE scans (
    id          INTEGER PRIMARY KEY,
    digest      TEXT NOT NULL REFERENCES artifacts (digest),
    target_id   INTEGER REFERENCES targets (id),
    kind        TEXT NOT NULL CHECK (kind IN ('initial', 'rematch')),
    status      TEXT NOT NULL CHECK (status IN ('running', 'complete', 'partial', 'failed')),
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    tools       TEXT NOT NULL DEFAULT '[]',  -- JSON: scanner name/version/DB version/DB built
    error       TEXT
);
CREATE INDEX scans_digest ON scans (digest);

CREATE TABLE findings (
    id                INTEGER PRIMARY KEY,
    digest            TEXT NOT NULL REFERENCES artifacts (digest),
    purl              TEXT NOT NULL,
    vuln_id           TEXT NOT NULL,
    pkg_key           TEXT NOT NULL,          -- purl without version (lineage)
    pkg_name          TEXT NOT NULL,
    pkg_version       TEXT NOT NULL,
    pkg_type          TEXT NOT NULL,
    aliases           TEXT NOT NULL DEFAULT '[]',
    severity          TEXT NOT NULL,
    cvss_score        REAL NOT NULL DEFAULT 0,
    cvss_vector       TEXT NOT NULL DEFAULT '',
    epss              REAL NOT NULL DEFAULT 0,
    kev               INTEGER NOT NULL DEFAULT 0,
    fix_versions      TEXT NOT NULL DEFAULT '[]',
    scanners          TEXT NOT NULL DEFAULT '[]',
    title             TEXT NOT NULL DEFAULT '',
    state             TEXT NOT NULL,
    first_detected_at TEXT NOT NULL,          -- inherited across the lineage
    created_at        TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,
    last_seen_scan_id INTEGER REFERENCES scans (id),
    closed_at         TEXT,
    predecessor_id    INTEGER REFERENCES findings (id),
    UNIQUE (digest, purl, vuln_id)
);
CREATE INDEX findings_state ON findings (state);
CREATE INDEX findings_lineage ON findings (pkg_key, vuln_id);

-- APPEND-ONLY: what every scan observed.
CREATE TABLE scan_matches (
    scan_id    INTEGER NOT NULL REFERENCES scans (id),
    finding_id INTEGER NOT NULL REFERENCES findings (id),
    scanners   TEXT NOT NULL,
    severity   TEXT NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);

-- APPEND-ONLY: every state change, with actor and evidence.
CREATE TABLE finding_events (
    id         INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings (id),
    at         TEXT NOT NULL,
    from_state TEXT,
    to_state   TEXT NOT NULL,
    actor      TEXT NOT NULL,
    reason     TEXT NOT NULL,
    scan_id    INTEGER REFERENCES scans (id)
);
CREATE INDEX finding_events_finding ON finding_events (finding_id);
CREATE INDEX finding_events_at ON finding_events (at);

-- APPEND-ONLY: VEX-style decisions (risk acceptance, not affected).
CREATE TABLE decisions (
    id            INTEGER PRIMARY KEY,
    finding_id    INTEGER NOT NULL REFERENCES findings (id),
    state         TEXT NOT NULL CHECK (state IN ('risk_accepted', 'not_affected')),
    justification TEXT NOT NULL,
    author        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT
);
CREATE INDEX decisions_finding ON decisions (finding_id);

-- Self-health findings: failures of the monitoring process itself.
CREATE TABLE health_findings (
    id            INTEGER PRIMARY KEY,
    check_name    TEXT NOT NULL,
    subject       TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('open', 'resolved')),
    severity      TEXT NOT NULL,
    detail        TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    resolved_at   TEXT,
    occurrences   INTEGER NOT NULL DEFAULT 1,
    UNIQUE (check_name, subject)
);

CREATE TABLE monitor_runs (
    id          INTEGER PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL CHECK (status IN ('running', 'ok', 'degraded', 'failed')),
    targets     INTEGER NOT NULL DEFAULT 0,
    errors      INTEGER NOT NULL DEFAULT 0
);

CREATE TRIGGER target_digests_no_update BEFORE UPDATE ON target_digests BEGIN SELECT RAISE(ABORT, 'target_digests is append-only'); END;
CREATE TRIGGER target_digests_no_delete BEFORE DELETE ON target_digests BEGIN SELECT RAISE(ABORT, 'target_digests is append-only'); END;
CREATE TRIGGER scan_matches_no_update BEFORE UPDATE ON scan_matches BEGIN SELECT RAISE(ABORT, 'scan_matches is append-only'); END;
CREATE TRIGGER scan_matches_no_delete BEFORE DELETE ON scan_matches BEGIN SELECT RAISE(ABORT, 'scan_matches is append-only'); END;
CREATE TRIGGER finding_events_no_update BEFORE UPDATE ON finding_events BEGIN SELECT RAISE(ABORT, 'finding_events is append-only'); END;
CREATE TRIGGER finding_events_no_delete BEFORE DELETE ON finding_events BEGIN SELECT RAISE(ABORT, 'finding_events is append-only'); END;
CREATE TRIGGER decisions_no_update BEFORE UPDATE ON decisions BEGIN SELECT RAISE(ABORT, 'decisions is append-only'); END;
CREATE TRIGGER decisions_no_delete BEFORE DELETE ON decisions BEGIN SELECT RAISE(ABORT, 'decisions is append-only'); END;
