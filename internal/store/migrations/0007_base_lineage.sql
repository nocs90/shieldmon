-- v7: base image lineage (docs/adr/0022-base-image-lineage.md).

-- APPEND-ONLY: the base configured for a target. The latest row wins; an empty base_ref clears it.
CREATE TABLE target_bases (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER NOT NULL REFERENCES targets (id),
    base_ref   TEXT NOT NULL,
    actor      TEXT NOT NULL,
    at         TEXT NOT NULL
);
CREATE INDEX target_bases_target ON target_bases (target_id, id);

-- APPEND-ONLY: what an image digest was read to be, once per digest: its layers, base layers
-- first, and its base annotations (a claim; annotated_verified says whether the layers of the
-- annotated base digest are a prefix of the image's).
CREATE TABLE image_inspections (
    digest               TEXT PRIMARY KEY REFERENCES artifacts (digest),
    diff_ids             TEXT NOT NULL,
    created              TEXT,
    annotated_base       TEXT NOT NULL,
    annotated_repository TEXT NOT NULL,
    annotated_digest     TEXT NOT NULL,
    annotated_verified   INTEGER NOT NULL CHECK (annotated_verified IN (0, 1)),
    problems             TEXT NOT NULL,
    inspected_at         TEXT NOT NULL
);

-- APPEND-ONLY: every digest a base reference pointed to on a platform, recorded when it changes.
CREATE TABLE base_observations (
    id          INTEGER PRIMARY KEY,
    base_ref    TEXT NOT NULL,
    platform    TEXT NOT NULL,
    digest      TEXT NOT NULL,
    diff_ids    TEXT NOT NULL,
    created     TEXT,
    observed_at TEXT NOT NULL
);
CREATE INDEX base_observations_ref ON base_observations (base_ref, platform, id);

CREATE TRIGGER target_bases_no_update BEFORE UPDATE ON target_bases BEGIN SELECT RAISE(ABORT, 'target_bases is append-only'); END;
CREATE TRIGGER target_bases_no_delete BEFORE DELETE ON target_bases BEGIN SELECT RAISE(ABORT, 'target_bases is append-only'); END;
CREATE TRIGGER image_inspections_no_update BEFORE UPDATE ON image_inspections BEGIN SELECT RAISE(ABORT, 'image_inspections is append-only'); END;
CREATE TRIGGER image_inspections_no_delete BEFORE DELETE ON image_inspections BEGIN SELECT RAISE(ABORT, 'image_inspections is append-only'); END;
CREATE TRIGGER base_observations_no_update BEFORE UPDATE ON base_observations BEGIN SELECT RAISE(ABORT, 'base_observations is append-only'); END;
CREATE TRIGGER base_observations_no_delete BEFORE DELETE ON base_observations BEGIN SELECT RAISE(ABORT, 'base_observations is append-only'); END;
