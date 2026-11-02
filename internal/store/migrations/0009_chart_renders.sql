-- v9: chart tracking (docs/adr/0034-chart-tracking.md).

-- APPEND-ONLY: what one version of a followed chart runs with one profile, as rendered. A
-- version is rendered again only when its archive or the profile changes; the latest row per
-- (chart, profile) is what the chart runs now. images is a JSON array of {"ref", "hook"},
-- valid references only (invalid counts the others); opaque counts custom resources.
CREATE TABLE chart_renders (
    id           INTEGER PRIMARY KEY,
    chart        TEXT NOT NULL,
    version      TEXT NOT NULL,
    app_version  TEXT NOT NULL,
    released_at  TEXT,
    digest       TEXT NOT NULL,
    profile      TEXT NOT NULL,
    profile_hash TEXT NOT NULL,
    images       TEXT NOT NULL,
    invalid      INTEGER NOT NULL,
    opaque       INTEGER NOT NULL,
    rendered_at  TEXT NOT NULL
);
CREATE INDEX chart_renders_chart ON chart_renders (chart, profile, id);

CREATE TRIGGER chart_renders_no_update BEFORE UPDATE ON chart_renders BEGIN SELECT RAISE(ABORT, 'chart_renders is append-only'); END;
CREATE TRIGGER chart_renders_no_delete BEFORE DELETE ON chart_renders BEGIN SELECT RAISE(ABORT, 'chart_renders is append-only'); END;
