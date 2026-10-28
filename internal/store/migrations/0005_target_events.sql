-- v5: target retirement (docs/adr/0017-target-retirement.md).

-- APPEND-ONLY: retirements and restorations of targets. A target is retired when its latest
-- event is a retirement. Findings are never changed by these events.
CREATE TABLE target_events (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER NOT NULL REFERENCES targets (id),
    action     TEXT NOT NULL CHECK (action IN ('retire', 'restore')),
    actor      TEXT NOT NULL,
    reason     TEXT NOT NULL,
    at         TEXT NOT NULL
);
CREATE INDEX target_events_target ON target_events (target_id);

CREATE TRIGGER target_events_no_update BEFORE UPDATE ON target_events BEGIN SELECT RAISE(ABORT, 'target_events is append-only'); END;
CREATE TRIGGER target_events_no_delete BEFORE DELETE ON target_events BEGIN SELECT RAISE(ABORT, 'target_events is append-only'); END;
