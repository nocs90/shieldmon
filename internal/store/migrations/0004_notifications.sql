-- v4: notifications, each event sent at most once per channel (docs/adr/0015-notifications.md).

-- One row per event (key: what it is about, see notify.Collect), with the event as the
-- engine first saw it (JSON).
CREATE TABLE notification_events (
    id          INTEGER PRIMARY KEY,
    key         TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX notification_events_created ON notification_events (created_at);

-- A channel receives the events recorded from when it was first configured on.
CREATE TABLE notification_channels (
    name      TEXT PRIMARY KEY,
    added_at  TEXT NOT NULL
);

-- What each channel was sent: recorded only after a successful send.
CREATE TABLE notifications (
    channel   TEXT NOT NULL REFERENCES notification_channels (name),
    event_id  INTEGER NOT NULL REFERENCES notification_events (id),
    sent_at   TEXT NOT NULL,
    PRIMARY KEY (channel, event_id)
);

CREATE TRIGGER notification_events_no_update BEFORE UPDATE ON notification_events BEGIN SELECT RAISE(ABORT, 'notification_events is append-only'); END;
CREATE TRIGGER notification_events_no_delete BEFORE DELETE ON notification_events BEGIN SELECT RAISE(ABORT, 'notification_events is append-only'); END;
CREATE TRIGGER notification_channels_no_update BEFORE UPDATE ON notification_channels BEGIN SELECT RAISE(ABORT, 'notification_channels is append-only'); END;
CREATE TRIGGER notification_channels_no_delete BEFORE DELETE ON notification_channels BEGIN SELECT RAISE(ABORT, 'notification_channels is append-only'); END;
CREATE TRIGGER notifications_no_update BEFORE UPDATE ON notifications BEGIN SELECT RAISE(ABORT, 'notifications is append-only'); END;
CREATE TRIGGER notifications_no_delete BEFORE DELETE ON notifications BEGIN SELECT RAISE(ABORT, 'notifications is append-only'); END;
