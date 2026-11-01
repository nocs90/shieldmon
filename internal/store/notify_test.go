package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/notify"
)

func TestNotificationRecords(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	ev := func(key string, k notify.Kind) notify.Event {
		return notify.Event{Key: key, Kind: k, Health: &notify.Health{Check: "c", Subject: key, FirstSeen: now}}
	}
	// Fractional seconds: times must not be compared as text.
	t0 := now.Add(500 * time.Millisecond)
	if err := s.RecordNotificationEvents(ctx, []notify.Event{ev("a", notify.HealthOpened), ev("b", notify.SLABreached)}, []string{"one"}, t0); err != nil {
		t.Fatal(err)
	}
	// Recorded again later: the same events, and a channel that only hears of what follows.
	t1 := now.Add(time.Hour)
	if err := s.RecordNotificationEvents(ctx, []notify.Event{ev("a", notify.HealthOpened), ev("c", notify.HealthOpened)}, []string{"one", "two"}, t1); err != nil {
		t.Fatal(err)
	}
	keysOf := func(evs []notify.Event) string {
		var out []string
		for _, e := range evs {
			out = append(out, e.Key)
		}
		return strings.Join(out, ",")
	}
	one, err := s.PendingNotifications(ctx, "one", []notify.Kind{notify.HealthOpened})
	if err != nil || keysOf(one) != "a,c" || one[0].Health == nil || one[0].Health.Subject != "a" {
		t.Fatalf("one: %q %v", keysOf(one), err)
	}
	if two, _ := s.PendingNotifications(ctx, "two", notify.Kinds); keysOf(two) != "c" {
		t.Fatalf("two hears only of events recorded since it was added: %q", keysOf(two))
	}
	if none, _ := s.PendingNotifications(ctx, "three", notify.Kinds); len(none) != 0 {
		t.Fatal("an unregistered channel has nothing pending")
	}
	if err := s.RecordNotifications(ctx, "one", []string{"a"}, t1); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordNotifications(ctx, "one", []string{"a"}, t1); err != nil {
		t.Fatalf("recording a send twice is harmless: %v", err)
	}
	if err := s.RecordNotifications(ctx, "one", []string{"zzz"}, t1); err == nil {
		t.Fatal("recording an unknown event must fail")
	}
	if one, _ = s.PendingNotifications(ctx, "one", notify.Kinds); keysOf(one) != "b,c" {
		t.Fatalf("one after sending a: %q", keysOf(one))
	}
	known, err := s.NotificationEventsKnown(ctx, []string{"a", "x"})
	if err != nil || !known["a"] || known["x"] {
		t.Fatalf("known = %v %v", known, err)
	}
	for _, q := range []string{
		`UPDATE notification_events SET payload = '{}'`,
		`DELETE FROM notification_events`,
		`UPDATE notification_channels SET added_at = ''`,
		`DELETE FROM notification_channels`,
		`UPDATE notifications SET sent_at = ''`,
		`DELETE FROM notifications`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: want append-only rejection, got %v", q, err)
		}
	}
}
