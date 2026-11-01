package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTargetRetirement(t *testing.T) {
	s, id := seed(t)
	ctx := context.Background()
	if err := s.RestoreTarget(ctx, id, "ops", "nothing to restore here", now); !errors.Is(err, ErrRetirement) {
		t.Errorf("restoring a monitored target: %v", err)
	}
	if err := s.RetireTarget(ctx, id, "ops", "short", now); err == nil {
		t.Error("a retirement needs a reason")
	}
	if err := s.RetireTarget(ctx, 999, "ops", "decommissioned in CHG-1", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown target: %v", err)
	}
	later := now.Add(time.Hour)
	if err := s.RetireTarget(ctx, id, "ops", "decommissioned in CHG-1", later); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireTarget(ctx, id, "ops", "decommissioned in CHG-1", later); !errors.Is(err, ErrRetirement) {
		t.Errorf("retiring twice: %v", err)
	}
	tg, err := s.GetTarget(ctx, id)
	if err != nil || !tg.RetiredAt.Equal(later) {
		t.Fatalf("retired target: %+v %v", tg, err)
	}
	if fs, _ := s.ListFindings(ctx, FindingFilter{}); fs[0].State != "open" {
		t.Error("retirement changes no finding")
	}
	if err := s.RestoreTarget(ctx, id, "ops", "back in production", later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if tg, _ := s.GetTarget(ctx, id); !tg.RetiredAt.IsZero() {
		t.Error("a restored target is monitored")
	}
	for _, q := range []string{`UPDATE target_events SET reason = 'x'`, `DELETE FROM target_events`} {
		if _, err := s.db.ExecContext(ctx, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: want append-only rejection, got %v", q, err)
		}
	}
}

func TestScope(t *testing.T) {
	at := func(h int) time.Time { return now.Add(time.Duration(h) * time.Hour) }
	// Target 1: digest A, then B at hour 10; retired at hour 20, restored at hour 30.
	// Target 2: digest B from hour 15, never retired after hour 25 (retired 25..).
	sc := NewScope(
		[]DigestChange{
			{TargetID: 1, Digest: "A", ObservedAt: at(0)},
			{TargetID: 1, Digest: "B", Previous: "A", ObservedAt: at(10)},
			{TargetID: 2, Digest: "B", ObservedAt: at(15)},
			{TargetID: 3, Digest: "C", ObservedAt: at(0)},
		},
		[]TargetEvent{
			{TargetID: 1, Action: ActionRetire, At: at(20)},
			{TargetID: 2, Action: ActionRetire, At: at(25)},
			{TargetID: 1, Action: ActionRestore, At: at(30)},
		},
	)
	for _, c := range []struct {
		digest string
		hour   int
		want   bool
	}{
		{"A", 5, false},  // target 1 on A, monitored
		{"A", 22, false}, // no target on A any more: stays in scope
		{"B", 22, false}, // target 1 retired, target 2 still monitors B
		{"B", 26, true},  // both targets on B retired
		{"B", 31, false}, // target 1 restored
		{"C", 40, false}, // never retired
		{"Z", 40, false}, // unknown digest
	} {
		if got := sc.Retired(c.digest, at(c.hour)); got != c.want {
			t.Errorf("digest %s at hour %d: retired=%t, want %t", c.digest, c.hour, got, c.want)
		}
	}
}
