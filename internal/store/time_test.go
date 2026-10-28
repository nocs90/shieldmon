package store

import (
	"context"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

// TestExpiryWithinTheSameSecond reproduces #67: RFC 3339 timestamps with fractional seconds do
// not sort as text ("…:00Z" > "…:00.5Z"), so a decision expiring in the same second as the
// cycle's clock was compared wrongly in SQL and reopened a cycle late.
func TestExpiryWithinTheSameSecond(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	fs, _ := s.ListFindings(ctx, FindingFilter{})
	expires := now.Add(48 * time.Hour) // a whole second: stored as "…:00Z"
	if err := applyDecision(s, ctx, fs[0].ID, decision(expires), now); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ExpireDecisions(ctx, expires.Add(-time.Millisecond)); err != nil || len(got) != 0 {
		t.Fatalf("not expired a millisecond before: %v %v", got, err)
	}
	got, err := s.ExpireDecisions(ctx, expires.Add(500*time.Millisecond)) // "…:00.5Z"
	if err != nil || len(got) != 1 {
		t.Fatalf("expired half a second after its expiry: %v %v", got, err)
	}
	if f, _ := s.GetFinding(ctx, fs[0].ID); f.State != model.StateReopened {
		t.Errorf("state %s", f.State)
	}
}

// TestHealthOrderedByTime: open health findings come most recent first, also within a second.
func TestHealthOrderedByTime(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	base := now.Truncate(time.Second)
	if err := s.RecordHealth(ctx, "a", "x", "high", "", base.Add(500*time.Millisecond)); err != nil { // "…:00.5Z"
		t.Fatal(err)
	}
	if err := s.RecordHealth(ctx, "b", "x", "high", "", base); err != nil { // "…:00Z": earlier, sorts after as text
		t.Fatal(err)
	}
	hs, err := s.ListHealth(ctx, false)
	if err != nil || len(hs) != 2 || hs[0].Check != "a" {
		t.Errorf("most recent first: %+v %v", hs, err)
	}
}
