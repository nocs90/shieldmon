// Package enrichtest is the conformance kit for enrichers (docs/extending/enricher.md).
package enrichtest

import (
	"context"
	"reflect"
	"testing"

	"github.com/nocs90/shieldmon/internal/enrich"
	"github.com/nocs90/shieldmon/internal/model"
)

// Fixture is an enricher wired by its test to a fake source.
type Fixture struct {
	// Name is the enricher's registered name.
	Name string
	// New builds an instance on an empty cache, against a source that serves good data.
	New func(t *testing.T) enrich.Enricher
	// Known is a match the good data enriches (Enrich changes it); Unknown one it does not.
	Known, Unknown model.Match
	// Broken builds an instance whose source fails or serves hostile data, sharing the cache
	// directory of the instance given (already updated from good data).
	Broken func(t *testing.T, updated enrich.Enricher) enrich.Enricher
}

// CheckEnricher verifies an enricher's contract: registered and described; no data and no
// change before the first update; Update honours cancellation; enrichment from updated data,
// idempotent, only on what the data knows; a failed update keeps the data and its age.
func CheckEnricher(t *testing.T, f Fixture) {
	t.Helper()
	p, ok := enrich.Lookup(f.Name)
	if !ok {
		t.Fatalf("enricher %q is not registered", f.Name)
	}
	if p.Description == "" {
		t.Errorf("enricher %q has no description", f.Name)
	}
	ctx := context.Background()
	e := f.New(t)
	if !e.UpdatedAt().IsZero() {
		t.Error("an empty cache has no data: UpdatedAt must be zero")
	}
	m := f.Known
	e.Enrich(&m)
	if !reflect.DeepEqual(m, f.Known) {
		t.Error("without data, Enrich must change nothing")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := e.Update(cancelled); err == nil {
		t.Error("Update must honour context cancellation")
	}
	if err := e.Update(ctx); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated := e.UpdatedAt()
	if updated.IsZero() {
		t.Fatal("UpdatedAt must be set by a successful update")
	}
	known := f.Known
	e.Enrich(&known)
	if reflect.DeepEqual(known, f.Known) {
		t.Error("the data must enrich the Known match")
	}
	twice := known
	e.Enrich(&twice)
	if !reflect.DeepEqual(twice, known) {
		t.Error("Enrich must be idempotent")
	}
	unknown := f.Unknown
	e.Enrich(&unknown)
	if !reflect.DeepEqual(unknown, f.Unknown) {
		t.Error("Enrich must change only what the data knows")
	}
	if f.Broken != nil {
		b := f.Broken(t, e)
		if err := b.Update(ctx); err == nil {
			t.Error("an update from a broken source must fail")
		}
		again := f.Known
		b.Enrich(&again)
		if !reflect.DeepEqual(again, known) || !b.UpdatedAt().Equal(updated) {
			t.Error("a failed update must keep the previous data and its age")
		}
	}
}
