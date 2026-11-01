package lineage

import (
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/oci"
)

// Policy is how base lineages are judged: how long a base may stay unchanged before it is
// unmaintained (0: never), and the configured successors.
type Policy struct {
	MaxAge     time.Duration
	Successors Successors
}

// Successors are the configured successor bases (docs/adr/0025-base-successors.md); the zero
// value has none.
type Successors struct {
	rules []successor
}

type successor struct{ pattern, to string }

// NewSuccessors validates bases.successors: a reference pattern and a tag to follow each.
func NewSuccessors(cfg []config.Successor) (Successors, error) {
	var s Successors
	for i, c := range cfg {
		p, err := oci.RefPattern(c.From)
		if err != nil {
			return s, fmt.Errorf("bases.successors[%d].from: %q: %w", i, c.From, err)
		}
		ref, err := oci.ParseReference(c.To, false)
		if err != nil {
			return s, fmt.Errorf("bases.successors[%d].to: %w", i, err)
		}
		if _, ok := ref.(name.Tag); !ok {
			return s, fmt.Errorf("bases.successors[%d].to: %q: name a tag to follow", i, c.To)
		}
		s.rules = append(s.rules, successor{pattern: p, to: ref.Name()})
	}
	return s, nil
}

// For returns the successor configured for a base reference, or "".
func (s Successors) For(baseRef string) string {
	for _, r := range s.rules {
		if r.to != baseRef && oci.MatchRef(r.pattern, baseRef) {
			return r.to
		}
	}
	return ""
}

// Freshness says since when a reference points to its newest observed digest (oldest first):
// from when it was seen moving there, or, when never seen moving, from the image's creation
// time if plausible. Source is "observed" or "created"; zero without observations.
func Freshness(obs []Observation, now time.Time) (since time.Time, source string) {
	if len(obs) == 0 {
		return time.Time{}, ""
	}
	newest := obs[len(obs)-1]
	if len(obs) == 1 && newest.Created.After(plausibleFrom) && !newest.Created.After(now) {
		return newest.Created, "created"
	}
	return newest.ObservedAt, "observed"
}
