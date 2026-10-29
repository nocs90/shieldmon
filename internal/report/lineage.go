package report

import (
	"context"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/lineage"
	"github.com/nocs90/shieldmon/internal/store"
)

// LineageSource is what base lineage needs from the store: append-only history and the
// immutable inspections of digests, so that the lineage at any past time can be computed again.
type LineageSource interface {
	TargetBaseHistory(ctx context.Context) ([]store.TargetBaseChange, error)
	DigestHistory(ctx context.Context) ([]store.DigestChange, error)
	Inspections(ctx context.Context) (map[string]store.ImageInspection, error)
	BaseObservations(ctx context.Context) ([]store.BaseObservation, error)
}

// Lineages gives the base lineage of each target at asOf (docs/adr/0022-base-image-lineage.md):
// the digest it resolved to then, the base configured then, what the base had been seen
// pointing to by then. A base unchanged for longer than maxAge is unmaintained.
func Lineages(ctx context.Context, src LineageSource, targets []store.Target, maxAge time.Duration, asOf time.Time) (map[int64]lineage.Result, error) {
	configured := map[int64]string{}
	bases, err := src.TargetBaseHistory(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range bases {
		if !c.At.After(asOf) {
			configured[c.TargetID] = c.BaseRef
		}
	}
	digests := map[int64]string{}
	history, err := src.DigestHistory(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range history {
		if !c.ObservedAt.After(asOf) {
			digests[c.TargetID] = c.Digest
		}
	}
	inspections, err := src.Inspections(ctx)
	if err != nil {
		return nil, err
	}
	all, err := src.BaseObservations(ctx)
	if err != nil {
		return nil, err
	}
	obs := map[string][]lineage.Observation{} // by reference and platform, oldest first
	for _, o := range all {
		if o.ObservedAt.After(asOf) {
			continue
		}
		k := o.BaseRef + " " + o.Platform
		obs[k] = append(obs[k], lineage.Observation{Digest: o.Digest, DiffIDs: o.DiffIDs, Created: o.Created, ObservedAt: o.ObservedAt})
	}
	out := make(map[int64]lineage.Result, len(targets))
	for _, t := range targets {
		ins := inspections[digests[t.ID]]
		img := lineage.Image{DiffIDs: ins.DiffIDs, BaseRef: configured[t.ID], Source: lineage.SourceConfigured}
		if img.BaseRef == "" && ins.AnnotatedBase != "" {
			img.BaseRef, img.Source = ins.AnnotatedBase, lineage.SourceAnnotation
		}
		if img.BaseRef == "" {
			img.Source = ""
		}
		// An annotated digest counts only once its layers matched, and for the base it names.
		if ins.AnnotatedVerified && ins.AnnotatedRepository == repositoryOf(img.BaseRef) {
			img.VerifiedDigest = ins.AnnotatedDigest
		}
		out[t.ID] = lineage.Evaluate(img, obs[img.BaseRef+" "+t.Platform], maxAge, asOf)
	}
	return out, nil
}

// BaseSummary counts monitored targets per base status, and those on an unmaintained base.
type BaseSummary struct {
	Status       map[string]int `json:"status"`
	Unmaintained int            `json:"unmaintained"`
}

// AddBaseLineage adds the base lineage of the report's monitored targets as of the end of its
// period (or its generation, for the current month): from append-only history, so a past
// month gives the same answer again.
func AddBaseLineage(ctx context.Context, src interface {
	LineageSource
	ListTargets(ctx context.Context) ([]store.Target, error)
}, r *Monthly, maxAge time.Duration,
) error {
	targets, err := src.ListTargets(ctx)
	if err != nil {
		return err
	}
	asOf := r.Period.End
	if r.GeneratedAt.Before(asOf) {
		asOf = r.GeneratedAt
	}
	bases, err := Lineages(ctx, src, targets, maxAge, asOf)
	if err != nil {
		return err
	}
	byKey := map[string]lineage.Result{}
	for _, t := range targets {
		byKey[t.Ref+" "+t.Platform] = bases[t.ID]
	}
	r.Bases = &BaseSummary{Status: map[string]int{}}
	for i := range r.TargetSummaries {
		ts := &r.TargetSummaries[i]
		if !ts.RetiredAt.IsZero() {
			continue
		}
		b := byKey[ts.Ref+" "+ts.Platform]
		ts.Base = &b
		r.Bases.Status[string(b.Status)]++
		if b.Unmaintained {
			r.Bases.Unmaintained++
		}
	}
	return nil
}

// repositoryOf strips the tag from a normalized tag reference (host/path:tag).
func repositoryOf(ref string) string {
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref[slash+1:], ":"); colon >= 0 {
		return ref[:slash+1+colon]
	}
	return ref
}
