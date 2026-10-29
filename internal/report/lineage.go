package report

import (
	"context"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/lineage"
	"github.com/nocs90/shieldmon/internal/store"
)

// LineageSource is what base lineage needs from the store.
type LineageSource interface {
	TargetBases(ctx context.Context) (map[int64]string, error)
	Inspections(ctx context.Context) (map[string]store.ImageInspection, error)
	BaseObservations(ctx context.Context) ([]store.BaseObservation, error)
}

// Lineages gives the base lineage of each target's current digest
// (docs/adr/0022-base-image-lineage.md): a base unchanged for longer than maxAge is
// unmaintained.
func Lineages(ctx context.Context, src LineageSource, targets []store.Target, maxAge time.Duration, now time.Time) (map[int64]lineage.Result, error) {
	configured, err := src.TargetBases(ctx)
	if err != nil {
		return nil, err
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
		k := o.BaseRef + " " + o.Platform
		obs[k] = append(obs[k], lineage.Observation{Digest: o.Digest, DiffIDs: o.DiffIDs, Created: o.Created, ObservedAt: o.ObservedAt})
	}
	out := make(map[int64]lineage.Result, len(targets))
	for _, t := range targets {
		ins := inspections[t.CurrentDigest]
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
		out[t.ID] = lineage.Evaluate(img, obs[img.BaseRef+" "+t.Platform], maxAge, now)
	}
	return out, nil
}

// repositoryOf strips the tag from a normalized tag reference (host/path:tag).
func repositoryOf(ref string) string {
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref[slash+1:], ":"); colon >= 0 {
		return ref[:slash+1+colon]
	}
	return ref
}
