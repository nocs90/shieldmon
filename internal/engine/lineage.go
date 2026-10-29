package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nocs90/shieldmon/internal/lineage"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/store"
)

// trackLineage records what a scanned image is built on and what its base reference points to
// now (docs/adr/0022-base-image-lineage.md). Manifests and configs only: nothing is pulled, no
// scanner runs. Failures open health findings and never fail the scan.
func (e *Engine) trackLineage(ctx context.Context, t store.Target, r oci.Resolved, p model.Platform) {
	ins, err := e.inspectImage(ctx, r, p)
	subject := r.DigestRef()
	if err != nil {
		e.health(ctx, CheckImageInspect, subject, "medium", err)
		return
	}
	e.healthy(ctx, CheckImageInspect, subject)
	bases, err := e.Store.TargetBases(ctx)
	if err != nil {
		e.log().Error("target bases", "err", err)
		return
	}
	ref := bases[t.ID]
	if ref == "" {
		ref = ins.AnnotatedBase
	}
	if ref != "" {
		e.observeBase(ctx, ref, p)
	}
}

// inspectImage returns the stored inspection of the image's digest, inspecting it the first
// time. An annotated base digest is read to check its layers: until they match, it is a claim.
func (e *Engine) inspectImage(ctx context.Context, r oci.Resolved, p model.Platform) (store.ImageInspection, error) {
	ins, err := e.Store.Inspection(ctx, r.Digest)
	if !errors.Is(err, store.ErrNotFound) {
		return ins, err
	}
	info, err := e.Fetcher.Inspect(ctx, r.DigestRef(), p)
	if err != nil {
		return ins, fmt.Errorf("inspect %s: %s", r.DigestRef(), redact.Error(err))
	}
	if info.Digest != r.Digest {
		return ins, fmt.Errorf("inspect %s: registry served %s", r.DigestRef(), info.Digest)
	}
	ins = store.ImageInspection{
		Digest: r.Digest, DiffIDs: info.DiffIDs, Created: info.Created, AnnotatedBase: info.BaseName,
		AnnotatedRepository: info.BaseRepository, AnnotatedDigest: info.BaseDigest, Problems: info.Problems,
		InspectedAt: e.now(),
	}
	if info.BaseDigest != "" {
		base, err := e.Fetcher.Inspect(ctx, info.BaseRepository+"@"+info.BaseDigest, p)
		switch {
		case err != nil:
			ins.Problems = append(ins.Problems, "annotated base digest could not be read: "+redact.Error(err))
		case lineage.IsPrefix(base.DiffIDs, info.DiffIDs):
			ins.AnnotatedVerified = true
		default:
			ins.Problems = append(ins.Problems, "annotated base digest does not share the image's first layers")
		}
	}
	if err := e.Store.RecordInspection(ctx, ins); err != nil {
		return ins, err
	}
	for _, pr := range ins.Problems {
		e.log().Warn("image annotations", "image", r.DigestRef(), "problem", pr)
	}
	return ins, nil
}

// baseStates is the base lineage of each monitored image digest with a known base, for
// notifications: one per digest and base, with the targets on it.
func (e *Engine) baseStates(ctx context.Context, now time.Time) ([]notify.Base, error) {
	targets, err := e.Store.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	targets = slices.DeleteFunc(targets, func(t store.Target) bool { return !t.RetiredAt.IsZero() || t.CurrentDigest == "" })
	lineages, err := report.Lineages(ctx, e.Store, targets, e.BaseMaxAge, now)
	if err != nil {
		return nil, err
	}
	var out []notify.Base
	index := map[string]int{}
	for _, t := range targets {
		l := lineages[t.ID]
		if l.BaseRef == "" {
			continue
		}
		k := t.CurrentDigest + " " + l.BaseRef
		i, ok := index[k]
		if !ok {
			i, index[k] = len(out), len(out)
			out = append(out, notify.Base{
				Digest: t.CurrentDigest, BaseRef: l.BaseRef, BaseDigest: l.BaseDigest, Newest: l.Newest, Since: l.Since,
				Status: string(l.Status), Unmaintained: l.Unmaintained,
			})
		}
		out[i].Images = append(out[i].Images, t.Ref+" ("+t.Platform+")")
	}
	return out, nil
}

// observeBase records what a base reference points to on a platform when it moved; once per
// monitor cycle.
func (e *Engine) observeBase(ctx context.Context, ref string, p model.Platform) {
	key := ref + " " + p.String()
	if e.observedBases != nil {
		if e.observedBases[key] {
			return
		}
		e.observedBases[key] = true
	}
	res, err := e.Fetcher.Resolve(ctx, ref, p)
	if err != nil {
		e.health(ctx, CheckBaseResolve, ref, "medium", err)
		return
	}
	last, err := e.Store.LatestBaseObservation(ctx, ref, p.String())
	if err == nil && last.Digest == res.Digest {
		e.healthy(ctx, CheckBaseResolve, ref)
		return
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		e.log().Error("base observation", "err", err)
		return
	}
	info, err := e.Fetcher.Inspect(ctx, res.DigestRef(), p)
	if err != nil {
		e.health(ctx, CheckBaseResolve, ref, "medium", err)
		return
	}
	if _, err := e.Store.RecordBaseObservation(ctx, store.BaseObservation{
		BaseRef: ref, Platform: p.String(), Digest: info.Digest, DiffIDs: info.DiffIDs, Created: info.Created, ObservedAt: e.now(),
	}); err != nil {
		e.log().Error("record base observation", "err", err)
		return
	}
	e.healthy(ctx, CheckBaseResolve, ref)
}
