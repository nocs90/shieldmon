package report

import (
	"context"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/lineage"
	"github.com/nocs90/shieldmon/internal/sbom"
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
// pointing to by then, and the successor configured for it (docs/adr/0025-base-successors.md).
func Lineages(ctx context.Context, src LineageSource, targets []store.Target, pol lineage.Policy, asOf time.Time) (map[int64]lineage.Result, error) {
	all, err := lineagesAt(ctx, src, targets, pol, asOf)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]lineage.Result, len(all))
	for id, l := range all {
		out[id] = l.Result
	}
	return out, nil
}

// targetLineage is a target's lineage with the digest and layers it rests on.
type targetLineage struct {
	lineage.Result
	digest  string
	diffIDs []string
}

func lineagesAt(ctx context.Context, src LineageSource, targets []store.Target, pol lineage.Policy, asOf time.Time) (map[int64]targetLineage, error) {
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
	out := make(map[int64]targetLineage, len(targets))
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
			img.VerifiedDigest, img.VerifiedLayers = ins.AnnotatedDigest, ins.AnnotatedBaseLayers
		}
		res := lineage.Evaluate(img, obs[img.BaseRef+" "+t.Platform], pol.MaxAge, asOf)
		if res.Successor = pol.Successors.For(img.BaseRef); res.Successor != "" {
			res.SuccessorSince, _ = lineage.Freshness(obs[res.Successor+" "+t.Platform], asOf)
		}
		out[t.ID] = targetLineage{Result: res, digest: digests[t.ID], diffIDs: ins.DiffIDs}
	}
	return out, nil
}

// BaseSummary counts monitored targets per base status, those on an unmaintained base, and
// open findings per remedy (docs/adr/0023-fixable-by-rebuild.md).
type BaseSummary struct {
	Status       map[string]int `json:"status"`
	Unmaintained int            `json:"unmaintained"`
	Remedies     map[string]int `json:"open_by_remedy,omitempty"`
}

// BaseSource is what base lineage and remedies need from the store.
type BaseSource interface {
	LineageSource
	ListTargets(ctx context.Context) ([]store.Target, error)
	SBOMs(ctx context.Context, digest string) ([]store.SBOM, error)
}

// AddBaseLineage adds the base lineage of the report's monitored targets as of the end of its
// period (or its generation, for the current month): from append-only history, so a past
// month gives the same answer again. With read, each open or risk-accepted row also gets its
// remedy, from the stored SBOMs of its image and of the newest base.
func AddBaseLineage(ctx context.Context, src BaseSource, r *Monthly, pol lineage.Policy, read SBOMReader) error {
	targets, err := src.ListTargets(ctx)
	if err != nil {
		return err
	}
	asOf := r.Period.End
	if r.GeneratedAt.Before(asOf) {
		asOf = r.GeneratedAt
	}
	bases, err := lineagesAt(ctx, src, targets, pol, asOf)
	if err != nil {
		return err
	}
	byKey := map[string]lineage.Result{}
	byDigest := map[string]targetLineage{} // monitored digests with a known base
	for _, t := range targets {
		l := bases[t.ID]
		byKey[t.Ref+" "+t.Platform] = l.Result
		if t.RetiredAt.IsZero() && l.BaseRef != "" && l.digest != "" {
			byDigest[l.digest] = l
		}
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
	if read == nil {
		return nil
	}
	r.Bases.Remedies = map[string]int{}
	packages := map[string]lineage.Packages{}
	for digest, l := range byDigest {
		image, err := readComponents(ctx, src, read, digest)
		if err != nil {
			return err
		}
		var newest []sbom.Component
		if l.Newest != "" {
			if newest, err = readComponents(ctx, src, read, l.Newest); err != nil {
				return err
			}
		}
		var baseLayers []string
		if l.BaseLayers > 0 && l.BaseLayers <= len(l.diffIDs) {
			baseLayers = l.diffIDs[:l.BaseLayers]
		}
		packages[digest] = lineage.Classify(image, baseLayers, newest)
	}
	for _, rows := range [][]Row{r.Open, r.AcceptedRisks} {
		for i := range rows {
			p, ok := packages[rows[i].Digest]
			if !ok {
				continue
			}
			rows[i].Remedy = string(p.Of(rows[i].PURL))
			if rows[i].State != "risk_accepted" && rows[i].State != "not_affected" {
				r.Bases.Remedies[rows[i].Remedy]++
			}
		}
	}
	return nil
}

// readComponents reads the components of every stored CycloneDX SBOM of a digest, each
// generator's with the layers it recorded; nil when none could be read. An SBOM that cannot be
// read or parsed is left out: its packages stay unknown.
func readComponents(ctx context.Context, src BaseSource, read SBOMReader, digest string) ([]sbom.Component, error) {
	list, err := src.SBOMs(ctx, digest)
	if err != nil {
		return nil, err
	}
	var out []sbom.Component
	for _, b := range list {
		if b.Format != "cyclonedx-json" {
			continue
		}
		data, err := read(b)
		if err != nil {
			continue
		}
		comps, _, err := sbom.ParseCycloneDX(data)
		if err != nil {
			continue
		}
		if out == nil {
			out = []sbom.Component{} // read, even if empty (a scratch base)
		}
		out = append(out, comps...)
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
