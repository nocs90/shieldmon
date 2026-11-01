package engine

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/export"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/sbom"
	"github.com/nocs90/shieldmon/internal/store"
)

// CheckExport opens when an export fails (subject: the export's name).
const CheckExport = "export_failed"

// ExportBatch is what exporters get (docs/adr/0027-exporters.md): every monitored, resolved
// target with its stored CycloneDX SBOM and its open and risk-accepted findings as of now,
// with deadlines, priority, remedies and owners as the reports show them.
func (e *Engine) ExportBatch(ctx context.Context, tool string) (export.Batch, error) {
	now := e.now()
	b := export.Batch{Now: now, Tool: tool}
	r, err := report.BuildMonthly(ctx, e.Store, report.MonthPeriod(now), e.Decisions.Profile, config.SLA(e.Decisions.SLADays), now)
	if err != nil {
		return b, err
	}
	read := func(s store.SBOM) ([]byte, error) { return e.ReadSBOM(s, sbom.MaxBytes) }
	if err := report.AddBaseLineage(ctx, e.Store, &r, e.Bases, read); err != nil {
		return b, err
	}
	report.AddOwners(&r, e.Owners)
	byDigest := map[string][]report.Row{}
	for _, x := range r.Open {
		byDigest[x.Digest] = append(byDigest[x.Digest], x)
	}
	for _, x := range r.AcceptedRisks {
		if x.State == "risk_accepted" {
			byDigest[x.Digest] = append(byDigest[x.Digest], x)
		}
	}
	targets, err := e.Store.ListTargets(ctx)
	if err != nil {
		return b, err
	}
	platforms := map[string]int{}
	for _, t := range targets {
		if t.RetiredAt.IsZero() && t.CurrentDigest != "" {
			platforms[t.Ref]++
		}
	}
	for _, t := range targets {
		if !t.RetiredAt.IsZero() || t.CurrentDigest == "" {
			continue
		}
		et := export.Target{
			Ref: t.Ref, Platform: t.Platform, Digest: t.CurrentDigest, Repository: t.Ref, Tag: t.CurrentDigest,
			MultiPlatform: platforms[t.Ref] > 1, Findings: byDigest[t.CurrentDigest],
		}
		if ref, err := oci.ParseReference(t.Ref, false); err == nil {
			et.Repository = ref.Context().Name()
			if tag, ok := ref.(name.Tag); ok {
				et.Tag = tag.TagStr()
			}
		}
		if et.SBOM, err = e.cycloneDX(ctx, t.CurrentDigest); err != nil {
			return b, err
		}
		b.Targets = append(b.Targets, et)
	}
	return b, nil
}

// cycloneDX reads the digest's stored CycloneDX SBOM, syft's first; nil when there is none.
func (e *Engine) cycloneDX(ctx context.Context, digest string) ([]byte, error) {
	list, err := e.Store.SBOMs(ctx, digest)
	if err != nil {
		return nil, err
	}
	var pick *store.SBOM
	for i := range list {
		if list[i].Format != "cyclonedx-json" {
			continue
		}
		if pick == nil || list[i].Generator == "syft" {
			pick = &list[i]
		}
	}
	if pick == nil {
		return nil, nil
	}
	return e.ReadSBOM(*pick, sbom.MaxBytes)
}

// Export sends the batch to each export and records the outcome as a health finding: a
// failing export is missing evidence downstream (I6).
func (e *Engine) Export(ctx context.Context, exports []export.Instance, b export.Batch) (map[string]export.Result, error) {
	out := map[string]export.Result{}
	for _, ex := range exports {
		res, err := ex.Sender.Export(ctx, b)
		out[ex.Name] = res
		switch {
		case err != nil:
			e.health(ctx, CheckExport, ex.Name, "medium", err)
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
		case len(res.Failed) > 0:
			e.health(ctx, CheckExport, ex.Name, "medium", fmt.Errorf("%d of %d target(s) not exported", len(res.Failed), len(b.Targets)))
		default:
			e.healthy(ctx, CheckExport, ex.Name)
		}
	}
	return out, nil
}
