package report

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/store"
)

// InventorySource is the subset of the store the inventory needs.
type InventorySource interface {
	ListTargets(ctx context.Context) ([]store.Target, error)
	GetArtifact(ctx context.Context, digest string) (store.Artifact, error)
	LatestScan(ctx context.Context, digest string) (store.Scan, error)
	LatestCompleteScan(ctx context.Context, digest string) (store.Scan, error)
	SBOMs(ctx context.Context, digest string) ([]store.SBOM, error)
	ListFindings(ctx context.Context, f store.FindingFilter) ([]store.Finding, error)
	DigestHistory(ctx context.Context) ([]store.DigestChange, error)
}

// Evidence gaps: why the inventory cannot vouch for an image's findings.
const (
	GapUnresolved = "unresolved"        // the tag never resolved to a digest
	GapNoScan     = "no_scan"           // the digest was never scanned
	GapPartial    = "last_scan_partial" // a matcher failed in the last scan
	GapFailed     = "last_scan_failed"  // the last scan failed
	GapStale      = "stale_evidence"    // no complete scan within the expected cadence
	GapNoSBOM     = "missing_sbom"      // a required generator has no SBOM ("missing_sbom:syft")
)

// InventoryOptions parameterise the inventory.
type InventoryOptions struct {
	Now time.Time
	// StaleAfter is how old the last complete scan may be (0: never stale).
	StaleAfter time.Duration
	// Generators are the SBOM generators the configured matchers require.
	Generators []string
}

// Inventory is what ShieldMon monitors and how fresh its evidence is.
type Inventory struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Summary     InventorySummary `json:"summary"`
	Images      []Image          `json:"images"`
}

// InventorySummary counts images and their evidence gaps.
type InventorySummary struct {
	Targets  int            `json:"targets"`
	Digests  int            `json:"digests"`
	WithGaps int            `json:"with_gaps"`
	Gaps     map[string]int `json:"gaps"`
	Open     map[string]int `json:"open_by_severity"`
}

// Image is one monitored target.
type Image struct {
	Ref            string         `json:"ref"`
	Platform       string         `json:"platform"`
	Digest         string         `json:"digest,omitempty"`
	Repository     string         `json:"repository,omitempty"`
	MonitoredSince time.Time      `json:"monitored_since"`
	LastResolved   time.Time      `json:"last_resolved,omitzero"`
	DigestChanges  int            `json:"digest_changes"`
	LastScan       *ScanInfo      `json:"last_scan,omitempty"`
	LastComplete   time.Time      `json:"last_complete_scan,omitzero"`
	SBOMs          []SBOMInfo     `json:"sboms"`
	Open           map[string]int `json:"open_by_severity"`
	Gaps           []string       `json:"gaps"`
}

// ScanInfo is a scan as the inventory shows it.
type ScanInfo struct {
	At     time.Time    `json:"at"`
	Kind   string       `json:"kind"`
	Status string       `json:"status"`
	Tools  []model.Tool `json:"tools"`
}

// SBOMInfo is a stored SBOM as the inventory shows it.
type SBOMInfo struct {
	Generator string `json:"generator"`
	Version   string `json:"generator_version"`
	Format    string `json:"format"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

// BuildInventory computes the inventory as of opts.Now.
func BuildInventory(ctx context.Context, src InventorySource, opts InventoryOptions) (Inventory, error) {
	inv := Inventory{GeneratedAt: opts.Now.UTC(), Summary: InventorySummary{Gaps: map[string]int{}, Open: map[string]int{}}}
	targets, err := src.ListTargets(ctx)
	if err != nil {
		return inv, err
	}
	history, err := src.DigestHistory(ctx)
	if err != nil {
		return inv, err
	}
	changes := map[int64]int{}
	for _, c := range history {
		if c.Previous != "" {
			changes[c.TargetID]++
		}
	}
	active, err := src.ListFindings(ctx, store.FindingFilter{States: []model.State{
		model.StateOpen, model.StateTriaged, model.StateInRemediation, model.StateReopened,
	}})
	if err != nil {
		return inv, err
	}
	openByDigest := map[string]map[string]int{}
	for _, f := range active {
		if openByDigest[f.Digest] == nil {
			openByDigest[f.Digest] = map[string]int{}
		}
		openByDigest[f.Digest][f.Severity.String()]++
	}
	digests := map[string]bool{}
	for _, t := range targets {
		img := Image{
			Ref: t.Ref, Platform: t.Platform, Digest: t.CurrentDigest, MonitoredSince: t.CreatedAt,
			LastResolved: t.LastResolvedAt, DigestChanges: changes[t.ID], SBOMs: []SBOMInfo{}, Open: map[string]int{}, Gaps: []string{},
		}
		if err := fillEvidence(ctx, src, &img, opts); err != nil {
			return inv, fmt.Errorf("%s: %w", t.Ref, err)
		}
		for sev, n := range openByDigest[t.CurrentDigest] {
			img.Open[sev] = n
		}
		if t.CurrentDigest != "" && !digests[t.CurrentDigest] {
			digests[t.CurrentDigest] = true
			for sev, n := range img.Open {
				inv.Summary.Open[sev] += n
			}
		}
		if len(img.Gaps) > 0 {
			inv.Summary.WithGaps++
		}
		for _, g := range img.Gaps {
			inv.Summary.Gaps[g]++
		}
		inv.Images = append(inv.Images, img)
	}
	inv.Summary.Targets, inv.Summary.Digests = len(targets), len(digests)
	sort.SliceStable(inv.Images, func(i, j int) bool {
		a, b := inv.Images[i], inv.Images[j]
		if a.Ref != b.Ref {
			return a.Ref < b.Ref
		}
		return a.Platform < b.Platform
	})
	return inv, nil
}

// fillEvidence adds what the store knows about the image's current digest, and its gaps.
func fillEvidence(ctx context.Context, src InventorySource, img *Image, opts InventoryOptions) error {
	if img.Digest == "" {
		img.Gaps = append(img.Gaps, GapUnresolved)
		return nil
	}
	if a, err := src.GetArtifact(ctx, img.Digest); err == nil {
		img.Repository = a.Repository
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	sboms, err := src.SBOMs(ctx, img.Digest)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, b := range sboms {
		have[b.Generator] = true
		img.SBOMs = append(img.SBOMs, SBOMInfo{Generator: b.Generator, Version: b.GeneratorVersion, Format: b.Format, SHA256: b.SHA256, Size: b.Size})
	}
	slices.SortFunc(img.SBOMs, func(a, b SBOMInfo) int {
		return strings.Compare(a.Generator+"\x00"+a.Format, b.Generator+"\x00"+b.Format)
	})
	last, err := src.LatestScan(ctx, img.Digest)
	switch {
	case errors.Is(err, store.ErrNotFound):
		img.Gaps = append(img.Gaps, GapNoScan)
	case err != nil:
		return err
	default:
		img.LastScan = &ScanInfo{At: last.StartedAt, Kind: last.Kind, Status: last.Status, Tools: last.Tools}
		switch last.Status {
		case store.ScanPartial:
			img.Gaps = append(img.Gaps, GapPartial)
		case store.ScanFailed:
			img.Gaps = append(img.Gaps, GapFailed)
		}
	}
	complete, err := src.LatestCompleteScan(ctx, img.Digest)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if img.LastScan != nil && opts.StaleAfter > 0 {
			img.Gaps = append(img.Gaps, GapStale)
		}
	case err != nil:
		return err
	default:
		img.LastComplete = complete.StartedAt
		if opts.StaleAfter > 0 && opts.Now.Sub(complete.StartedAt) > opts.StaleAfter {
			img.Gaps = append(img.Gaps, GapStale)
		}
	}
	for _, g := range opts.Generators {
		if !have[g] {
			img.Gaps = append(img.Gaps, GapNoSBOM+":"+g)
		}
	}
	return nil
}

// InventoryFormat renders an inventory. Formats register themselves like report formats.
type InventoryFormat struct {
	Name        string
	Description string
	Render      func(io.Writer, Inventory) error
}

var inventoryFormats = map[string]InventoryFormat{}

// RegisterInventoryFormat makes an inventory format available. It panics on duplicates.
func RegisterInventoryFormat(f InventoryFormat) {
	if f.Name == "" || f.Render == nil {
		panic("report: RegisterInventoryFormat requires Name and Render")
	}
	if _, dup := inventoryFormats[f.Name]; dup {
		panic("report: duplicate inventory format " + f.Name)
	}
	inventoryFormats[f.Name] = f
}

// InventoryFormats returns the registered inventory formats sorted by name.
func InventoryFormats() []InventoryFormat {
	out := make([]InventoryFormat, 0, len(inventoryFormats))
	for _, f := range inventoryFormats {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RenderInventory writes the inventory in the named format.
func RenderInventory(w io.Writer, inv Inventory, format string) error {
	f, ok := inventoryFormats[format]
	if !ok {
		var names []string
		for _, f := range InventoryFormats() {
			names = append(names, f.Name)
		}
		return fmt.Errorf("unknown inventory format %q (supported: %s)", format, strings.Join(names, ", "))
	}
	return f.Render(w, inv)
}
