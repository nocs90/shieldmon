// Package lineage says what an image is built on and whether that base is current, from
// recorded layers and observations (docs/adr/0022-base-image-lineage.md). It is pure: the
// caller loads the records and passes the time in.
package lineage

import (
	"slices"
	"time"
)

// Status of an image against the newest digest of its base reference.
type Status string

// Statuses (ADR 0022).
const (
	// Current: the newest digest of the base reference is a layer prefix of the image.
	Current Status = "current"
	// RebuildAvailable: an older digest of the base is the prefix; the reference has moved.
	RebuildAvailable Status = "rebuild_available"
	// Unknown: a base reference is known but no observed or verified digest is a prefix.
	Unknown Status = "unknown"
	// None: no base reference is configured or annotated.
	None Status = "none"
)

// Sources of a base reference, in order of trust.
const (
	SourceConfigured = "configured"
	SourceAnnotation = "annotation"
)

// Image is what is known of an image.
type Image struct {
	DiffIDs []string
	// BaseRef is the base reference (configured, else annotated) and Source where it comes from.
	BaseRef string
	Source  string
	// VerifiedDigest is the annotated base digest when its layers were verified as a prefix of
	// the image's and it is in the repository of BaseRef; VerifiedLayers how many (0: unknown).
	VerifiedDigest string
	VerifiedLayers int
}

// Observation is a digest the base reference pointed to, from ObservedAt on.
type Observation struct {
	Digest     string
	DiffIDs    []string
	Created    time.Time
	ObservedAt time.Time
}

// Result is the lineage of an image.
type Result struct {
	BaseRef string `json:"base_ref,omitempty"`
	Source  string `json:"base_source,omitempty"`
	Status  Status `json:"status"`
	// BaseDigest is the digest proven to be the image's base by its layers, BaseLayers how many
	// of the image's first layers it provides (0: unknown).
	BaseDigest string `json:"base_digest,omitempty"`
	BaseLayers int    `json:"base_layers,omitempty"`
	// Newest is the digest the base reference points to now, and Since since when it does:
	// observed by ShieldMon, or the base's creation time when it was never seen moving.
	Newest       string    `json:"newest_base_digest,omitempty"`
	Since        time.Time `json:"newest_base_since,omitzero"`
	SinceSource  string    `json:"newest_base_since_source,omitempty"`
	Unmaintained bool      `json:"base_unmaintained"`
}

// plausibleFrom is the earliest creation time taken at face value: reproducible builds set
// the epoch.
var plausibleFrom = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// Evaluate gives the lineage of img against the observations of its base reference (on its
// platform, oldest first). A base unchanged for longer than maxAge is unmaintained (0: never).
func Evaluate(img Image, obs []Observation, maxAge time.Duration, now time.Time) Result {
	r := Result{BaseRef: img.BaseRef, Source: img.Source, Status: None}
	if img.BaseRef == "" {
		return r
	}
	r.Status = Unknown
	if len(obs) == 0 {
		return r
	}
	newest := obs[len(obs)-1]
	r.Newest = newest.Digest
	r.Since, r.SinceSource = newest.ObservedAt, "observed"
	if len(obs) == 1 && newest.Created.After(plausibleFrom) && !newest.Created.After(now) {
		r.Since, r.SinceSource = newest.Created, "created"
	}
	r.Unmaintained = maxAge > 0 && now.Sub(r.Since) > maxAge

	switch {
	case IsPrefix(newest.DiffIDs, img.DiffIDs):
		r.Status, r.BaseDigest, r.BaseLayers = Current, newest.Digest, len(newest.DiffIDs)
		return r
	case img.VerifiedDigest != "" && img.VerifiedDigest != newest.Digest:
		r.Status, r.BaseDigest, r.BaseLayers = RebuildAvailable, img.VerifiedDigest, img.VerifiedLayers
		return r
	}
	for i := len(obs) - 2; i >= 0; i-- {
		if IsPrefix(obs[i].DiffIDs, img.DiffIDs) {
			r.Status, r.BaseDigest, r.BaseLayers = RebuildAvailable, obs[i].Digest, len(obs[i].DiffIDs)
			return r
		}
	}
	return r
}

// IsPrefix reports whether base's layers are the first layers of img. A base without layers
// proves nothing.
func IsPrefix(base, img []string) bool {
	return len(base) > 0 && len(base) <= len(img) && slices.Equal(base, img[:len(base)])
}
