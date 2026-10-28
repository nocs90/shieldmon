// Package vex reads and writes VEX documents (docs/adr/0014-vex.md): OpenVEX 0.2.0 and
// CycloneDX VEX in, OpenVEX out. Documents are hostile input (I7): sizes and counts are
// bounded and every identifier is validated. The package is pure: storing and applying
// statements is the store's and the engine's job.
package vex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/package-url/packageurl-go"

	"github.com/nocs90/shieldmon/internal/normalize"
)

// Bounds on an imported document.
const (
	MaxDocumentBytes = 16 << 20
	MaxStatements    = 100_000
	maxFieldLen      = 4096
)

// Justifications are OpenVEX's not_affected justifications.
var Justifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// Statement is one not_affected statement, normalized. The product is an image digest, or a
// repository (every digest of it) when Digest is empty.
type Statement struct {
	VulnID     string
	Aliases    []string // canonical, sorted, without VulnID
	Digest     string   // sha256:…
	Repository string   // registry/path, normalized like ShieldMon's targets
	// PURL is the canonical package URL; empty applies to every package. AnyVersion means
	// it was given without a version and applies to every version.
	PURL          string
	AnyVersion    bool
	Justification string // one of Justifications, or "" when Impact says why
	Impact        string
	Notes         string // status_notes without the expiry line
	Author        string
	Timestamp     time.Time
	ExpiresAt     time.Time
	Source        string // the document's @id
}

// Key identifies a statement regardless of the document it came in, so that importing the
// same statement twice (or an export of it) stores it once.
func (s Statement) Key() string {
	h := sha256.New()
	for _, f := range []string{
		s.VulnID, strings.Join(s.Aliases, ","), s.Digest, s.Repository, s.PURL, fmt.Sprint(s.AnyVersion),
		s.Justification, s.Impact, s.Notes, s.Author, s.Timestamp.UTC().Format(time.RFC3339), expiry(s.ExpiresAt),
	} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func expiry(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Reason is the justification text of the decision a statement records.
func (s Statement) Reason() string {
	switch {
	case s.Justification != "" && s.Impact != "":
		return s.Justification + ": " + s.Impact
	case s.Justification != "":
		return s.Justification
	}
	return s.Impact
}

// SplitReason reads a decision's justification text back: an OpenVEX justification, alone
// or followed by ": " and an impact statement, or else free text, which is the impact.
func SplitReason(reason string) (justification, impact string) {
	reason = strings.TrimSpace(reason)
	for _, j := range Justifications {
		if reason == j {
			return j, ""
		}
		if rest, ok := strings.CutPrefix(reason, j+": "); ok {
			return j, strings.TrimSpace(rest)
		}
	}
	return "", reason
}

// InForce reports whether the statement applies at now.
func (s Statement) InForce(now time.Time) bool { return s.ExpiresAt.IsZero() || s.ExpiresAt.After(now) }

// Finding is what a statement is matched against.
type Finding struct {
	Digest     string
	Repository string
	PURL       string
	PkgKey     string
	VulnID     string
	Aliases    []string
}

// Matches reports whether s covers f: same product, package (any version when the statement
// gave none) and vulnerability, aliases included.
func (s Statement) Matches(f Finding) bool {
	if s.Digest != "" {
		if s.Digest != f.Digest {
			return false
		}
	} else if s.Repository == "" || s.Repository != f.Repository {
		return false
	}
	switch {
	case s.PURL == "":
	case s.AnyVersion:
		if s.PURL != f.PkgKey {
			return false
		}
	default:
		if s.PURL != f.PURL {
			return false
		}
	}
	ids := append([]string{s.VulnID}, s.Aliases...)
	return slices.Contains(ids, f.VulnID) || slices.ContainsFunc(f.Aliases, func(a string) bool { return slices.Contains(ids, a) })
}

// Skipped is a statement that was read but not imported, and why: nothing is dropped
// silently.
type Skipped struct {
	VulnID string
	Reason string
}

// ErrNotVEX is returned for a document that is neither OpenVEX nor CycloneDX VEX.
var ErrNotVEX = errors.New("not an OpenVEX or CycloneDX VEX document")

// Parse reads an OpenVEX or CycloneDX VEX document. author applies to statements whose
// document names none; statements whose expiry is not after now are skipped.
func Parse(data []byte, author string, now time.Time) ([]Statement, []Skipped, error) {
	if len(data) > MaxDocumentBytes {
		return nil, nil, fmt.Errorf("VEX document larger than %d bytes", MaxDocumentBytes)
	}
	var probe struct {
		Context   json.RawMessage `json:"@context"`
		BOMFormat string          `json:"bomFormat"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrNotVEX, err)
	}
	switch {
	case bytes.Contains(probe.Context, []byte("openvex")):
		return parseOpenVEX(data, author, now)
	case probe.BOMFormat == "CycloneDX":
		return parseCycloneDX(data, author, now)
	}
	return nil, nil, ErrNotVEX
}

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// product parses a product identifier: a pkg:oci PURL (digest as version, repository_url
// qualifier), an image reference with a digest, or a bare digest.
func product(id string) (digest, repository string, err error) {
	id = strings.TrimSpace(id)
	switch {
	case digestRE.MatchString(id):
		return id, "", nil
	case strings.HasPrefix(id, "pkg:oci/"):
		p, err := packageurl.FromString(id)
		if err != nil {
			return "", "", fmt.Errorf("product %q: %w", short(id), err)
		}
		if p.Version != "" {
			if !digestRE.MatchString(p.Version) {
				return "", "", fmt.Errorf("product %q: version is not a sha256 digest", short(id))
			}
			digest = p.Version
		}
		if repo := p.Qualifiers.Map()["repository_url"]; repo != "" {
			r, err := name.NewRepository(repo, name.StrictValidation)
			if err != nil {
				return "", "", fmt.Errorf("product %q: repository_url: %w", short(id), err)
			}
			repository = r.Name()
		}
		if digest == "" && repository == "" {
			return "", "", fmt.Errorf("product %q names neither a digest nor a repository_url", short(id))
		}
		return digest, repository, nil
	case strings.Contains(id, "@sha256:"):
		ref, err := name.NewDigest(id, name.StrictValidation)
		if err != nil {
			return "", "", fmt.Errorf("product %q: %w", short(id), err)
		}
		return ref.DigestStr(), ref.Context().Name(), nil
	}
	return "", "", fmt.Errorf("product %q is not an image digest, digest reference or pkg:oci PURL", short(id))
}

// ProductPURL is the pkg:oci identifier of an image digest in repository, or of the whole
// repository when digest is empty.
func ProductPURL(digest, repository string) string {
	nm := repository
	if i := strings.LastIndex(repository, "/"); i >= 0 {
		nm = repository[i+1:]
	}
	var q packageurl.Qualifiers
	if repository != "" {
		q = packageurl.QualifiersFromMap(map[string]string{"repository_url": repository})
	}
	if nm == "" {
		nm = "image"
	}
	return packageurl.NewPackageURL("oci", "", nm, digest, q, "").ToString()
}

// pkgPURL canonicalizes a package PURL; anyVersion when it has no version.
func pkgPURL(raw string) (purl string, anyVersion bool, err error) {
	p, err := packageurl.FromString(strings.TrimSpace(raw))
	if err != nil || p.Name == "" {
		return "", false, fmt.Errorf("package %q is not a PURL", short(raw))
	}
	canonical, key := normalize.CanonicalPURL(raw, "", "", "")
	if p.Version == "" {
		return key, true, nil
	}
	return canonical, false, nil
}

func vulnID(id string) (string, error) {
	id = normalize.CanonicalVulnID(id)
	if id == "" || len(id) > 256 || strings.ContainsAny(id, " \t\r\n") {
		return "", fmt.Errorf("vulnerability %q is not an identifier", short(id))
	}
	return id, nil
}

func aliases(main string, raw []string) []string {
	var out []string
	for _, a := range raw {
		if id, err := vulnID(a); err == nil && id != main && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// text bounds a free-text field.
func text(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxFieldLen {
		return "", fmt.Errorf("field longer than %d bytes", maxFieldLen)
	}
	return s, nil
}

func short(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// OpenVEX statements have neither an expiry nor an author of their own (the document has
// one) and allow no extra property, so ShieldMon keeps both as lines of status_notes, which
// it writes and reads (docs/adr/0014-vex.md).
const (
	expiryLine = "expires: "
	authorLine = "author: "
)

// splitNotes separates ShieldMon's lines from the rest of status_notes.
func splitNotes(notes string) (rest string, exp time.Time, author string, err error) {
	var kept []string
	for _, line := range strings.Split(notes, "\n") {
		trimmed := strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(trimmed, expiryLine); ok {
			t, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
			if err != nil {
				return "", time.Time{}, "", fmt.Errorf("status_notes: %w", err)
			}
			exp = t.UTC()
			continue
		}
		if v, ok := strings.CutPrefix(trimmed, authorLine); ok {
			author = strings.TrimSpace(v)
			continue
		}
		kept = append(kept, line)
	}
	return strings.TrimSpace(strings.Join(kept, "\n")), exp, author, nil
}

// joinNotes writes the expiry, and the author when it is not the document's.
func joinNotes(notes string, exp time.Time, author, docAuthor string) string {
	lines := []string{}
	if notes != "" {
		lines = append(lines, notes)
	}
	if author != "" && author != docAuthor {
		lines = append(lines, authorLine+author)
	}
	if !exp.IsZero() {
		lines = append(lines, expiryLine+exp.UTC().Format(time.RFC3339))
	}
	return strings.Join(lines, "\n")
}

// finish validates what every format shares and appends the statement or a skip.
func finish(s Statement, now time.Time, out *[]Statement, skipped *[]Skipped) {
	switch {
	case s.Author == "":
		*skipped = append(*skipped, Skipped{s.VulnID, "no author (the document names none; give --author)"})
	case len(s.Reason()) < 10:
		*skipped = append(*skipped, Skipped{s.VulnID, "no justification or impact statement"})
	case !s.InForce(now):
		*skipped = append(*skipped, Skipped{s.VulnID, "expired on " + s.ExpiresAt.Format(time.DateOnly)})
	case len(*out) >= MaxStatements:
		*skipped = append(*skipped, Skipped{s.VulnID, fmt.Sprintf("more than %d statements", MaxStatements)})
	default:
		*out = append(*out, s)
	}
}
