package vex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// OpenVEXContext is the version ShieldMon reads and writes.
const OpenVEXContext = "https://openvex.dev/ns/v0.2.0"

type ovDocument struct {
	Context    string        `json:"@context"`
	ID         string        `json:"@id"`
	Author     string        `json:"author"`
	Role       string        `json:"role,omitempty"`
	Timestamp  string        `json:"timestamp"`
	Version    int           `json:"version"`
	Tooling    string        `json:"tooling,omitempty"`
	Statements []ovStatement `json:"statements"`
}

type ovStatement struct {
	Vulnerability ovVulnerability `json:"vulnerability"`
	Timestamp     string          `json:"timestamp,omitempty"`
	Products      []ovProduct     `json:"products,omitempty"`
	Status        string          `json:"status"`
	StatusNotes   string          `json:"status_notes,omitempty"`
	Justification string          `json:"justification,omitempty"`
	Impact        string          `json:"impact_statement,omitempty"`
}

type ovVulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type ovProduct struct {
	ID            string      `json:"@id"`
	Identifiers   *ovIDs      `json:"identifiers,omitempty"`
	Subcomponents []ovProduct `json:"subcomponents,omitempty"`
}

type ovIDs struct {
	PURL string `json:"purl,omitempty"`
}

func (p ovProduct) id() string {
	if p.ID != "" {
		return p.ID
	}
	if p.Identifiers != nil {
		return p.Identifiers.PURL
	}
	return ""
}

func parseOpenVEX(data []byte, author string, now time.Time) ([]Statement, []Skipped, error) {
	var doc ovDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("OpenVEX: %w", err)
	}
	if doc.Context != OpenVEXContext {
		return nil, nil, fmt.Errorf("OpenVEX: unsupported @context %q (want %s)", short(doc.Context), OpenVEXContext)
	}
	if len(doc.Statements) > MaxStatements {
		return nil, nil, fmt.Errorf("OpenVEX: more than %d statements", MaxStatements)
	}
	if doc.Author != "" {
		author = doc.Author
	}
	docTime, _ := time.Parse(time.RFC3339, doc.Timestamp)
	var out []Statement
	var skipped []Skipped
	for _, st := range doc.Statements {
		id, err := vulnID(st.Vulnerability.Name)
		if err != nil {
			skipped = append(skipped, Skipped{short(st.Vulnerability.Name), err.Error()})
			continue
		}
		if st.Status != "not_affected" {
			skipped = append(skipped, Skipped{id, "status " + short(st.Status) + ": only not_affected is recorded"})
			continue
		}
		base, err := ovBase(st, id, author, docTime, doc.ID)
		if err != nil {
			skipped = append(skipped, Skipped{id, err.Error()})
			continue
		}
		if len(st.Products) == 0 {
			skipped = append(skipped, Skipped{id, "no product"})
			continue
		}
		for _, p := range st.Products {
			digest, repo, err := product(p.id())
			if err != nil {
				skipped = append(skipped, Skipped{id, err.Error()})
				continue
			}
			s := base
			s.Digest, s.Repository = digest, repo
			if len(p.Subcomponents) == 0 {
				finish(s, now, &out, &skipped)
				continue
			}
			for _, sub := range p.Subcomponents {
				purl, anyVersion, err := pkgPURL(sub.id())
				if err != nil {
					skipped = append(skipped, Skipped{id, err.Error()})
					continue
				}
				ss := s
				ss.PURL, ss.AnyVersion = purl, anyVersion
				finish(ss, now, &out, &skipped)
			}
		}
	}
	return out, skipped, nil
}

func ovBase(st ovStatement, id, author string, docTime time.Time, source string) (Statement, error) {
	s := Statement{VulnID: id, Aliases: aliases(id, st.Vulnerability.Aliases), Author: author, Source: short(source)}
	if st.Justification != "" && !slices.Contains(Justifications, st.Justification) {
		return s, fmt.Errorf("unknown justification %q", short(st.Justification))
	}
	s.Justification = st.Justification
	var err error
	if s.Impact, err = text(st.Impact); err != nil {
		return s, err
	}
	notes, err := text(st.StatusNotes)
	if err != nil {
		return s, err
	}
	var noted string
	if s.Notes, s.ExpiresAt, noted, err = splitNotes(notes); err != nil {
		return s, err
	}
	if noted != "" {
		s.Author = noted
	}
	s.Timestamp = docTime
	if t, err := time.Parse(time.RFC3339, st.Timestamp); err == nil {
		s.Timestamp = t
	}
	s.Timestamp = s.Timestamp.UTC()
	return s, nil
}

// Document is an OpenVEX document to export.
type Document struct {
	Author     string
	Tooling    string
	Timestamp  time.Time
	Statements []Statement
}

// OpenVEX encodes doc as an OpenVEX 0.2.0 document: one statement per product and package,
// in a stable order, so that its import gives back the same statements.
func OpenVEX(doc Document) ([]byte, error) {
	stmts := slices.Clone(doc.Statements)
	slices.SortFunc(stmts, func(a, b Statement) int {
		return strings.Compare(a.VulnID+"\x00"+a.Repository+"\x00"+a.Digest+"\x00"+a.PURL+"\x00"+a.Key(),
			b.VulnID+"\x00"+b.Repository+"\x00"+b.Digest+"\x00"+b.PURL+"\x00"+b.Key())
	})
	out := ovDocument{
		Context: OpenVEXContext, Author: doc.Author, Timestamp: doc.Timestamp.UTC().Format(time.RFC3339),
		Version: 1, Tooling: doc.Tooling, Statements: []ovStatement{},
	}
	ids := sha256.New()
	for _, s := range stmts {
		p := ovProduct{ID: ProductPURL(s.Digest, s.Repository)}
		if s.PURL != "" {
			p.Subcomponents = []ovProduct{{ID: s.PURL}}
		}
		out.Statements = append(out.Statements, ovStatement{
			Vulnerability: ovVulnerability{Name: s.VulnID, Aliases: s.Aliases},
			Timestamp:     s.Timestamp.UTC().Format(time.RFC3339),
			Products:      []ovProduct{p},
			Status:        "not_affected",
			StatusNotes:   joinNotes(s.Notes, s.ExpiresAt, s.Author, doc.Author),
			Justification: s.Justification,
			Impact:        s.Impact,
		})
		ids.Write([]byte(s.Key()))
	}
	// The identifier names the content, so exporting the same statements twice gives the
	// same document.
	out.ID = "urn:shieldmon:vex:" + hex.EncodeToString(ids.Sum(nil))[:32]
	return json.MarshalIndent(out, "", "  ")
}
