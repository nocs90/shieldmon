package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

// KEVURL is the CISA Known Exploited Vulnerabilities catalog (JSON feed).
const KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// Bounds of a catalog: it holds about 1,500 entries in 1.5 MB.
const (
	kevMaxBytes   = 32 << 20
	kevMaxEntries = 200_000
	kevTimeout    = 2 * time.Minute
)

var cveRE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)

func init() {
	Register(Plugin{
		Name:        "kev",
		Description: "CISA Known Exploited Vulnerabilities catalog: marks findings in KEV whatever the scanner reports",
		Options:     []string{"url", "file"},
		Default:     true,
		New:         newKEV,
	})
}

// KEVEntry is what the catalog says about one CVE.
type KEVEntry struct {
	Added      string `json:"added"`
	Due        string `json:"due,omitempty"`
	Ransomware bool   `json:"ransomware,omitempty"`
}

// kevCache is the catalog as kept on disk: validated entries only, with what conditional
// requests need.
type kevCache struct {
	Version      string              `json:"catalog_version"`
	Released     string              `json:"date_released"`
	ConfirmedAt  time.Time           `json:"confirmed_at"`
	ETag         string              `json:"etag,omitempty"`
	LastModified string              `json:"last_modified,omitempty"`
	Entries      map[string]KEVEntry `json:"entries"`
}

type kev struct {
	url    *url.URL
	file   string
	path   string
	client *http.Client
	now    func() time.Time

	mu    sync.RWMutex
	cache kevCache
}

func newKEV(s Spec) (Enricher, error) {
	k := &kev{path: filepath.Join(s.CacheDir, "kev.json"), now: s.now}
	var err error
	if k.file, err = s.String("file", ""); err != nil {
		return nil, err
	}
	raw, err := s.String("url", KEVURL)
	if err != nil {
		return nil, err
	}
	if k.file == "" {
		if k.url, err = url.Parse(raw); err != nil || k.url.Scheme != "https" || k.url.Host == "" || k.url.User != nil {
			return nil, errors.New("option url: want an https URL without credentials (file: for a local copy)")
		}
	}
	k.client = &http.Client{
		Transport: s.Transport,
		Timeout:   kevTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Scheme != "https" {
				return errors.New("redirect refused: at most 3, https only")
			}
			return nil
		},
	}
	// A missing or unreadable cache is no data yet: Update fetches it.
	if b, err := os.ReadFile(k.path); err == nil && len(b) <= kevMaxBytes {
		var c kevCache
		if json.Unmarshal(b, &c) == nil && c.Entries != nil {
			k.cache = c
		}
	}
	return k, nil
}

func (k *kev) UpdatedAt() time.Time {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.cache.ConfirmedAt
}

func (k *kev) Enrich(m *model.Match) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if m.KEV {
		return
	}
	for _, id := range append([]string{m.VulnID}, m.Aliases...) {
		if _, ok := k.cache.Entries[id]; ok {
			m.KEV = true
			return
		}
	}
}

func (k *kev) Update(ctx context.Context) error {
	k.mu.RLock()
	prev := k.cache
	k.mu.RUnlock()
	data, etag, modified, notModified, err := k.fetch(ctx, prev)
	if err != nil {
		return err
	}
	next := prev
	if !notModified {
		if next, err = parseKEV(data, len(prev.Entries)); err != nil {
			return err
		}
		next.ETag, next.LastModified = etag, modified
	}
	next.ConfirmedAt = k.now()
	if err := writeAtomic(k.path, next); err != nil {
		return err
	}
	k.mu.Lock()
	k.cache = next
	k.mu.Unlock()
	return nil
}

// fetch reads the catalog from the file option, or from the URL with a conditional request.
func (k *kev) fetch(ctx context.Context, prev kevCache) (data []byte, etag, modified string, notModified bool, err error) {
	if k.file != "" {
		f, err := os.Open(k.file)
		if err != nil {
			return nil, "", "", false, err
		}
		defer f.Close()
		data, err = readBounded(f)
		return data, "", "", false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url.String(), nil)
	if err != nil {
		return nil, "", "", false, err
	}
	req.Header.Set("User-Agent", "shieldmon")
	if len(prev.Entries) > 0 {
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
		}
		if prev.LastModified != "" {
			req.Header.Set("If-Modified-Since", prev.LastModified)
		}
	}
	resp, err := k.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "", "", false, ctx.Err()
		}
		return nil, "", "", false, fmt.Errorf("GET %s: connection failed", k.url.Host)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && len(prev.Entries) > 0:
		return nil, "", "", true, nil
	case resp.StatusCode != http.StatusOK:
		return nil, "", "", false, fmt.Errorf("GET %s: answered %s", k.url.Host, resp.Status)
	}
	data, err = readBounded(resp.Body)
	return data, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), false, err
}

func readBounded(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, kevMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > kevMaxBytes {
		return nil, fmt.Errorf("catalog larger than %d bytes", kevMaxBytes)
	}
	return data, nil
}

// parseKEV validates a catalog. Entries with a malformed CVE ID are dropped, but a catalog
// with more than 10% of them, or with fewer than half the entries already known (KEV entries
// are almost never removed: a short catalog is truncated or not the real one), is refused.
func parseKEV(data []byte, known int) (kevCache, error) {
	var doc struct {
		Title    string `json:"title"`
		Version  string `json:"catalogVersion"`
		Released string `json:"dateReleased"`
		Count    *int   `json:"count"`
		Vulns    []struct {
			CVE        string `json:"cveID"`
			Added      string `json:"dateAdded"`
			Due        string `json:"dueDate"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return kevCache{}, fmt.Errorf("not a KEV catalog: %w", err)
	}
	switch {
	case len(doc.Vulns) == 0:
		return kevCache{}, errors.New("not a KEV catalog: no vulnerabilities")
	case len(doc.Vulns) > kevMaxEntries:
		return kevCache{}, fmt.Errorf("catalog with more than %d entries", kevMaxEntries)
	case doc.Count != nil && *doc.Count != len(doc.Vulns):
		return kevCache{}, fmt.Errorf("catalog says %d entries and holds %d: truncated", *doc.Count, len(doc.Vulns))
	}
	c := kevCache{Version: clip(doc.Version), Released: clip(doc.Released), Entries: make(map[string]KEVEntry, len(doc.Vulns))}
	bad := 0
	for _, v := range doc.Vulns {
		if !cveRE.MatchString(v.CVE) || !isDate(v.Added) || (v.Due != "" && !isDate(v.Due)) {
			bad++
			continue
		}
		c.Entries[v.CVE] = KEVEntry{Added: v.Added, Due: v.Due, Ransomware: v.Ransomware == "Known"}
	}
	if bad*10 > len(doc.Vulns) {
		return kevCache{}, fmt.Errorf("%d of %d entries malformed", bad, len(doc.Vulns))
	}
	if known > 0 && len(c.Entries)*2 < known {
		return kevCache{}, fmt.Errorf("catalog has %d entries, %d were known: refusing a catalog that lost more than half", len(c.Entries), known)
	}
	return c, nil
}

func isDate(s string) bool {
	_, err := time.Parse(time.DateOnly, s)
	return err == nil
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// writeAtomic writes v as JSON next to path and renames it into place, owner-only.
func writeAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kev-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // gone after the rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
