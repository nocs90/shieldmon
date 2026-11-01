package charts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

func init() {
	Register(Plugin{
		Name:        "http",
		Description: "Helm chart repository over HTTPS (index.yaml)",
		Options:     []string{"url"},
		New: func(s Spec) (Source, error) {
			raw, err := s.Options.String("url", "")
			if err != nil {
				return nil, err
			}
			var u *url.URL
			if s.Derived {
				u, err = derivedURL(raw)
				if err != nil {
					err = fmt.Errorf("repository URL %q: %w", truncate(raw), err)
				}
			} else {
				u, err = parseURL("url", raw)
			}
			if err != nil {
				return nil, err
			}
			h := &httpSource{base: u, client: s.Client, public: s.Public, derived: s.Derived, oci: s.OCI}
			if h.public == nil {
				h.public = PublicClient()
			}
			if s.Derived {
				h.client = h.public
			}
			return h, nil
		},
	})
}

// parseURL accepts https, or http to a loopback address (a local mirror), never with
// credentials in it. It is for URLs from the configuration only.
func parseURL(key, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("option %s: not an absolute URL", key)
	}
	if u.User != nil {
		return nil, fmt.Errorf("option %s: credentials do not belong in the URL", key)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if loopback(u) {
			return u, nil
		}
	}
	return nil, fmt.Errorf("option %s: want an https URL (http only to localhost)", key)
}

func loopback(u *url.URL) bool {
	ip := net.ParseIP(u.Hostname())
	return u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
}

type httpSource struct {
	base *url.URL
	// client reaches the repository the configuration names; public reaches anything remote
	// content names (archives on other hosts).
	client, public *http.Client
	// derived marks a repository named by remote content (Artifact Hub), reached like one.
	derived bool
	// oci fetches archives the index places in a registry (oci:// URLs, as Bitnami's does).
	oci OCI

	mu      sync.Mutex
	cached  map[string][]indexEntry
	fetched time.Time
}

type indexEntry struct {
	Version    string    `yaml:"version"`
	AppVersion string    `yaml:"appVersion"`
	Created    time.Time `yaml:"created"`
	Digest     string    `yaml:"digest"`
	URLs       []string  `yaml:"urls"`
	Deprecated bool      `yaml:"deprecated"`
}

// maxIndexEntries bounds the entries of one chart in an index before they are sorted.
const maxIndexEntries = 10 * MaxVersions

func (h *httpSource) Location(chart string) string { return h.base.String() + " " + chart }

// index reads the repository's index once per minute at most: listing then fetching does not
// download it twice.
func (h *httpSource) index(ctx context.Context, chart string) ([]indexEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cached == nil || time.Since(h.fetched) > time.Minute {
		u := h.base.JoinPath("index.yaml")
		data, err := get(ctx, h.client, u, MaxIndexBytes, nil)
		if err != nil {
			return nil, err
		}
		var idx struct {
			Entries map[string][]indexEntry `yaml:"entries"`
		}
		if err := yaml.Unmarshal(data, &idx); err != nil {
			return nil, fmt.Errorf("%s: index: %w", u.Host, err)
		}
		h.cached, h.fetched = idx.Entries, time.Now()
	}
	entries, ok := h.cached[chart]
	if !ok {
		return nil, fmt.Errorf("%s: no chart %q in the index", h.base.Host, truncate(chart))
	}
	if len(entries) > maxIndexEntries {
		return nil, fmt.Errorf("%s: chart %q has %d entries in the index, more than %d", h.base.Host, truncate(chart), len(entries), maxIndexEntries)
	}
	valid := make([]indexEntry, 0, len(entries))
	for _, e := range entries {
		if validVersion(e.Version) {
			valid = append(valid, e)
		}
	}
	sortByVersion(valid, func(e indexEntry) string { return e.Version })
	return valid[:min(len(valid), MaxVersions)], nil
}

func (h *httpSource) Versions(ctx context.Context, chart string) ([]Version, error) {
	es, err := h.index(ctx, chart)
	if err != nil {
		return nil, err
	}
	out := make([]Version, 0, len(es))
	for _, e := range es {
		v := Version{Version: e.Version, AppVersion: truncate(e.AppVersion), Created: e.Created.UTC(), Deprecated: e.Deprecated}
		if d, ok := sha256Digest(e.Digest); ok {
			v.Digest = d
		}
		out = append(out, v)
	}
	return out, nil
}

func (h *httpSource) Fetch(ctx context.Context, chart, version string, w io.Writer) (string, error) {
	es, err := h.index(ctx, chart)
	if err != nil {
		return "", err
	}
	for _, e := range es {
		if e.Version != version {
			continue
		}
		what := truncate(chart) + " " + truncate(version)
		if len(e.URLs) == 0 {
			return "", fmt.Errorf("%s: the index names no archive", what)
		}
		want, hasDigest := sha256Digest(e.Digest)
		if strings.TrimSpace(e.Digest) != "" && !hasDigest {
			return "", fmt.Errorf("%s: the index's digest %q is not a SHA-256: refusing to fetch unverified", what, truncate(e.Digest))
		}
		hash := sha256.New()
		if ref, isOCI := strings.CutPrefix(e.URLs[0], "oci://"); isOCI {
			if h.oci == nil {
				return "", fmt.Errorf("%s: the index places the archive in a registry, and no registry access is configured", what)
			}
			if !publicHost(strings.SplitN(ref, "/", 2)[0]) {
				return "", fmt.Errorf("%s: archive registry: %w", what, ErrNotPublic)
			}
			if _, err := h.oci.Fetch(ctx, ref, MaxArchiveBytes, io.MultiWriter(w, hash)); err != nil {
				return "", err
			}
		} else {
			u, client, err := h.archiveURL(e.URLs[0])
			if err != nil {
				return "", fmt.Errorf("%s: archive URL: %w", what, err)
			}
			if _, err := get(ctx, client, u, MaxArchiveBytes, io.MultiWriter(w, hash)); err != nil {
				return "", err
			}
		}
		got := "sha256:" + hex.EncodeToString(hash.Sum(nil))
		if hasDigest && want != got {
			return "", fmt.Errorf("%s: archive digest %s, the index says %s", what, got, want)
		}
		return got, nil
	}
	return "", fmt.Errorf("%s: no version %q in the index", truncate(chart), truncate(version))
}

// archiveURL resolves an index's archive URL, relative to the repository as a directory as
// Helm does, and says which client may fetch it: on the repository's own host, the one the
// configuration trusts; anywhere else, only an https URL to a public address.
func (h *httpSource) archiveURL(raw string) (*url.URL, *http.Client, error) {
	ref, err := url.Parse(raw)
	if err != nil {
		return nil, nil, errors.New("not a URL")
	}
	dir := *h.base
	if !strings.HasSuffix(dir.Path, "/") {
		dir.Path += "/"
	}
	u := dir.ResolveReference(ref)
	if u.User != nil {
		return nil, nil, errors.New("credentials do not belong in the URL")
	}
	if u.Host == h.base.Host && u.Scheme == h.base.Scheme {
		return u, h.client, nil
	}
	if u, err = derivedURL(u.String()); err != nil {
		return nil, nil, err
	}
	return u, h.public, nil
}

func sha256Digest(s string) (string, bool) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "sha256:")
	if len(s) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", false
	}
	return "sha256:" + s, true
}

// errTooLarge marks a body over its limit.
var errTooLarge = errors.New("response larger than allowed")

// get fetches u, at most limit bytes: into w when given, else returned. Errors name the host
// and the status code only: a reason phrase or URL could carry anything.
func get(ctx context.Context, c *http.Client, u *url.URL, limit int64, w io.Writer) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("GET %s: invalid request", u.Host)
	}
	req.Header.Set("User-Agent", "shieldmon")
	resp, err := c.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // without the URL
		}
		return nil, fmt.Errorf("GET %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %d %s", u.Host, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("GET %s: %w (%d > %d bytes)", u.Host, errTooLarge, resp.ContentLength, limit)
	}
	body := io.LimitReader(resp.Body, limit+1)
	if w == nil {
		data, err := io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", u.Host, err)
		}
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("GET %s: %w (> %d bytes)", u.Host, errTooLarge, limit)
		}
		return data, nil
	}
	n, err := io.Copy(w, body)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u.Host, err)
	}
	if n > limit {
		return nil, fmt.Errorf("GET %s: %w (> %d bytes)", u.Host, errTooLarge, limit)
	}
	return nil, nil
}

// truncate bounds a name taken from a source for messages.
func truncate(s string) string {
	if len(s) <= 120 {
		return s
	}
	r := []rune(s)
	if len(r) > 120 {
		r = r[:120]
	}
	return string(r) + "…"
}
