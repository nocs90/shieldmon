package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// maxResponseBytes bounds what is read of an endpoint's answer (and then discarded).
const maxResponseBytes = 64 << 10

// HTTPClient is the client HTTP notifiers use: it follows no redirect (one would carry the
// signature or token to another host), and times out.
func HTTPClient(s Spec) *http.Client {
	return &http.Client{
		Transport: s.Transport,
		Timeout:   SendTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ParseURL validates an endpoint URL option: https, or http to a loopback address only (a
// local relay). It never holds credentials: user info is refused.
func ParseURL(key, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("option %s: not an absolute URL", key)
	}
	if u.User != nil {
		return nil, fmt.Errorf("option %s: credentials do not belong in the URL: name an environment variable", key)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()) {
			return u, nil
		}
	}
	return nil, fmt.Errorf("option %s: want an https URL (http only to localhost)", key)
}

// Post sends body to u with the given headers and checks the answer is 2xx. Errors name the
// host and status only: the URL path may be a credential (chat webhooks) and an answer may
// echo the request.
func Post(ctx context.Context, c *http.Client, u *url.URL, contentType string, body []byte, header http.Header) error {
	return Request(ctx, c, http.MethodPost, u, contentType, body, header)
}

// Request is Post with another method.
func Request(ctx context.Context, c *http.Client, method string, u *url.URL, contentType string, body []byte, header http.Header) error {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s %s: invalid request", method, u.Host)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "shieldmon")
	return Do(c, req)
}

// Do sends req and checks the answer is 2xx, with the error discipline of Post.
func Do(c *http.Client, req *http.Request) error {
	_, _, err := DoRead(c, req, 0)
	return err
}

// DoRead is Do returning up to limit bytes of the answer's body (0: discard it) and its
// headers.
func DoRead(c *http.Client, req *http.Request, limit int64) ([]byte, http.Header, error) {
	resp, err := c.Do(req) //nolint:gosec // G704: the endpoint is the operator's configured URL (ParseURL), not request input
	if err != nil {
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return nil, nil, fmt.Errorf("%s %s: %w", req.Method, req.URL.Host, ctxErr)
		}
		return nil, nil, fmt.Errorf("%s %s: %s", req.Method, req.URL.Host, transportError(err))
	}
	defer resp.Body.Close()
	var body []byte
	if limit > 0 {
		body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err == nil && int64(len(body)) > limit {
			err = fmt.Errorf("answer larger than %d bytes", limit)
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, nil, fmt.Errorf("%s %s: answered %s; redirects are not followed", req.Method, req.URL.Host, resp.Status)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, nil, fmt.Errorf("%s %s: answered %s", req.Method, req.URL.Host, resp.Status)
	case err != nil:
		return nil, nil, fmt.Errorf("%s %s: %w", req.Method, req.URL.Host, err)
	}
	return body, resp.Header, nil
}

// transportError describes a transport failure without the URL, which *url.Error includes.
func transportError(err error) string {
	if ue := (*url.Error)(nil); errors.As(err, &ue) {
		err = ue.Err
	}
	msg := err.Error()
	if i := strings.Index(msg, "://"); i >= 0 {
		return "connection failed"
	}
	return msg
}
