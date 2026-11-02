package charts

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrNotPublic is returned for a connection, asked for by remote content (an index's archive
// URL, a repository Artifact Hub names), to an address that is not public: loopback, private,
// link-local, carrier-grade NAT, unspecified or multicast. Remote content must not make
// ShieldMon reach into the networks it runs in.
var ErrNotPublic = errors.New("address is not public")

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// publicIP reports whether ip may be reached on behalf of remote content.
func publicIP(ip net.IP) bool {
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsInterfaceLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified() && !cgnat.Contains(ip)
}

// PublicClient fetches over HTTPS for remote content: it connects only to public addresses,
// checked on the address actually dialled (so a name that resolves, or re-resolves, to a
// private address is refused too), follows at most 5 redirects, all HTTPS. Through a proxy
// from the environment, the proxy is dialled and decides.
func PublicClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || !publicIP(ip) {
				return fmt.Errorf("%w: %s", ErrNotPublic, host)
			}
			return nil
		},
	}
	direct := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 30 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	viaProxy := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 30 * time.Second, ForceAttemptHTTP2: true}
	return &http.Client{
		Timeout:       2 * time.Minute,
		Transport:     proxySplit{direct: direct, proxied: viaProxy},
		CheckRedirect: httpsRedirects,
	}
}

// proxySplit sends requests the environment proxies through the proxy, the others through the
// guarded dialer.
type proxySplit struct{ direct, proxied *http.Transport }

func (p proxySplit) RoundTrip(r *http.Request) (*http.Response, error) {
	if u, err := http.ProxyFromEnvironment(r); err == nil && u != nil {
		return p.proxied.RoundTrip(r)
	}
	return p.direct.RoundTrip(r)
}

func httpsRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 || req.URL.Scheme != "https" {
		return errors.New("redirect refused: at most 5, https only")
	}
	return nil
}

// publicHost reports whether host (a registry host[:port] or URL host) is not obviously
// internal: a loopback, private or link-local literal, or localhost. Registries are dialled by
// go-containerregistry, outside PublicClient: a public name that resolves to an internal
// address is not caught here.
func publicHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return publicIP(ip)
	}
	return true
}

// internalSuffixes are DNS names that only resolve inside a network: cluster services,
// mDNS, and names reserved for private use.
var internalSuffixes = []string{".local", ".internal", ".svc", ".cluster.local", ".lan", ".home.arpa", ".corp", ".intranet"}

// PublicRegistry reports whether a registry host[:port] that remote content names (an image
// of a chart) looks public: not what publicHost refuses, not a single-label name, and not a
// name reserved for internal networks (docs/adr/0034-chart-tracking.md). Like publicHost, it
// cannot see where a public name resolves.
func PublicRegistry(hostport string) bool {
	if !publicHost(hostport) {
		return false
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if net.ParseIP(host) != nil {
		return true // publicHost judged the literal
	}
	// A fully qualified name ("localhost.") resolves like the name without its dot.
	host = strings.TrimSuffix(host, ".")
	if !publicHost(host) {
		return false
	}
	labels := strings.Split(host, ".")
	// No single-label name, and no numeric shorthand that some resolvers read as an address
	// (127.1, 0x7f.1): a registry name ends in a top-level domain of letters.
	if len(labels) < 2 || !isTLD(labels[len(labels)-1]) {
		return false
	}
	for _, s := range internalSuffixes {
		if strings.HasSuffix(host, s) {
			return false
		}
	}
	return true
}

// isTLD reports whether s can be a top-level domain: letters, or an IDN (xn--).
func isTLD(s string) bool {
	if strings.HasPrefix(s, "xn--") && len(s) > 4 {
		return true
	}
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// derivedURL checks a URL taken from remote content: https, no credentials, not an internal
// host.
func derivedURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("not an absolute URL")
	}
	if u.Scheme != "https" || u.User != nil {
		return nil, errors.New("want an https URL without credentials")
	}
	if !publicHost(u.Host) {
		return nil, fmt.Errorf("%w: %s", ErrNotPublic, u.Hostname())
	}
	return u, nil
}
