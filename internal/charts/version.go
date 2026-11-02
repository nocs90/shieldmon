package charts

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// semverRE is a SemVer 2 version, as Helm requires of chart versions (a leading v allowed).
// OCI tags cannot hold '+': Helm writes build metadata as '_' there.
var semverRE = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:[+_]([0-9A-Za-z.-]+))?$`)

func validVersion(v string) bool { return len(v) <= 128 && semverRE.MatchString(v) }

type semver struct {
	major, minor, patch uint64
	pre                 []string
}

func parseSemver(v string) (semver, bool) {
	m := semverRE.FindStringSubmatch(v)
	if m == nil {
		return semver{}, false
	}
	var s semver
	var err error
	if s.major, err = strconv.ParseUint(m[1], 10, 64); err != nil {
		return semver{}, false
	}
	if s.minor, err = strconv.ParseUint(m[2], 10, 64); err != nil {
		return semver{}, false
	}
	if s.patch, err = strconv.ParseUint(m[3], 10, 64); err != nil {
		return semver{}, false
	}
	if m[4] != "" {
		s.pre = strings.Split(m[4], ".")
	}
	return s, true
}

// compareVersions orders versions by SemVer precedence; invalid ones sort below valid ones.
func compareVersions(a, b string) int {
	x, okA := parseSemver(a)
	y, okB := parseSemver(b)
	return compareParsed(a, x, okA, b, y, okB)
}

func compareParsed(a string, x semver, okA bool, b string, y semver, okB bool) int {
	switch {
	case !okA && !okB:
		return cmp.Compare(a, b)
	case !okA:
		return -1
	case !okB:
		return 1
	}
	if c := cmp.Or(cmp.Compare(x.major, y.major), cmp.Compare(x.minor, y.minor), cmp.Compare(x.patch, y.patch)); c != 0 {
		return c
	}
	// A pre-release ranks below its release.
	switch {
	case len(x.pre) == 0 && len(y.pre) == 0:
		return 0
	case len(x.pre) == 0:
		return 1
	case len(y.pre) == 0:
		return -1
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		p, q := x.pre[i], y.pre[i]
		pn, errP := strconv.ParseUint(p, 10, 64)
		qn, errQ := strconv.ParseUint(q, 10, 64)
		var c int
		switch {
		case errP == nil && errQ == nil:
			c = cmp.Compare(pn, qn)
		case errP == nil:
			c = -1 // numeric identifiers rank below alphanumeric ones
		case errQ == nil:
			c = 1
		default:
			c = cmp.Compare(p, q)
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(x.pre), len(y.pre))
}

// Newest returns the newest version that is neither a pre-release nor deprecated, "" if none.
func Newest(vs []Version) string {
	best := ""
	for _, v := range vs {
		s, ok := parseSemver(v.Version)
		if !ok || len(s.pre) > 0 || v.Deprecated {
			continue
		}
		if best == "" || compareVersions(v.Version, best) > 0 {
			best = v.Version
		}
	}
	return best
}

// sortByVersion sorts newest first, parsing each version once.
func sortByVersion[T any](s []T, version func(T) string) {
	type item struct {
		v   T
		raw string
		sv  semver
		ok  bool
	}
	items := make([]item, len(s))
	for i, v := range s {
		raw := version(v)
		sv, ok := parseSemver(raw)
		items[i] = item{v, raw, sv, ok}
	}
	slices.SortStableFunc(items, func(a, b item) int { return compareParsed(b.raw, b.sv, b.ok, a.raw, a.sv, a.ok) })
	for i := range items {
		s[i] = items[i].v
	}
}
