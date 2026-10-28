package cli

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/store"
)

var (
	targetIDArg  = regexp.MustCompile(`^#?[0-9]{1,5}$`)
	digestPrefix = regexp.MustCompile(`^(sha256:)?[0-9a-f]{6,64}$`)
)

// resolveDigest turns what a human types into a stored digest. It accepts,
// in order: a target ID ("3" or "#3"), a digest or unique digest prefix of at
// least 6 hex characters (like git), or an image reference of a target.
func (a *app) resolveDigest(ctx context.Context, arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if targetIDArg.MatchString(arg) {
		id, _ := strconv.ParseInt(strings.TrimPrefix(arg, "#"), 10, 64)
		t, err := a.store.GetTarget(ctx, id)
		if err != nil {
			return "", fmt.Errorf("target #%d: %w", id, err)
		}
		if t.CurrentDigest == "" {
			return "", fmt.Errorf("target #%d has not been resolved yet", id)
		}
		return t.CurrentDigest, nil
	}
	if digestPrefix.MatchString(arg) {
		ds, err := a.store.DigestsWithPrefix(ctx, arg)
		if err != nil {
			return "", err
		}
		switch len(ds) {
		case 1:
			return ds[0], nil
		case 0:
			return "", fmt.Errorf("no scanned image digest starts with %s", arg)
		default:
			return "", fmt.Errorf("digest prefix %s is ambiguous: %s", arg, strings.Join(ds, ", "))
		}
	}
	ref, err := oci.ParseReference(arg, false)
	if err != nil {
		return "", fmt.Errorf("%q is not a target ID, digest prefix or image reference", arg)
	}
	ts, err := a.store.TargetsByRef(ctx, ref.Name())
	if err != nil {
		return "", err
	}
	switch len(ts) {
	case 0:
		return "", fmt.Errorf("%s is not a monitored target (see 'shieldmon targets list')", ref.Name())
	case 1:
		if ts[0].CurrentDigest == "" {
			return "", errors.New(ref.Name() + " has not been resolved yet")
		}
		return ts[0].CurrentDigest, nil
	}
	var ids []string
	for _, t := range ts {
		ids = append(ids, fmt.Sprintf("#%d (%s)", t.ID, t.Platform))
	}
	return "", fmt.Errorf("%s is monitored on several platforms, use a target ID: %s", ref.Name(), strings.Join(ids, ", "))
}

// resolveTarget turns a target ID ("3" or "#3") or the image reference of a target monitored
// on one platform into the target; a reference on several platforms needs an ID.
func (a *app) resolveTarget(ctx context.Context, arg string) (store.Target, error) {
	arg = strings.TrimSpace(arg)
	if targetIDArg.MatchString(arg) {
		id, _ := strconv.ParseInt(strings.TrimPrefix(arg, "#"), 10, 64)
		t, err := a.store.GetTarget(ctx, id)
		if err != nil {
			return t, fmt.Errorf("target #%d: %w", id, err)
		}
		return t, nil
	}
	ref, err := oci.ParseReference(arg, false)
	if err != nil {
		return store.Target{}, fmt.Errorf("%q is not a target ID or image reference", arg)
	}
	ts, err := a.store.TargetsByRef(ctx, ref.Name())
	if err != nil {
		return store.Target{}, err
	}
	switch len(ts) {
	case 0:
		return store.Target{}, fmt.Errorf("%s is not a target (see 'shieldmon targets list')", ref.Name())
	case 1:
		return ts[0], nil
	}
	var ids []string
	for _, t := range ts {
		ids = append(ids, fmt.Sprintf("#%d (%s)", t.ID, t.Platform))
	}
	return store.Target{}, fmt.Errorf("%s is a target on several platforms, use a target ID: %s", ref.Name(), strings.Join(ids, ", "))
}

// shortDigest abbreviates sha256:<64 hex> to sha256:<12 hex> for display.
func shortDigest(d string) string {
	if alg, hex, ok := strings.Cut(d, ":"); ok && len(hex) > 12 {
		return alg + ":" + hex[:12]
	}
	return d
}
