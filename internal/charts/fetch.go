package charts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// FetchChecked downloads one version of chart from src and checks its archive: what is
// rendered, and recorded, is only what CheckArchive accepted. It returns the archive, its
// digest and its Chart.yaml.
func FetchChecked(ctx context.Context, src Source, chart, version string) ([]byte, string, Meta, error) {
	var buf bytes.Buffer
	digest, err := src.Fetch(ctx, chart, version, &buf)
	if err != nil {
		return nil, "", Meta{}, err
	}
	meta, err := CheckArchive(buf.Bytes(), chart, version)
	if err != nil {
		return nil, "", Meta{}, fmt.Errorf("%s %s: %w", chart, version, err)
	}
	return buf.Bytes(), digest, meta, nil
}

// ProfileHash identifies everything a render depends on in p: a version is rendered again
// when its profile's hash changes (a values file edited).
func ProfileHash(p Profile) string {
	data, err := json.Marshal(p)
	if err != nil {
		panic(err) // a Profile always marshals
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
