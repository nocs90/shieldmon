package charts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// Limits on a chart archive's content, subcharts included, checked before anything renders it.
const (
	MaxUnpackedBytes  = 64 << 20
	MaxArchiveEntries = 10_000
	// MaxSubchartDepth bounds charts/*.tgz nested in charts/*.tgz.
	MaxSubchartDepth  = 3
	maxChartYAMLBytes = 1 << 20
	// headerAllowance is what tar headers (PAX, GNU long names) may add to the unpacked bytes.
	headerAllowance = 16 << 20
)

// ErrArchive marks an archive that is not a well-formed, bounded chart.
var ErrArchive = errors.New("not a valid chart archive")

// Meta is what an archive's Chart.yaml says.
type Meta struct {
	Name       string `yaml:"name" json:"name"`
	Version    string `yaml:"version" json:"version"`
	AppVersion string `yaml:"appVersion" json:"app_version,omitempty"`
	Deprecated bool   `yaml:"deprecated" json:"deprecated,omitempty"`
}

// budget is shared by an archive and its subcharts.
type budget struct {
	entries  int
	unpacked int64
}

// CheckArchive reads a chart archive (.tgz) and returns its Chart.yaml. It refuses, before any
// rendering, in the archive and in every subchart archive it bundles (charts/*.tgz, which Helm
// loads): anything but regular files and directories (links could reach outside the chart),
// absolute or escaping paths, duplicate entries, more than one top-level directory, data after
// the end of the archive, more than MaxArchiveEntries entries or MaxUnpackedBytes unpacked in
// all, subcharts nested deeper than MaxSubchartDepth, and a Chart.yaml whose keys a
// case-insensitive reader (Helm's) would read otherwise. The top chart's Chart.yaml must name
// the chart and version asked for.
func CheckArchive(data []byte, wantName, wantVersion string) (Meta, error) {
	var b budget
	meta, err := checkArchive(data, 0, &b)
	if err != nil {
		return Meta{}, err
	}
	switch {
	case meta.Name != wantName:
		return Meta{}, fmt.Errorf("%w: Chart.yaml names %q, want %q", ErrArchive, truncate(meta.Name), truncate(wantName))
	case meta.Version != wantVersion:
		return Meta{}, fmt.Errorf("%w: Chart.yaml says version %q, want %q", ErrArchive, truncate(meta.Version), truncate(wantVersion))
	}
	return meta, nil
}

// limitedReader counts what the decompressor yields, headers included.
type limitedReader struct {
	r io.Reader
	b *budget
}

func (l limitedReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	if l.b.unpacked += int64(n); l.b.unpacked > MaxUnpackedBytes+headerAllowance {
		return n, fmt.Errorf("%w: more than %d bytes unpacked", ErrArchive, MaxUnpackedBytes)
	}
	return n, err
}

func checkArchive(data []byte, depth int, b *budget) (Meta, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return Meta{}, fmt.Errorf("%w: %w", ErrArchive, err)
	}
	defer func() { _ = zr.Close() }()
	in := limitedReader{zr, b}
	tr := tar.NewReader(in)
	var meta Meta
	var top string
	var files int64
	found := false
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Meta{}, fmt.Errorf("%w: %w", ErrArchive, err)
		}
		if b.entries++; b.entries > MaxArchiveEntries {
			return Meta{}, fmt.Errorf("%w: more than %d entries", ErrArchive, MaxArchiveEntries)
		}
		name := h.Name
		clean := path.Clean(name)
		if path.IsAbs(name) || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(name, "\\") {
			return Meta{}, fmt.Errorf("%w: entry %q leaves the chart", ErrArchive, truncate(name))
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		case tar.TypeXGlobalHeader:
			continue
		default:
			return Meta{}, fmt.Errorf("%w: entry %q is not a regular file or directory", ErrArchive, truncate(name))
		}
		if seen[clean] && h.Typeflag == tar.TypeReg {
			return Meta{}, fmt.Errorf("%w: entry %q appears twice", ErrArchive, truncate(name))
		}
		seen[clean] = true
		first, rest, _ := strings.Cut(clean, "/")
		switch {
		case top == "":
			top = first
		case first != top:
			return Meta{}, fmt.Errorf("%w: more than one top-level directory (%q, %q)", ErrArchive, truncate(top), truncate(first))
		}
		if h.Size < 0 {
			return Meta{}, fmt.Errorf("%w: entry %q has a negative size", ErrArchive, truncate(name))
		}
		if files += h.Size; files > MaxUnpackedBytes {
			return Meta{}, fmt.Errorf("%w: more than %d bytes unpacked", ErrArchive, MaxUnpackedBytes)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		switch {
		case rest == "Chart.yaml":
			if h.Size > maxChartYAMLBytes {
				return Meta{}, fmt.Errorf("%w: Chart.yaml larger than %d bytes", ErrArchive, maxChartYAMLBytes)
			}
			raw, err := io.ReadAll(io.LimitReader(tr, maxChartYAMLBytes))
			if err != nil {
				return Meta{}, fmt.Errorf("%w: %w", ErrArchive, err)
			}
			if meta, err = chartYAML(raw); err != nil {
				return Meta{}, err
			}
			found = true
		case isSubchartArchive(rest):
			// Helm loads bundled subcharts: they get the same checks, on the same budget.
			if depth+1 > MaxSubchartDepth {
				return Meta{}, fmt.Errorf("%w: subcharts nested deeper than %d", ErrArchive, MaxSubchartDepth)
			}
			sub, err := io.ReadAll(io.LimitReader(tr, MaxArchiveBytes+1))
			if err != nil {
				return Meta{}, fmt.Errorf("%w: %w", ErrArchive, err)
			}
			if len(sub) > MaxArchiveBytes {
				return Meta{}, fmt.Errorf("%w: subchart %q larger than %d bytes", ErrArchive, truncate(name), MaxArchiveBytes)
			}
			if _, err := checkArchive(sub, depth+1, b); err != nil {
				return Meta{}, fmt.Errorf("subchart %q: %w", truncate(name), err)
			}
		}
	}
	// Nothing may follow the end of the archive but padding: a second archive appended there
	// is invisible to this check and could be read by another tool.
	var trailing [32 << 10]byte
	for {
		n, err := in.Read(trailing[:])
		if bytes.ContainsFunc(trailing[:n], func(r rune) bool { return r != 0 }) {
			return Meta{}, fmt.Errorf("%w: data after the end of the archive", ErrArchive)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Meta{}, fmt.Errorf("%w: %w", ErrArchive, err)
		}
	}
	switch {
	case !found:
		return Meta{}, fmt.Errorf("%w: no Chart.yaml", ErrArchive)
	case meta.Name != top:
		return Meta{}, fmt.Errorf("%w: Chart.yaml names %q in directory %q", ErrArchive, truncate(meta.Name), truncate(top))
	}
	return meta, nil
}

// isSubchartArchive is charts/<file>.tgz directly under the chart directory.
func isSubchartArchive(rest string) bool {
	dir, file := path.Split(rest)
	return dir == "charts/" && strings.HasSuffix(file, ".tgz")
}

// chartYAML reads Chart.yaml as Helm would. Helm reads it case-insensitively (through
// encoding/json), yaml.v3 exactly: a key that differs only in case (Name: next to name:)
// would make the two read different charts, so it is refused.
func chartYAML(raw []byte) (Meta, error) {
	var keys map[string]any
	if err := yaml.Unmarshal(raw, &keys); err != nil {
		return Meta{}, fmt.Errorf("%w: Chart.yaml: %w", ErrArchive, err)
	}
	folded := map[string]string{}
	for k := range keys {
		low := strings.ToLower(k)
		if prev, ok := folded[low]; ok {
			return Meta{}, fmt.Errorf("%w: Chart.yaml has both %q and %q", ErrArchive, truncate(prev), truncate(k))
		}
		folded[low] = k
		for _, want := range []string{"name", "version", "appVersion", "apiVersion", "deprecated"} {
			if strings.EqualFold(k, want) && k != want {
				return Meta{}, fmt.Errorf("%w: Chart.yaml key %q: want %q", ErrArchive, truncate(k), want)
			}
		}
	}
	var meta Meta
	if err := yaml.Unmarshal(raw, &meta); err != nil {
		return Meta{}, fmt.Errorf("%w: Chart.yaml: %w", ErrArchive, err)
	}
	meta.AppVersion = truncate(meta.AppVersion)
	return meta, nil
}
