package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nocs90/shieldmon/internal/store"
)

// ReadSBOM returns a stored SBOM's bytes, at most limit of them, after checking that the file
// is the one the store recorded: inside the data directory, a regular file, of the recorded
// size and SHA-256. A mismatch means the SBOM was changed after the scan and is not evidence.
func (e *Engine) ReadSBOM(b store.SBOM, limit int64) ([]byte, error) {
	if !filepath.IsLocal(b.Path) {
		return nil, fmt.Errorf("SBOM %s/%s: path outside the data directory", b.Generator, b.Format)
	}
	path := filepath.Join(e.DataDir, b.Path)
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	switch {
	case !st.Mode().IsRegular():
		return nil, fmt.Errorf("SBOM %s/%s: not a regular file", b.Generator, b.Format)
	case st.Size() != b.Size:
		return nil, fmt.Errorf("SBOM %s/%s: size %d, recorded %d: changed after the scan", b.Generator, b.Format, st.Size(), b.Size)
	case st.Size() > limit:
		return nil, fmt.Errorf("SBOM %s/%s: %d bytes, more than the %d read back", b.Generator, b.Format, st.Size(), limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != b.SHA256 || int64(len(data)) != b.Size {
		return nil, fmt.Errorf("SBOM %s/%s: SHA-256 differs from the recorded one: changed after the scan", b.Generator, b.Format)
	}
	return data, nil
}
