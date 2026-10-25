package scanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestLandlockBoundsFileSize checks RLIMIT_FSIZE: a file outside the scratch directory, which
// the Runner's watch does not measure, still stops at the quota.
func TestLandlockBoundsFileSize(t *testing.T) {
	if err := landlockAvailable(); err != nil {
		if slices.Contains(strings.Split(os.Getenv("SHIELDMON_TEST_SANDBOX"), ","), "landlock") {
			t.Fatal("landlock:", err)
		}
		t.Skip("landlock:", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	r := Runner{Timeout: time.Minute, Sandbox: landlock{self: self}, TempDir: t.TempDir(), ScratchQuota: 1 << 20}
	ctx := WithPolicy(context.Background(), Policy{Writable: []string{out}})
	big := filepath.Join(out, "big")
	// exec: head itself must be the process the limit stops, not a shell around it.
	if _, err := r.Run(ctx, "/bin/sh", "-c", "exec head -c 4194304 /dev/zero > "+big); err == nil {
		t.Fatal("writing past the file size limit must fail")
	}
	if st, err := os.Stat(big); err != nil || st.Size() > 1<<20 {
		t.Fatalf("file grew past the limit: %v %v", st, err)
	}
}
