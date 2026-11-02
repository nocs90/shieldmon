package store

import (
	"context"
	"strings"
	"testing"

	"github.com/nocs90/shieldmon/internal/vex"
)

// A VEX document cannot record decisions as an API identity (docs/adr/0031-server-mode.md):
// its statements become decisions authored by their author.
func TestVEXStatementsCannotPassForTheAPI(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	st := vex.Statement{
		VulnID: "CVE-1", Repository: "registry.test/app", PURL: "pkg:apk/alpine/zlib", AnyVersion: true,
		Justification: "vulnerable_code_not_present", Author: "API: alice", Timestamp: now,
	}
	if _, err := s.AddVEXStatements(ctx, []vex.Statement{st}, "importer", now); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("a statement authored as the API: %v", err)
	}
	st.Author = "Vendor PSIRT"
	if _, err := s.AddVEXStatements(ctx, []vex.Statement{st}, "api:bob", now); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("an importer named as the API: %v", err)
	}
	if n, err := s.AddVEXStatements(ctx, []vex.Statement{st}, "importer", now); err != nil || n != 1 {
		t.Errorf("an ordinary statement: %d %v", n, err)
	}
}
