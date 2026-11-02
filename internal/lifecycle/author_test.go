package lifecycle

import "testing"

func TestReservedAuthor(t *testing.T) {
	// Look-alike colons are built from code points, so that the source stays plain ASCII.
	fullwidth, ratio := "api"+string(rune(0xFF1A))+"alice", "api"+string(rune(0x2236))+"alice"
	for name, want := range map[string]bool{
		"api:alice": true, "API:alice": true, " api:alice": true, "Api : alice": true, "api alice": true,
		"api/alice": true, fullwidth: true, ratio: true,
		"alice": false, "api": false, "apiary": false, "api-team": false, "api_bot": false, "api2": false,
		"rapi:x": false, "": false,
	} {
		if got := ReservedAuthor(name); got != want {
			t.Errorf("ReservedAuthor(%q) = %v, want %v", name, got, want)
		}
	}
}
