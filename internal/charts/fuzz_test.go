package charts_test

import (
	"testing"

	"github.com/nocs90/shieldmon/internal/charts"
	"github.com/nocs90/shieldmon/internal/charts/chartstest"
)

// Chart archives come from third parties: the check must never panic, and what it accepts
// names the chart and version asked for.
func FuzzCheckArchive(f *testing.F) {
	f.Add(chartstest.Archive(f, "web", "1.0.0"))
	f.Add(chartstest.RawArchive(f, "web", chartstest.File{Name: "Chart.yaml", Body: "name: web\nversion: 1.0.0\n"}))
	f.Add([]byte("\x1f\x8b\x08\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := charts.CheckArchive(data, "web", "1.0.0")
		if err == nil && (m.Name != "web" || m.Version != "1.0.0") {
			t.Errorf("accepted %+v", m)
		}
	})
}
