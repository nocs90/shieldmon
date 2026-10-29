package gate

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/report"
)

// WriteJSON writes the result as indented JSON.
func WriteJSON(w io.Writer, r Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteSARIF writes the result as SARIF 2.1.0 with the rules and fingerprints of the monthly
// SARIF report: flagged findings as results (error for fail, warning for warn), exempt ones
// as suppressed results with their decision.
func WriteSARIF(w io.Writer, r Result) error {
	in := make([]report.SARIFResult, 0, len(r.Flagged)+len(r.Exempt))
	for _, f := range r.Flagged {
		level := "error"
		if f.Action == config.GateWarn {
			level = "warning"
		}
		in = append(in, report.SARIFResult{
			Row: f.Row, Level: level,
			Properties: map[string]any{"gate_action": f.Action, "gate_rules": f.Rules},
		})
	}
	for _, x := range r.Exempt {
		just := x.Decision.State
		if x.Decision.Deviation != "" {
			just += " (" + x.Decision.Deviation + ")"
		}
		just += ": " + x.Decision.Justification
		in = append(in, report.SARIFResult{Row: x, Level: report.SARIFLevel(x.Severity), Suppressed: true, Justification: just})
	}
	props := map[string]string{
		"gate_verdict": string(r.Verdict), "image": r.Image, "digest": r.Digest, "policy": r.Policy,
		"evaluated_at": r.EvaluatedAt.Format(time.RFC3339),
	}
	if len(r.Unproven) > 0 {
		props["unproven"] = strings.Join(r.Unproven, "; ")
	}
	return report.WriteSARIF(w, in, props)
}
