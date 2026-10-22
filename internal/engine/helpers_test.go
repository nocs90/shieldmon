package engine_test

import (
	"time"

	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
)

func lifecycleDecision(expires time.Time) lifecycle.Decision {
	return lifecycle.Decision{
		State:         model.StateRiskAccepted,
		Justification: "zlib minizip not used; compensating control documented in RISK-12",
		Author:        "secops-lead",
		ExpiresAt:     expires,
	}
}
