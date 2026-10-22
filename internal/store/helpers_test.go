package store

import (
	"time"

	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
)

// openPolicy has no SLA so store tests can focus on persistence.
var openPolicy = lifecycle.Policy{Profile: "test", VendorDependencyMaxDays: 30, OperationalRequirementMaxDays: 365}

func decision(expires time.Time) lifecycle.Decision {
	return lifecycle.Decision{
		State: model.StateRiskAccepted, Justification: "compensating control in place",
		Author: "secops", ExpiresAt: expires,
	}
}
