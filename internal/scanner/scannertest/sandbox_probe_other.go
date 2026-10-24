//go:build !linux

package scannertest

import "errors"

var errProbeUnsupported = errors.New("probe needs Linux")

func probeUserns() error      { return errProbeUnsupported }
func probePersonality() error { return errProbeUnsupported }
