package engine

import "errors"

// ErrLocked is returned by Lock when another ShieldMon process holds the data directory.
var ErrLocked = errors.New("data directory locked")
