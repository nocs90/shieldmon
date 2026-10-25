//go:build !linux

package scanner

import "errors"

func landlockAvailable() error { return errors.New("requires Linux") }
