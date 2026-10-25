//go:build !linux

package scanner

import "errors"

func landlockAvailable() error { return errors.New("requires Linux") }

func landlockSupport() (int, error) { return 0, errors.New("requires Linux") }
