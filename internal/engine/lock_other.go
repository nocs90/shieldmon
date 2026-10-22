//go:build !unix

package engine

// Lock is a no-op on non-Unix platforms, which are not supported targets.
func Lock(string) (func(), error) { return func() {}, nil }
