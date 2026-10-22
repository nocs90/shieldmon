//go:build !unix

package scanner

import "os/exec"

func setProcessGroup(*exec.Cmd) {}
