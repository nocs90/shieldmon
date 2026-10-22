// Command shieldmon is the ShieldMon CLI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/nocs90/shieldmon/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
