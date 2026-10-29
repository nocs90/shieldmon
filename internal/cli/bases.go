package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/oci"
)

// baseRef validates a base reference: a tag to follow, stored normalized like targets
// (docs/adr/0022-base-image-lineage.md).
func baseRef(raw string) (string, error) {
	ref, err := oci.ParseReference(raw, false)
	if err != nil {
		return "", fmt.Errorf("base %q: %w", raw, err)
	}
	if _, ok := ref.(name.Tag); !ok {
		return "", fmt.Errorf("base %q: name a tag to follow (a digest never moves, so no rebuild could be proposed)", raw)
	}
	return ref.Name(), nil
}

func (a *app) targetsSetBaseCmd() *cobra.Command {
	var by string
	var none bool
	cmd := &cobra.Command{
		Use:   "set-base TARGET [BASE]",
		Short: "Record the base image a target is built on (or --none)",
		Long: `Record the base image a target is built on: the tag its Dockerfile starts FROM. It takes
precedence over the image's org.opencontainers.image.base.name annotation. ShieldMon follows
the tag every monitoring cycle and compares layers: whether the image is on the newest base,
a rebuild is available, or the base is unmaintained (docs/adr/0022-base-image-lineage.md).

TARGET is a target ID or the image reference of a target on one platform.`,
		Example: "  shieldmon targets set-base 3 registry.access.redhat.com/ubi9/nodejs-22-minimal:latest\n  shieldmon targets set-base 3 --none",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if by == "" {
				return errors.New("--by is required (who; default from $SHIELDMON_ACTOR or $USER)")
			}
			var base string
			switch {
			case none && len(args) == 2, !none && len(args) == 1:
				return errors.New("give a BASE or --none")
			case !none:
				var err error
				if base, err = baseRef(args[1]); err != nil {
					return err
				}
			}
			if err := a.setup(cmd); err != nil {
				return err
			}
			unlock, err := a.lock()
			if err != nil {
				return err
			}
			defer unlock()
			t, err := a.resolveTarget(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := a.store.SetTargetBase(cmd.Context(), t.ID, base, by, time.Now().UTC()); err != nil {
				return err
			}
			if base == "" {
				fmt.Fprintf(cmd.OutOrStdout(), "target #%d %s (%s): no configured base\n", t.ID, t.Ref, t.Platform)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "target #%d %s (%s) is built on %s; 'shieldmon monitor' follows it\n", t.ID, t.Ref, t.Platform, base)
			return nil
		},
	}
	cmd.Flags().StringVar(&by, "by", engine.ActorFromEnv(), "who records it")
	cmd.Flags().BoolVar(&none, "none", false, "clear the configured base")
	return cmd
}
