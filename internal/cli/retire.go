package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/engine"
)

// targetsRetireCmd is 'targets retire' (retire true) or 'targets restore' (ADR 0017).
func (a *app) targetsRetireCmd(retire bool) *cobra.Command {
	var by, reason string
	use, short, long := "restore TARGET", "Monitor a retired target again",
		`Monitor a retired target again. Its findings come back into the open numbers as they are;
the next monitoring cycle resolves the tag and reconciles them with scan evidence.`
	if retire {
		use, short, long = "retire TARGET", "Stop monitoring a decommissioned image, keeping its history",
			`Stop monitoring a target (an image that is decommissioned). The retirement is recorded
with who and why; monitor skips the target and scan refuses it. Its findings are not closed:
nothing proved them fixed. Reports, the inventory and notifications leave out findings whose
images are all retired ("retired with the image"), and count them apart. A digest that
another monitored target still resolves to keeps its findings in scope.

TARGET is a target ID or the image reference of a target on one platform.`
	}
	cmd := &cobra.Command{
		Use: use, Short: short, Long: long,
		Example: "  shieldmon targets retire 7 --reason \"decommissioned in CHG-2041\"\n  shieldmon targets restore 7 --reason \"back in production\"",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if by == "" {
				return errors.New("--by is required (who; default from $SHIELDMON_ACTOR or $USER)")
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
			verb := "restored"
			if retire {
				verb = "retired"
				err = a.engine.RetireTarget(cmd.Context(), t, by, reason)
			} else {
				err = a.engine.RestoreTarget(cmd.Context(), t, by, reason)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s target #%d %s (%s)\n", verb, t.ID, printable(t.Ref), t.Platform)
			return nil
		},
	}
	cmd.Flags().StringVar(&by, "by", engine.ActorFromEnv(), "who decides (recorded)")
	cmd.Flags().StringVar(&reason, "reason", "", "why, at least 10 characters, e.g. a change ticket (recorded)")
	return cmd
}
