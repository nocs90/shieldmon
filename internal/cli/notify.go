package cli

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/notify"
)

// notifyCmd previews and tests notification channels (docs/adr/0015-notifications.md).
func (a *app) notifyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "notify", Short: "Preview pending notifications and test notification channels"}
	cmd.AddCommand(a.notifyPreviewCmd(), a.notifyTestCmd())
	return cmd
}

func (a *app) notifyPreviewCmd() *cobra.Command {
	var channel, format string
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Show what the next monitoring cycle would send to each channel, sending nothing",
		Long: `Show the events the next 'shieldmon monitor' would send to each configured channel if
nothing changed: new critical and KEV findings since the last cycle, remediation deadlines
due soon or passed, open health findings, and events a failing channel still owes. Nothing
is sent or recorded.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			if channel != "" && !slices.ContainsFunc(a.engine.Channels, func(c notify.Channel) bool { return c.Name == channel }) {
				return fmt.Errorf("no channel %q in notifications.channels", channel)
			}
			pending, err := a.engine.PendingNotifications(cmd.Context())
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if format == "json" {
				if channel != "" {
					pending = map[string][]notify.Event{channel: pending[channel]}
				}
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(pending)
			}
			if len(a.engine.Channels) == 0 {
				fmt.Fprintln(w, "no notification channels configured (notifications.channels)")
				return nil
			}
			for _, ch := range a.engine.Channels {
				if channel != "" && ch.Name != channel {
					continue
				}
				mode := "one message per event"
				if ch.Digest {
					mode = "digest"
				}
				evs := pending[ch.Name]
				fmt.Fprintf(w, "%s (%s, %s): %d event(s)\n", ch.Name, ch.Notifier, mode, len(evs))
				for _, e := range evs {
					fmt.Fprintf(w, "  %-20s %s\n", e.Kind, notify.Clean(e.Title(), 200))
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&channel, "channel", "", "only this channel")
	cmd.Flags().StringVarP(&format, "output", "o", "text", "output format: text, json")
	return cmd
}

func (a *app) notifyTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test CHANNEL",
		Short: "Send a test message to a configured channel",
		Long: `Send a test message, with no event, to a configured channel: to check its endpoint and
credentials before the next monitoring cycle relies on them. Nothing is recorded.`,
		Example: "  shieldmon notify test secops",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			i := slices.IndexFunc(a.engine.Channels, func(c notify.Channel) bool { return c.Name == args[0] })
			if i < 0 {
				return fmt.Errorf("no channel %q in notifications.channels", args[0])
			}
			if err := notify.Test(cmd.Context(), a.engine.Channels[i], time.Now()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "test message sent to %s\n", args[0])
			return nil
		},
	}
}
