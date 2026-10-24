// Package cli implements the shieldmon command line.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/scanner"
	"github.com/nocs90/shieldmon/internal/store"
)

// Version is set at build time via -ldflags.
var Version = "dev"

type app struct {
	cfgPath  string
	dataDir  string
	logLevel string

	cfg    config.Config
	store  *store.Store
	engine *engine.Engine
	log    *slog.Logger
	out    io.Writer
}

// Execute runs the CLI and returns the process exit code.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	a := &app{out: stdout}
	root := a.rootCmd()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if a.store != nil {
		_ = a.store.Close()
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "shieldmon",
		Short: "Continuous vulnerability monitoring for container images",
		Long: `ShieldMon continuously monitors container images for vulnerabilities.

Images are identified by digest, SBOMs are generated once per digest and
re-matched against fresh vulnerability data, and findings are closed only
when a later scan provides evidence.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.cfgPath, "config", "", "config file (default "+config.DefaultPath()+")")
	root.PersistentFlags().StringVar(&a.dataDir, "data-dir", "", "data directory (overrides config)")
	root.PersistentFlags().StringVar(&a.logLevel, "log-level", "warn", "log level: debug, info, warn, error")

	root.AddGroup(
		&cobra.Group{ID: "monitor", Title: "Monitoring:"},
		&cobra.Group{ID: "triage", Title: "Triage and reporting:"},
		&cobra.Group{ID: "setup", Title: "Setup:"},
	)
	for group, cmds := range map[string][]*cobra.Command{
		"monitor": {a.scanCmd(), a.monitorCmd(), a.rematchCmd(), a.targetsCmd()},
		"triage":  {a.findingsCmd(), a.healthCmd(), a.reportCmd(), a.sbomCmd()},
		"setup":   {a.initCmd(), a.doctorCmd(), a.pluginsCmd(), a.versionCmd()},
	} {
		for _, c := range cmds {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	root.SetHelpCommandGroupID("setup")
	root.SetCompletionCommandGroupID("setup")

	help := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if p, ok := bannerPainter(cmd.OutOrStdout()); ok && cmd == root {
			writeBanner(cmd.OutOrStdout(), p)
		}
		help(cmd, args)
	})
	return root
}

// setup loads configuration and opens the store; called by commands that need it.
func (a *app) setup(cmd *cobra.Command) error {
	path, explicit := a.cfgPath, a.cfgPath != ""
	if !explicit {
		path = config.DefaultPath()
	}
	cfg, err := config.Load(path, explicit)
	if err != nil {
		return err
	}
	if a.dataDir != "" {
		cfg.DataDir = a.dataDir
	}
	if cfg.DataDir, err = filepath.Abs(cfg.DataDir); err != nil {
		return err
	}
	a.cfg = cfg

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(a.logLevel)); err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	a.log = slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: lvl}))

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(cmd.Context(), filepath.Join(cfg.DataDir, "shieldmon.db"))
	if err != nil {
		return err
	}
	a.store = st

	set, err := a.scannerSet()
	if err != nil {
		return err
	}
	a.engine = &engine.Engine{
		Store:           st,
		Scanners:        set,
		Fetcher:         engine.RegistryFetcher{Options: a.ociOptions()},
		DataDir:         cfg.DataDir,
		DBMaxAge:        cfg.Health.DBMaxAge.Duration,
		MonitorInterval: cfg.Health.MonitorInterval.Duration,
		Log:             a.log,
	}
	return nil
}

func (a *app) ociOptions() oci.Options {
	l := a.cfg.Limits
	return oci.Options{
		Limits: oci.Limits{
			MaxLayers: l.MaxLayers, MaxLayerBytes: l.MaxLayerBytes, MaxTotalBytes: l.MaxTotalBytes,
			MaxConfigBytes: oci.DefaultLimits.MaxConfigBytes,
		},
		UserAgent: "shieldmon/" + Version,
	}
}

func (a *app) scannerSet() (scanner.Set, error) {
	sc := a.cfg.Scanners
	_, sandbox, err := scanner.SelectSandbox(sc.Sandbox.Backend)
	if err != nil {
		return scanner.Set{}, err
	}
	r := scanner.Runner{Timeout: sc.Timeout.Duration, MaxOutput: sc.MaxOutputBytes, Sandbox: sandbox}
	specs := map[string]scanner.Spec{}
	for name, t := range sc.Tools {
		specs[name] = scanner.Spec{
			Bin:     scanner.Binary{Name: name, Path: t.Path, SHA256: t.SHA256},
			Runner:  r,
			Options: scanner.Options(t.Options),
		}
	}
	return scanner.Build(sc.Matchers, specs, r)
}

func (a *app) lock() (func(), error) { return engine.Lock(a.cfg.DataDir) }

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "shieldmon", Version)
		},
	}
}

func (a *app) initCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a config template and initialize the database",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := a.cfgPath
			if path == "" {
				path = config.DefaultPath()
			}
			if _, err := os.Stat(path); err == nil && !force {
				fmt.Fprintf(cmd.OutOrStdout(), "config exists: %s (use --force to overwrite)\n", path)
			} else {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(path, []byte(config.Template), 0o600); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote config: %s\n", path)
			}
			if err := a.setup(cmd); err != nil {
				return err
			}
			v, err := a.store.SchemaVersion(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "database ready: %s (schema v%d)\n", filepath.Join(a.cfg.DataDir, "shieldmon.db"), v)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing config file")
	return cmd
}

func (a *app) doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check scanners, pins and vulnerability DB freshness",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			ctx := cmd.Context()
			problems := 0
			set := a.engine.Scanners
			gens, err := set.RequiredGenerators()
			if err != nil {
				return err
			}
			needed := map[string]bool{}
			for _, g := range gens {
				needed[g.Name()] = true
			}
			for _, m := range set.Matchers {
				needed[m.Name()] = true
			}
			fmt.Fprintf(w, "data dir: %s\n", a.cfg.DataDir)
			if name, sb, _ := scanner.SelectSandbox(a.cfg.Scanners.Sandbox.Backend); sb != nil {
				if _, err := sb.Command(scanner.Policy{}, "true", nil); err != nil {
					fmt.Fprintf(w, "✗ sandbox %v\n", err)
					problems++
				} else {
					fmt.Fprintf(w, "• sandbox %s\n", name)
				}
			}
			names := make([]string, 0, len(needed))
			for n := range needed {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, name := range names {
				tool := a.cfg.Scanners.Tools[name]
				path, err := scanner.Binary{Name: name, Path: tool.Path}.Resolve()
				if err != nil {
					fmt.Fprintf(w, "✗ %-6s %v\n", name, err)
					problems++
					continue
				}
				sum, _ := scanner.FileSHA256(path)
				pin := "not pinned (set scanners.tools." + name + ".sha256)"
				if tool.SHA256 != "" {
					if tool.SHA256 == sum {
						pin = "pin OK"
					} else {
						pin = "PIN MISMATCH"
						problems++
					}
				}
				fmt.Fprintf(w, "• %-6s %s\n         sha256 %s — %s\n", name, path, sum, pin)
			}
			type tooler interface {
				Tool(context.Context) (model.Tool, error)
			}
			now := time.Now().UTC()
			for _, m := range set.Matchers {
				t, ok := m.(tooler)
				if !ok {
					continue
				}
				tool, err := t.Tool(ctx)
				if err != nil {
					fmt.Fprintf(w, "✗ %-6s %v\n", m.Name(), err)
					problems++
					continue
				}
				age := "unknown DB age"
				if !tool.DBBuilt.IsZero() {
					age = fmt.Sprintf("DB %s built %s (%s old)", tool.DBVersion, tool.DBBuilt.Format(time.RFC3339), tool.DBAge(now).Round(time.Minute))
					if tool.DBAge(now) > a.cfg.Health.DBMaxAge.Duration {
						age += " — STALE"
						problems++
					}
				}
				fmt.Fprintf(w, "• %-6s v%s, %s\n", m.Name(), tool.Version, age)
			}
			health, err := a.store.ListHealth(ctx, false)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "open health findings: %d\n", len(health))
			if problems > 0 {
				return fmt.Errorf("%d problem(s) found", problems)
			}
			fmt.Fprintln(w, "all checks passed")
			return nil
		},
	}
}

func (a *app) platformFlag(cmd *cobra.Command, p *string) {
	cmd.Flags().StringVar(p, "platform", "", "image platform os/arch[/variant] (default from config)")
}

func (a *app) platform(v string) (model.Platform, error) {
	if v == "" {
		v = a.cfg.Platform
	}
	return model.ParsePlatform(v)
}

func (a *app) scanCmd() *cobra.Command {
	var platform, format string
	cmd := &cobra.Command{
		Use:   "scan IMAGE...",
		Short: "Resolve, SBOM and match images, and track them as monitoring targets",
		Long: `Scan resolves each image reference to its digest, generates SBOMs if this
digest has never been seen, matches them, and reconciles findings. The image
becomes a monitoring target that 'shieldmon monitor' re-evaluates.`,
		Example: "  shieldmon scan alpine:3.18.0\n  shieldmon scan --platform linux/arm64 ghcr.io/org/app:1.2.3",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			p, err := a.platform(platform)
			if err != nil {
				return err
			}
			unlock, err := a.lock()
			if err != nil {
				return err
			}
			defer unlock()
			var results []engine.Result
			failed := 0
			for _, ref := range args {
				r, err := a.engine.Scan(cmd.Context(), ref, p)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "%s: %v\n", ref, err)
					failed++
					continue
				}
				results = append(results, r)
				if r.Status != store.ScanComplete {
					failed++
				}
			}
			if err := printResults(cmd.OutOrStdout(), results, format); err != nil {
				return err
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d scans did not complete (see 'shieldmon health')", failed, len(args))
			}
			return nil
		},
	}
	a.platformFlag(cmd, &platform)
	cmd.Flags().StringVarP(&format, "output", "o", "text", "output format: text, json")
	return cmd
}

func (a *app) monitorCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Run one continuous-monitoring cycle over all targets (for cron/systemd/CronJob)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			unlock, err := a.lock()
			if err != nil {
				return err
			}
			defer unlock()
			sum, err := a.engine.Monitor(cmd.Context())
			if err != nil {
				return err
			}
			if format == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				err := enc.Encode(struct {
					RunID    int64             `json:"run_id"`
					Status   string            `json:"status"`
					Results  []resultJSON      `json:"results"`
					Failures map[string]string `json:"failures,omitempty"`
					Expired  []int64           `json:"expired_decisions,omitempty"`
				}{sum.RunID, sum.Status, toResultJSON(sum.Results), sum.Failures, sum.ExpiredDecision})
				if err != nil {
					return err
				}
			} else {
				if err := printResults(cmd.OutOrStdout(), sum.Results, format); err != nil {
					return err
				}
				for ref, e := range sum.Failures {
					fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", ref, e)
				}
				if len(sum.ExpiredDecision) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "reopened %d finding(s) with expired decisions\n", len(sum.ExpiredDecision))
				}
				fmt.Fprintf(cmd.OutOrStdout(), "monitor run #%d: %s\n", sum.RunID, sum.Status)
			}
			if sum.Status != "ok" {
				return fmt.Errorf("monitoring cycle %s (see 'shieldmon health')", sum.Status)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "text", "output format: text, json")
	return cmd
}

func (a *app) rematchCmd() *cobra.Command {
	var all bool
	var format string
	cmd := &cobra.Command{
		Use:   "rematch [TARGET|DIGEST...]",
		Short: "Re-match stored SBOMs against current vulnerability data (no registry access)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			if all == (len(args) > 0) {
				return fmt.Errorf("give digests or --all")
			}
			if all {
				targets, err := a.store.ListTargets(cmd.Context())
				if err != nil {
					return err
				}
				seen := map[string]bool{}
				for _, t := range targets {
					if t.CurrentDigest != "" && !seen[t.CurrentDigest] {
						seen[t.CurrentDigest] = true
						args = append(args, t.CurrentDigest)
					}
				}
			}
			unlock, err := a.lock()
			if err != nil {
				return err
			}
			defer unlock()
			var results []engine.Result
			for _, arg := range args {
				d, err := a.resolveDigest(cmd.Context(), arg)
				if err != nil {
					return err
				}
				r, err := a.engine.Rematch(cmd.Context(), d)
				if err != nil {
					return err
				}
				results = append(results, r)
			}
			return printResults(cmd.OutOrStdout(), results, format)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "rematch the current digest of every target")
	cmd.Flags().StringVarP(&format, "output", "o", "text", "output format: text, json")
	return cmd
}

func (a *app) pluginsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "plugins",
		Short: "List registered extension plugins (scanners, report formats)",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "Scanner plugins:")
			for _, p := range scanner.Plugins() {
				opts := ""
				if len(p.Options) > 0 {
					opts = " (options: " + strings.Join(p.Options, ", ") + ")"
				}
				fmt.Fprintf(w, "  %-8s %s%s\n", p.Name, p.Description, opts)
			}
			fmt.Fprintln(w, "Sandbox backends:")
			for _, b := range scanner.SandboxBackends() {
				status := "available"
				if err := b.Available(); err != nil {
					status = "unavailable: " + err.Error()
				}
				fmt.Fprintf(w, "  %-8s %s (%s)\n", b.Name, b.Description, status)
			}
			fmt.Fprintln(w, "Report formats:")
			for _, f := range report.Formats() {
				fmt.Fprintf(w, "  %-8s %s\n", f.Name, f.Description)
			}
		},
	}
}
