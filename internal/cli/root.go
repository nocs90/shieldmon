// Package cli implements the shieldmon command line.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/notify"
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

	cfg        config.Config
	registries *oci.Registries
	store      *store.Store
	engine     *engine.Engine
	log        *slog.Logger
	out        io.Writer
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
		"triage":  {a.findingsCmd(), a.vexCmd(), a.healthCmd(), a.reportCmd(), a.sbomCmd(), a.componentsCmd(), a.notifyCmd(), a.auditCmd()},
		"setup":   {a.initCmd(), a.doctorCmd(), a.dbCmd(), a.pluginsCmd(), a.versionCmd()},
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
	rules := make([]oci.Rule, 0, len(cfg.Registries))
	for _, r := range cfg.Registries {
		rules = append(rules, oci.Rule{Hosts: r.Hosts, Provider: r.Provider, Options: r.Options})
	}
	if a.registries, err = oci.NewRegistries(rules); err != nil {
		return err
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(a.logLevel)); err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	a.log = slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: lvl}))

	// tmp holds scanner scratch space and, in the container image (TMPDIR=<data_dir>/tmp), the
	// only temporary files a read-only root filesystem allows.
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "tmp"), 0o700); err != nil {
		return err
	}
	st, err := store.Open(cmd.Context(), filepath.Join(cfg.DataDir, "shieldmon.db"))
	if err != nil {
		return err
	}
	a.store = st

	set, sandbox, err := a.scannerSet()
	if err != nil {
		return err
	}
	policy, err := cfg.Policy()
	if err != nil {
		return err
	}
	chans := make([]notify.ChannelConfig, 0, len(cfg.Notifications.Channels))
	for _, c := range cfg.Notifications.Channels {
		chans = append(chans, notify.ChannelConfig{Name: c.Name, Notifier: c.Notifier, Events: c.Events, Digest: c.Digest, Options: c.Options})
	}
	channels, err := notify.NewChannels(chans, notify.Spec{})
	if err != nil {
		return err
	}
	a.engine = &engine.Engine{
		Store:               st,
		Scanners:            set,
		Sandboxed:           scanner.Confined(sandbox),
		SandboxDegraded:     scanner.SandboxDegraded(sandbox),
		Fetcher:             engine.RegistryFetcher{Options: a.ociOptions()},
		DataDir:             cfg.DataDir,
		DBMaxAge:            cfg.Health.DBMaxAge.Duration,
		MonitorInterval:     cfg.Health.MonitorInterval.Duration,
		Decisions:           policy,
		Channels:            channels,
		DueSoon:             time.Duration(cfg.Notifications.DueSoonDays) * 24 * time.Hour,
		AuditVerifyInterval: cfg.Health.AuditVerifyInterval.Duration,
		Log:                 a.log,
	}
	return nil
}

func (a *app) ociOptions() oci.Options {
	l := a.cfg.Limits
	return oci.Options{
		Keychain: a.registries,
		Limits: oci.Limits{
			MaxLayers: l.MaxLayers, MaxLayerBytes: l.MaxLayerBytes, MaxTotalBytes: l.MaxTotalBytes,
			MaxConfigBytes: oci.DefaultLimits.MaxConfigBytes,
		},
		UserAgent: "shieldmon/" + Version,
	}
}

// scannerSet builds the configured scanners and returns the sandbox they run in.
func (a *app) scannerSet() (scanner.Set, scanner.Sandbox, error) {
	sc := a.cfg.Scanners
	_, sandbox, err := scanner.SelectSandbox(sc.Sandbox.Backend)
	if err != nil {
		return scanner.Set{}, nil, err
	}
	// Scanner DBs, caches and scratch space live in the data dir, so that a sandbox can
	// expose them without the user's home directory.
	data, err := filepath.Abs(a.cfg.DataDir)
	if err != nil {
		return scanner.Set{}, nil, err
	}
	r := scanner.Runner{
		Timeout: sc.Timeout.Duration, MaxOutput: sc.MaxOutputBytes, Sandbox: sandbox,
		CacheDir: filepath.Join(data, "cache"), TempDir: filepath.Join(data, "tmp"),
		ScratchQuota: a.cfg.Limits.MaxScratchBytes, MinFreeBytes: a.cfg.Limits.MinFreeDiskBytes,
	}
	specs := map[string]scanner.Spec{}
	for name, t := range sc.Tools {
		specs[name] = scanner.Spec{
			Bin:     scanner.Binary{Name: name, Path: t.Path, SHA256: t.SHA256},
			Runner:  r,
			Options: scanner.Options(t.Options),
		}
	}
	set, err := scanner.Build(sc.Matchers, specs, r)
	return set, sandbox, err
}

// preflight records the sandbox posture and refreshes vulnerability DBs before a
// command matches. A failed update is reported but does not stop the command.
func (a *app) preflight(cmd *cobra.Command) {
	if err := a.engine.Preflight(cmd.Context()); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: vulnerability DB update failed, matching with the DBs on disk: %v\n", err)
	}
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
	var sandbox string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a config template and initialize the database",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := a.cfgPath
			if path == "" {
				path = config.DefaultPath()
			}
			if _, _, err := scanner.SelectSandbox(sandbox); err != nil {
				return fmt.Errorf("--sandbox: %w", err)
			}
			w := cmd.OutOrStdout()
			if _, err := os.Stat(path); err == nil && !force {
				fmt.Fprintf(w, "config exists: %s (use --force to overwrite)\n", path)
			} else {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(path, []byte(config.TemplateWithSandbox(sandbox)), 0o600); err != nil {
					return err
				}
				fmt.Fprintf(w, "wrote config: %s\n", path)
			}
			if err := a.setup(cmd); err != nil {
				return err
			}
			v, err := a.store.SchemaVersion(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "database ready: %s (schema v%d)\n", filepath.Join(a.cfg.DataDir, "shieldmon.db"), v)
			// Say now, not at the first scan, whether scanners can run here.
			name, sb, _ := scanner.SelectSandbox(a.cfg.Scanners.Sandbox.Backend)
			switch _, err := sb.Command(scanner.Policy{}, "true", nil); {
			case err != nil:
				fmt.Fprintf(w, "sandbox: %v\n  scans refuse to start until a backend runs here (see 'shieldmon plugins')\n", err)
			case !scanner.Confined(sb):
				fmt.Fprintf(w, "sandbox: %s, scanners run unconfined (a scanner_unsandboxed health finding stays open)\n", name)
			default:
				fmt.Fprintf(w, "sandbox: %s\n", name)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing config file")
	cmd.Flags().StringVar(&sandbox, "sandbox", scanner.AutoSandbox,
		"scanners.sandbox.backend for a new config (none on development hosts without a backend, such as macOS)")
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
				_, err := sb.Command(scanner.Policy{}, "true", nil)
				switch {
				case err != nil:
					fmt.Fprintf(w, "✗ sandbox %v\n", err)
					problems++
				case !scanner.Confined(sb):
					fmt.Fprintf(w, "✗ sandbox %s: scanners parse image content unconfined ('shieldmon plugins' lists the backends)\n", name)
					problems++
				default:
					fmt.Fprintf(w, "• sandbox %s\n", name)
					// A warning, not a problem: the scanners are still confined.
					if err := scanner.SandboxDegraded(sb); err != nil {
						fmt.Fprintf(w, "! sandbox %s is degraded: %v\n", name, err)
					}
				}
			}
			a.doctorScratch(w)
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

// doctorScratch reports the filesystem of the scanners' scratch space. A dedicated one is
// recommended, not required, so this only prints information and warnings.
func (a *app) doctorScratch(w io.Writer) {
	dir := filepath.Join(a.cfg.DataDir, "tmp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(w, "! scratch %s: %v\n", dir, err)
		return
	}
	m, err := scanner.InspectMount(dir)
	switch {
	case err != nil:
		fmt.Fprintf(w, "! scratch %s: %v\n", dir, err)
	case !m.Dedicated:
		fmt.Fprintf(w, "• scratch %s: on the data dir's filesystem; the scratch quota is enforced by watching (a dedicated filesystem bounds it in the kernel: deploy/scratch)\n", dir)
	default:
		fmt.Fprintf(w, "• scratch %s: dedicated filesystem, %.1f GiB\n", dir, float64(m.Size)/(1<<30))
		var missing []string
		for opt, set := range map[string]bool{"noexec": m.NoExec, "nosuid": m.NoSuid, "nodev": m.NoDev} {
			if !set {
				missing = append(missing, opt)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			fmt.Fprintf(w, "! scratch filesystem is not mounted %s\n", strings.Join(missing, ","))
		}
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
			a.preflight(cmd)
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
					Notified map[string]int    `json:"notified,omitempty"`
					NotifyKO map[string]string `json:"notify_failures,omitempty"`
				}{sum.RunID, sum.Status, toResultJSON(sum.Results), sum.Failures, sum.ExpiredDecision, sum.Notified, sum.NotifyFailures})
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
				for _, ch := range slices.Sorted(maps.Keys(sum.Notified)) {
					fmt.Fprintf(cmd.OutOrStdout(), "notified %s: %d event(s)\n", ch, sum.Notified[ch])
				}
				for _, ch := range slices.Sorted(maps.Keys(sum.NotifyFailures)) {
					fmt.Fprintf(cmd.ErrOrStderr(), "notification channel %s: %s\n", ch, sum.NotifyFailures[ch])
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
			a.preflight(cmd)
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

func (a *app) dbCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Manage the scanners' vulnerability DBs",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "update",
		Short: "Refresh vulnerability DBs (the only scanner step with network; monitor, scan and rematch run it first)",
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
			if err := a.engine.UpdateDBs(cmd.Context()); err != nil {
				return fmt.Errorf("vulnerability DB update failed (see 'shieldmon health'): %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "vulnerability DBs up to date")
			return nil
		},
	})
	return cmd
}

func (a *app) pluginsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "plugins",
		Short: "List registered extension plugins (scanners, sandboxes, registry providers, notifiers, report formats)",
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
			fmt.Fprintln(w, "Registry providers:")
			for _, p := range oci.Providers() {
				scope := "configured hosts only"
				if p.Default > 0 {
					scope = fmt.Sprintf("built in, order %d", p.Default)
				}
				opts := ""
				if len(p.Options) > 0 {
					opts = "; options: " + strings.Join(p.Options, ", ")
				}
				fmt.Fprintf(w, "  %-8s %s (%s%s)\n", p.Name, p.Description, scope, opts)
			}
			fmt.Fprintln(w, "Notifiers:")
			for _, n := range notify.Notifiers() {
				opts := ""
				if len(n.Options) > 0 {
					opts = " (options: " + strings.Join(n.Options, ", ") + ")"
				}
				fmt.Fprintf(w, "  %-14s %s%s\n", n.Name, n.Description, opts)
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
			width := 0
			for _, f := range report.Formats() {
				width = max(width, len(f.Name))
			}
			for _, f := range report.Formats() {
				fmt.Fprintf(w, "  %-*s %s\n", width, f.Name, f.Description)
			}
		},
	}
}
