package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/priority"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/runtimectx"
	"github.com/nocs90/shieldmon/internal/server"
	"github.com/nocs90/shieldmon/internal/store"
)

// runtimeRefresh is how long the server keeps runtime context before reading the exports again.
const runtimeRefresh = 5 * time.Minute

func (a *app) serveCmd() *cobra.Command {
	var listen string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the API and run monitoring cycles on schedule (docs/processes/server.md)",
		Long: `Serve the API: findings, targets, health and reports to read; triage and decisions,
authored by the authenticated token; monitoring cycles to start. With server.schedule
(the default) a monitoring cycle runs at start and every health.monitor_interval, under
the same lock as 'shieldmon monitor', which skips a cycle while another one runs.

Tokens are configured under server.tokens ('shieldmon serve token' makes one). The server
listens on server.listen (default 127.0.0.1:8484); any other address needs server.tls_cert
and server.tls_key.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			if listen != "" {
				a.cfg.Server.Listen = listen
			}
			return a.serve(cmd)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address to listen on (default server.listen)")
	cmd.AddCommand(a.serveTokenCmd())
	return cmd
}

func (a *app) serveTokenCmd() *cobra.Command {
	var role string
	cmd := &cobra.Command{
		Use:   "token NAME",
		Short: "Make an API token: prints its secret once, and the line to add to server.tokens",
		Long: `Make an API token for NAME (who holds it; decisions made with it name NAME as author).
The secret is printed once: give it to its holder. Only its SHA-256 goes in the
configuration.`,
		Example: "  shieldmon serve token alice --role triager",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secret, sum, err := server.GenerateToken()
			if err != nil {
				return err
			}
			if _, err := server.NewToken(args[0], role, sum); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "secret (shown once, give it to %s): %s\n", args[0], secret)
			fmt.Fprintf(w, "server.tokens entry:\n  - { name: %s, role: %s, sha256: %q }\n", args[0], role, sum)
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "viewer", "viewer, triager or admin")
	return cmd
}

// cliAuthor refuses, on the command line, the names the API records for token holders: the
// audit trail must tell them apart (docs/adr/0031-server-mode.md).
func cliAuthor(name string) error {
	if strings.HasPrefix(name, server.ActorPrefix) {
		return fmt.Errorf("author %q: the %q prefix is reserved for decisions made through the API", name, server.ActorPrefix)
	}
	return nil
}

// serverTokens checks the configured tokens.
func (a *app) serverTokens() (server.Tokens, error) {
	if len(a.cfg.Server.Tokens) == 0 {
		return nil, errors.New("server.tokens is empty: make one with 'shieldmon serve token NAME --role ROLE'")
	}
	var ts server.Tokens
	seen := map[string]bool{}
	for i, t := range a.cfg.Server.Tokens {
		tok, err := server.NewToken(t.Name, t.Role, t.SHA256)
		if err != nil {
			return nil, fmt.Errorf("server.tokens[%d]: %w", i, err)
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("server.tokens[%d]: name %q is listed twice", i, t.Name)
		}
		seen[t.Name] = true
		ts = append(ts, tok)
	}
	return ts, nil
}

// checkListen refuses to send bearer tokens in clear text beyond this host.
func checkListen(addr string, tlsOn bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("server.listen %q: %w", addr, err)
	}
	if tlsOn {
		return nil
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("server.listen %q is not a loopback address: set server.tls_cert and server.tls_key, or put a TLS proxy in front on 127.0.0.1", addr)
}

func (a *app) serve(cmd *cobra.Command) error {
	sc := a.cfg.Server
	tokens, err := a.serverTokens()
	if err != nil {
		return err
	}
	if (sc.TLSCert == "") != (sc.TLSKey == "") {
		return errors.New("server.tls_cert and server.tls_key go together")
	}
	tlsOn := sc.TLSCert != ""
	if err := checkListen(sc.Listen, tlsOn); err != nil {
		return err
	}
	policy, err := a.cfg.Policy()
	if err != nil {
		return err
	}
	var tlsConf *tls.Config
	if tlsOn {
		// Loaded before anything starts: a wrong path must not interrupt a monitoring cycle.
		cert, err := tls.LoadX509KeyPair(sc.TLSCert, sc.TLSKey)
		if err != nil {
			return fmt.Errorf("server.tls_cert/tls_key: %w", err)
		}
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}
	ctx, stop := context.WithCancel(cmd.Context())
	defer stop()
	sched := &scheduler{
		interval: a.cfg.Health.MonitorInterval.Duration, enabled: sc.Schedule,
		cycle: a.cycle, log: a.log, trigger: make(chan struct{}, 1),
	}
	sco := &scorer{a: a, policy: policy}
	h := server.Handler(server.Deps{
		Store: a.store, Policy: policy, Auth: tokens, Score: sco.score,
		Monthly: func(ctx context.Context, at time.Time) (report.Monthly, error) {
			return a.monthlyReport(ctx, logWriter{a.log}, at, time.Now().UTC())
		},
		Status: sched.status, Trigger: sched.start, Log: a.log,
	})
	ln, err := net.Listen("tcp", sc.Listen)
	if err != nil {
		return err
	}
	// What was bound, not what the name resolved to: "localhost" may not be loopback.
	if tcp, ok := ln.Addr().(*net.TCPAddr); !tlsOn && (!ok || !tcp.IP.IsLoopback()) {
		_ = ln.Close()
		return fmt.Errorf("server.listen %q bound %s, not a loopback address: set server.tls_cert and server.tls_key", sc.Listen, ln.Addr())
	}
	srv := &http.Server{
		Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 32 << 10,
		ErrorLog: slog.NewLogLogger(a.log.Handler(), slog.LevelWarn), TLSConfig: tlsConf,
	}
	sched.done.Add(1)
	go sched.run(ctx)
	fmt.Fprintf(cmd.OutOrStdout(), "serving on %s (%s), scheduler %s\n", ln.Addr(), map[bool]string{true: "https", false: "http"}[tlsOn], map[bool]string{true: "on", false: "off"}[sc.Schedule])
	errc := make(chan error, 1)
	go func() {
		if tlsOn {
			errc <- srv.ServeTLS(ln, "", "")
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	var serveErr error
	select {
	case serveErr = <-errc:
	case <-ctx.Done():
	}
	// Stop the scheduler first: a running cycle sees its context cancelled and ends.
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdown)
	sched.wait()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return err
}

// cycle runs one monitoring cycle under the data dir lock, as 'shieldmon monitor' does.
func (a *app) cycle(ctx context.Context) (engine.MonitorSummary, error) {
	unlock, err := a.lock()
	if err != nil {
		return engine.MonitorSummary{}, err
	}
	defer unlock()
	// Followed charts come first in the cycle (docs/adr/0034-chart-tracking.md); read once.
	a.followCharts(os.Stderr)
	return a.engine.Monitor(ctx)
}

// scheduler runs monitoring cycles every interval and on request, one at a time.
type scheduler struct {
	interval time.Duration
	enabled  bool
	cycle    func(context.Context) (engine.MonitorSummary, error)
	log      *slog.Logger
	trigger  chan struct{}

	mu   sync.Mutex
	st   server.Status
	done sync.WaitGroup
}

func (s *scheduler) status() server.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.Scheduler, st.Interval = s.enabled, s.interval
	return st
}

// start asks for a cycle now; false when one is running or already asked for.
func (s *scheduler) start() bool {
	s.mu.Lock()
	running := s.st.Running
	s.mu.Unlock()
	if running {
		return false
	}
	select {
	case s.trigger <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *scheduler) wait() { s.done.Wait() }

// run schedules cycles until ctx ends; the caller adds one to s.done before starting it.
func (s *scheduler) run(ctx context.Context) {
	defer s.done.Done()
	var timer <-chan time.Time
	next := func() {
		if !s.enabled || s.interval <= 0 {
			return
		}
		t := time.NewTimer(s.interval)
		timer = t.C
		s.mu.Lock()
		s.st.NextAt = time.Now().Add(s.interval).UTC()
		s.mu.Unlock()
	}
	if s.enabled {
		s.runOnce(ctx)
	}
	next()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer:
		case <-s.trigger:
		}
		s.runOnce(ctx)
		next()
	}
}

func (s *scheduler) runOnce(ctx context.Context) {
	s.mu.Lock()
	s.st.Running, s.st.LastStarted, s.st.LastError = true, time.Now().UTC(), ""
	s.mu.Unlock()
	sum, err := s.cycle(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Running, s.st.LastFinished = false, time.Now().UTC()
	switch {
	case err != nil:
		s.st.LastStatus, s.st.LastError = "failed", redact.Error(err)
		s.log.Error("monitoring cycle failed", "error", s.st.LastError)
	default:
		s.st.LastStatus, s.st.LastRunID = sum.Status, sum.RunID
		s.log.Info("monitoring cycle done", "run", sum.RunID, "status", sum.Status)
	}
}

// scorer ranks findings with the runtime context of the configured clusters, read again at
// most every runtimeRefresh.
type scorer struct {
	a      *app
	policy lifecycle.Policy

	mu     sync.Mutex
	loaded time.Time
	lookup func(string) (runtimectx.Context, error)
	cache  map[string]*runtimectx.Context
}

func (s *scorer) score(f store.Finding) priority.Score {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.loaded) > runtimeRefresh {
		set, _ := s.a.runtimeSet(logWriter{s.a.log})
		s.lookup = report.RuntimeLookup(context.Background(), s.a.store, set)
		s.cache, s.loaded = map[string]*runtimectx.Context{}, time.Now()
	}
	c, ok := s.cache[f.Digest]
	if !ok {
		if rt, err := s.lookup(f.Digest); err == nil && rt.Running {
			c = &rt
		}
		s.cache[f.Digest] = c
	}
	return findingScore(s.policy, f, c, time.Now())
}

// logWriter turns warnings meant for stderr into log records.
type logWriter struct{ log *slog.Logger }

func (w logWriter) Write(p []byte) (int, error) {
	w.log.Warn(string(trimNewline(p)))
	return len(p), nil
}

func trimNewline(p []byte) []byte {
	for len(p) > 0 && (p[len(p)-1] == '\n' || p[len(p)-1] == '\r') {
		p = p[:len(p)-1]
	}
	return p
}

var _ io.Writer = logWriter{}
