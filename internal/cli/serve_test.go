package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/engine"
)

// syncBuffer is a bytes.Buffer safe for a goroutine writing while the test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestServe(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	common := []string{"--config", cfg, "--data-dir", filepath.Join(dir, "data")}
	runc := func(args ...string) (string, string, int) { return run(t, append(args, common...)...) }
	if _, errOut, code := runc("init", "--sandbox", "none"); code != 0 {
		t.Fatal(errOut)
	}
	if _, errOut, code := runc("serve"); code == 0 || !strings.Contains(errOut, "server.tokens is empty") {
		t.Errorf("no tokens: %s", errOut)
	}
	out, errOut, code := runc("serve", "token", "alice", "--role", "triager")
	secret := regexp.MustCompile(`smt_[A-Za-z0-9_-]{43}`).FindString(out)
	entry := regexp.MustCompile(`- \{ name: alice, role: triager, sha256: "[0-9a-f]{64}" \}`).FindString(out)
	if code != 0 || secret == "" || entry == "" {
		t.Fatalf("token: code=%d err=%s\n%s", code, errOut, out)
	}
	if _, errOut, code := runc("serve", "token", "Alice"); code == 0 || !strings.Contains(errOut, "lowercase") {
		t.Errorf("token names are checked: %s", errOut)
	}
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	conf := strings.Replace(string(b), "  schedule: true ", "  schedule: false ", 1)
	conf = strings.Replace(conf, "  tokens: []\n", "  tokens:\n    "+entry+"\n", 1)
	if err := os.WriteFile(cfg, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := runc("serve", "--listen", "0.0.0.0:0"); code == 0 || !strings.Contains(errOut, "not a loopback address") {
		t.Errorf("clear-text tokens beyond loopback: %s", errOut)
	}
	withTLS := strings.Replace(conf, "  tls_cert: \"\"\n  tls_key: \"\"\n", "  tls_cert: /nonexistent.crt\n  tls_key: /nonexistent.key\n", 1)
	if err := os.WriteFile(cfg, []byte(withTLS), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := runc("serve", "--listen", "127.0.0.1:0"); code == 0 || !strings.Contains(errOut, "tls_cert/tls_key") {
		t.Errorf("a wrong certificate fails before anything starts: %s", errOut)
	}
	if err := os.WriteFile(cfg, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := runc("findings", "accept-risk", "1", "--author", "api:alice", "--justification", "pretending to be a token"); code == 0 || !strings.Contains(errOut, "reserved") {
		t.Errorf("the API's author names are reserved: %s", errOut)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- Execute(ctx, append([]string{"serve", "--listen", "127.0.0.1:0"}, common...), &stdout, &stderr)
	}()
	serving := regexp.MustCompile(`serving on (127\.0\.0\.1:\d+)`)
	addr := ""
	for deadline := time.Now().Add(10 * time.Second); addr == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if m := serving.FindStringSubmatch(stdout.String()); m != nil {
			addr = m[1]
		}
	}
	if addr == "" || !strings.Contains(stdout.String(), "scheduler off") {
		cancel()
		t.Fatalf("server did not start: %s %s", stdout.String(), stderr.String())
	}
	get := func(path, token string) (int, string) {
		req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, body := get("/api/v1/status", secret); code != 200 || !strings.Contains(body, `"scheduler": false`) {
		t.Errorf("status: %d %s", code, body)
	}
	if code, _ := get("/api/v1/findings", ""); code != 401 {
		t.Errorf("unauthenticated: %d", code)
	}
	if code, body := get("/api/v1/reports/monthly?format=md", secret); code != 200 || !strings.Contains(body, "# Container vulnerability ConMon report") {
		t.Errorf("report: %d %.200s", code, body)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("shutdown: code %d, %s", code, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
	if strings.Contains(stderr.String(), secret) {
		t.Error("the secret reached the logs")
	}
}

func TestScheduler(t *testing.T) {
	var mu sync.Mutex
	runs := 0
	release := make(chan struct{})
	s := &scheduler{
		interval: time.Hour, enabled: false, log: slog.New(slog.DiscardHandler), trigger: make(chan struct{}, 1),
		cycle: func(context.Context) (engine.MonitorSummary, error) {
			mu.Lock()
			runs++
			n := runs
			mu.Unlock()
			<-release
			if n == 2 {
				return engine.MonitorSummary{}, errors.New("another shieldmon process holds the lock")
			}
			return engine.MonitorSummary{RunID: int64(n), Status: "ok"}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.done.Add(1)
	go s.run(ctx)
	if !s.start() {
		t.Fatal("first request starts a cycle")
	}
	waitFor(t, func() bool { return s.status().Running })
	if s.start() {
		t.Error("no second cycle while one runs")
	}
	release <- struct{}{}
	waitFor(t, func() bool { st := s.status(); return !st.Running && st.LastRunID == 1 && st.LastStatus == "ok" })
	if !s.start() {
		t.Fatal("a cycle can start again")
	}
	release <- struct{}{}
	waitFor(t, func() bool {
		st := s.status()
		return st.LastStatus == "failed" && strings.Contains(st.LastError, "lock")
	})
	if st := s.status(); st.Scheduler || !st.NextAt.IsZero() {
		t.Errorf("a disabled schedule has no next cycle: %+v", st)
	}
	cancel()
	s.wait()
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal("condition not reached")
}

func TestCheckListen(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:8484": true, "[::1]:8484": true, "localhost:1": true, "0.0.0.0:8484": false, "10.0.0.5:80": false, ":8484": false, "nope": false} {
		if err := checkListen(addr, false); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if err := checkListen("0.0.0.0:8443", true); err != nil {
		t.Errorf("TLS on any address: %v", err)
	}
}
