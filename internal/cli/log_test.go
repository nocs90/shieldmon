package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestJSONLogsAreRedacted: whatever reaches the logger, JSON lines carry no credential.
func TestJSONLogsAreRedacted(t *testing.T) {
	const secret = "hunter2-s3cr3t"
	var buf bytes.Buffer
	log, err := newLogger(&buf, "json", "debug")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("fetch https://user:"+secret+"@registry.test/v2/ failed",
		"err", errors.New("401 for https://ci:"+secret+"@mirror.test/listing.json"),
		"detail", "Authorization: Bearer "+secret,
		"errors", []string{"token=" + secret},
		"count", 3)
	log.Debug("nested", "scan", map[string]string{"k": "v"})
	out := buf.String() // read before the scanner drains the buffer
	sc := bufio.NewScanner(strings.NewReader(out))
	lines := 0
	for sc.Scan() {
		lines++
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not one JSON object per line: %q", sc.Text())
		}
		if m["level"] == nil || m["msg"] == nil || m["time"] == nil {
			t.Errorf("standard keys: %v", m)
		}
	}
	if lines != 2 {
		t.Fatalf("lines = %d", lines)
	}
	if strings.Contains(out, secret) {
		t.Errorf("a credential reached the log:\n%s", out)
	}
	if !strings.Contains(out, `"count":3`) || !strings.Contains(out, `"scan":{"k":"v"}`) {
		t.Errorf("other values are kept as they are:\n%s", out)
	}
}

func TestTextLogsAreRedactedToo(t *testing.T) {
	var buf bytes.Buffer
	log, err := newLogger(&buf, "text", "info")
	if err != nil {
		t.Fatal(err)
	}
	log.Warn("x", "err", errors.New("https://u:p4ssw0rd-x@h.test/"))
	if strings.Contains(buf.String(), "p4ssw0rd-x") {
		t.Errorf("text: %s", buf.String())
	}
	if _, err := newLogger(&buf, "xml", "info"); err == nil {
		t.Error("unknown format")
	}
	if _, err := newLogger(&buf, "json", "loud"); err == nil {
		t.Error("unknown level")
	}
}

func TestLogFormatFlag(t *testing.T) {
	dir := t.TempDir()
	common := []string{"--config", dir + "/config.yaml", "--data-dir", dir + "/data"}
	if _, errOut, code := run(t, append([]string{"init", "--sandbox", "none"}, common...)...); code != 0 {
		t.Fatal(errOut)
	}
	_, errOut, code := run(t, append([]string{"health", "--log-format", "json", "--log-level", "debug"}, common...)...)
	if code != 0 {
		t.Fatalf("health: %s", errOut)
	}
	for _, l := range strings.Split(strings.TrimSpace(errOut), "\n") {
		if l != "" && !json.Valid([]byte(l)) {
			t.Errorf("stderr line is not JSON: %q", l)
		}
	}
	if _, errOut, code := run(t, append([]string{"health", "--log-format", "logfmt"}, common...)...); code != 1 || !strings.Contains(errOut, "want text or json") {
		t.Errorf("unknown format: %d %s", code, errOut)
	}
}
