package cli

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/nocs90/shieldmon/internal/redact"
)

// newLogger builds the logger of --log-format and --log-level. Every message and attribute
// goes through redact, whatever the caller did: a log line must never carry a credential.
func newLogger(w io.Writer, format, level string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: lvl, ReplaceAttr: redactAttr}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("--log-format %q: want text or json", format)
}

// redactAttr redacts string and error values, the message included (slog passes it here).
func redactAttr(_ []string, a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, redact.String(v.String()))
	case slog.KindAny:
		switch x := v.Any().(type) {
		case error:
			return slog.String(a.Key, redact.Error(x))
		case fmt.Stringer:
			return slog.String(a.Key, redact.String(x.String()))
		case []string:
			out := make([]string, len(x))
			for i, s := range x {
				out[i] = redact.String(s)
			}
			return slog.Any(a.Key, out)
		}
	}
	return a
}
