package notify_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/notify/notifytest"
)

const smtpPassword = "smtp-relay-password-0123"

func smtpChannel(t *testing.T, srv *notifytest.SMTPServer, opts map[string]any) (notify.Channel, error) {
	t.Helper()
	o := map[string]any{
		"host": srv.Host, "port": srv.Port, "from": "ShieldMon <shieldmon@example.com>",
		"to": []any{"secops@example.com", "Platform <platform@example.com>"}, "username": "shieldmon", "password_env": "SMTP_PASSWORD",
	}
	for k, v := range opts {
		o[k] = v
	}
	chs, err := notify.NewChannels([]notify.ChannelConfig{{Name: "mail", Notifier: "smtp", Options: o}},
		notify.Spec{TLS: srv.TLS, Env: func(k string) string {
			if k == "SMTP_PASSWORD" {
				return smtpPassword
			}
			return ""
		}})
	if err != nil {
		return notify.Channel{}, err
	}
	return chs[0], nil
}

func mustSMTP(t *testing.T, srv *notifytest.SMTPServer) notify.Notifier {
	t.Helper()
	ch, err := smtpChannel(t, srv, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ch.Sender
}

func TestSMTPConformance(t *testing.T) {
	ok := notifytest.NewSMTPServer(t, notifytest.Accept, "shieldmon", smtpPassword)
	notifytest.CheckNotifier(t, notifytest.Fixture{
		Name:     "smtp",
		Notifier: mustSMTP(t, ok),
		Received: ok.Mail,
		Failing:  mustSMTP(t, notifytest.NewSMTPServer(t, notifytest.Reject, "shieldmon", smtpPassword)),
		Hanging:  mustSMTP(t, notifytest.NewSMTPServer(t, notifytest.Hang, "shieldmon", smtpPassword)),
		Secret:   smtpPassword,
	})
	mail := ok.Mail()[0]
	for _, want := range []string{
		"From: \"ShieldMon\" <shieldmon@example.com>\n",
		"To: <secops@example.com>, \"Platform\" <platform@example.com>\n",
		"Subject: =?utf-8?q?ShieldMon:_New_known_exploited_vulnerability:_CVE-2024-3094",
		"Auto-Submitted: auto-generated\n",
		"No fix available yet",
	} {
		if !strings.Contains(mail, want) {
			t.Errorf("mail lacks %q:\n%s", want, mail)
		}
	}
}

func TestSMTPRequiresTLS(t *testing.T) {
	plain := notifytest.NewSMTPServer(t, notifytest.Plaintext, "shieldmon", smtpPassword)
	n := mustSMTP(t, plain)
	err := n.Send(context.Background(), notify.Message{Channel: "mail", Test: true, SentAt: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") {
		t.Fatalf("a server without STARTTLS must be refused, got %v", err)
	}
	if len(plain.Mail()) != 0 {
		t.Fatal("nothing may be sent in plaintext")
	}

	// A certificate the client does not trust fails the handshake.
	ok := notifytest.NewSMTPServer(t, notifytest.Accept, "shieldmon", smtpPassword)
	untrusted, err := notify.NewChannels([]notify.ChannelConfig{{Name: "mail", Notifier: "smtp", Options: map[string]any{
		"host": ok.Host, "port": ok.Port, "from": "a@example.com", "to": "b@example.com",
	}}}, notify.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	if err := untrusted[0].Sender.Send(context.Background(), notify.Message{Channel: "mail", Test: true, SentAt: time.Now()}); err == nil {
		t.Fatal("an untrusted certificate must fail")
	}

	srv := notifytest.NewSMTPServer(t, notifytest.Accept, "shieldmon", smtpPassword)
	for what, opts := range map[string]map[string]any{
		"plaintext mode":        {"tls": "none"},
		"header injection":      {"from": "a@example.com\r\nBcc: victim@example.com"},
		"no recipients":         {"to": []any{}},
		"user without password": {"password_env": "UNSET_VARIABLE"},
		"port in host":          {"host": "smtp.example.com:25"},
	} {
		if _, err := smtpChannel(t, srv, opts); err == nil {
			t.Errorf("%s: must be refused", what)
		}
	}
}
