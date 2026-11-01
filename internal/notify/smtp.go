package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

func init() {
	RegisterNotifier(Plugin{
		Name:        "smtp",
		Description: "e-mail through an SMTP relay, TLS required (STARTTLS on 587, implicit TLS on 465)",
		Options:     []string{"host", "port", "tls", "from", "to", "username", "password_env"},
		New:         newSMTP,
	})
}

// smtpMailer sends each message as a plain-text e-mail. TLS is never optional: with
// tls: starttls (the default) a server that does not offer STARTTLS is refused, there is no
// fallback to plaintext, and credentials are only sent over TLS.
type smtpMailer struct {
	host      string
	port      int
	implicit  bool
	from      *mail.Address
	to        []*mail.Address
	username  string
	password  string
	tlsConfig *tls.Config
}

func newSMTP(s Spec) (Notifier, error) {
	m := &smtpMailer{}
	var err error
	if m.host, err = s.Options.String("host", ""); err != nil {
		return nil, err
	}
	if m.host == "" || strings.ContainsAny(m.host, "/:@ \r\n") {
		return nil, errors.New("option host: want a host name (the port goes in port)")
	}
	mode, err := s.Options.String("tls", "starttls")
	if err != nil {
		return nil, err
	}
	switch mode {
	case "starttls":
	case "implicit":
		m.implicit = true
	default:
		return nil, fmt.Errorf("option tls: want starttls or implicit, got %q (plaintext is not supported)", mode)
	}
	def := 587
	if m.implicit {
		def = 465
	}
	if m.port, err = s.Options.Int("port", def); err != nil {
		return nil, err
	}
	if m.port < 1 || m.port > 65535 {
		return nil, errors.New("option port: out of range")
	}
	from, err := s.Options.String("from", "")
	if err != nil {
		return nil, err
	}
	if m.from, err = parseAddress("from", from); err != nil {
		return nil, err
	}
	to, err := s.Options.Strings("to")
	if err != nil {
		return nil, err
	}
	if len(to) == 0 || len(to) > 50 {
		return nil, errors.New("option to: want 1 to 50 recipients")
	}
	for _, a := range to {
		addr, err := parseAddress("to", a)
		if err != nil {
			return nil, err
		}
		m.to = append(m.to, addr)
	}
	if m.username, err = s.Options.String("username", ""); err != nil {
		return nil, err
	}
	if m.password, err = s.Secret("password_env"); err != nil {
		return nil, err
	}
	if (m.username == "") != (m.password == "") {
		return nil, errors.New("options username and password_env go together")
	}
	m.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if s.TLS != nil {
		m.tlsConfig = s.TLS.Clone()
		m.tlsConfig.MinVersion = max(m.tlsConfig.MinVersion, tls.VersionTLS12)
	}
	m.tlsConfig.ServerName = m.host
	return m, nil
}

func parseAddress(key, v string) (*mail.Address, error) {
	if strings.ContainsAny(v, "\r\n") {
		return nil, fmt.Errorf("option %s: invalid address", key)
	}
	a, err := mail.ParseAddress(v)
	if err != nil {
		return nil, fmt.Errorf("option %s: invalid address %q", key, v)
	}
	return a, nil
}

func (m *smtpMailer) Send(ctx context.Context, msg Message) error {
	data, err := m.compose(msg)
	if err != nil {
		return err
	}
	if err := m.deliver(ctx, data); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("smtp %s: %w", m.host, ctx.Err())
		}
		return err
	}
	return nil
}

// deliver runs one SMTP session. Server replies are not repeated in errors (a server may echo
// what it was sent): only the step and the reply code.
func (m *smtpMailer) deliver(ctx context.Context, data []byte) error {
	addr := net.JoinHostPort(m.host, strconv.Itoa(m.port))
	d := net.Dialer{Timeout: SendTimeout}
	var conn net.Conn
	var err error
	if m.implicit {
		td := tls.Dialer{NetDialer: &d, Config: m.tlsConfig}
		conn, err = td.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp %s: connect: %s", m.host, transportError(err))
	}
	defer func() { _ = conn.Close() }()
	// net/smtp has no context: the deadline bounds the session, cancellation closes it.
	deadline := time.Now().Add(SendTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	step := "greeting"
	fail := func(err error) error {
		var te *textproto.Error
		if errors.As(err, &te) {
			return fmt.Errorf("smtp %s: %s: server answered %d", m.host, step, te.Code)
		}
		return fmt.Errorf("smtp %s: %s: %s", m.host, step, transportError(err))
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = c.Close() }()
	step = "EHLO"
	if err := c.Hello("shieldmon"); err != nil {
		return fail(err)
	}
	if !m.implicit {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp %s: the server does not offer STARTTLS; plaintext is not supported", m.host)
		}
		step = "STARTTLS"
		if err := c.StartTLS(m.tlsConfig); err != nil {
			return fail(err)
		}
	}
	if m.username != "" {
		step = "AUTH"
		if err := c.Auth(smtp.PlainAuth("", m.username, m.password, m.host)); err != nil {
			return fail(err)
		}
	}
	step = "MAIL FROM"
	if err := c.Mail(m.from.Address); err != nil {
		return fail(err)
	}
	step = "RCPT TO"
	for _, to := range m.to {
		if err := c.Rcpt(to.Address); err != nil {
			return fail(err)
		}
	}
	step = "DATA"
	w, err := c.Data()
	if err != nil {
		return fail(err)
	}
	if _, err := w.Write(data); err != nil {
		return fail(err)
	}
	if err := w.Close(); err != nil {
		return fail(err)
	}
	step = "QUIT"
	if err := c.Quit(); err != nil {
		return fail(err)
	}
	return nil
}

// Bounds of hostile text in e-mail.
const (
	maxSubjectRunes = 200
	maxLineRunes    = 500
)

// compose builds the e-mail. Header values come from configuration (addresses, validated) or
// are cleaned of control characters and RFC 2047-encoded (the subject); the body is
// quoted-printable plain text whose lines are cleaned.
func (m *smtpMailer) compose(msg Message) ([]byte, error) {
	var b bytes.Buffer
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	to := make([]string, len(m.to))
	for i, a := range m.to {
		to[i] = a.String()
	}
	header := [][2]string{
		{"From", m.from.String()},
		{"To", strings.Join(to, ", ")},
		{"Subject", mime.QEncoding.Encode("utf-8", Clean(msg.Subject(), maxSubjectRunes))},
		{"Date", msg.SentAt.UTC().Format(time.RFC1123Z)},
		{"Message-ID", "<" + hex.EncodeToString(id) + "@shieldmon.invalid>"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "quoted-printable"},
		{"Auto-Submitted", "auto-generated"},
		{"X-ShieldMon-Delivery", DeliveryID(msg)},
	}
	for _, h := range header {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	line := func(s string) {
		_, _ = qp.Write([]byte(Clean(s, maxLineRunes) + "\r\n"))
	}
	if msg.Test {
		line("This is a test message from ShieldMon for notification channel " + msg.Channel + ".")
		line("If you received it, the channel works.")
	}
	for i, e := range msg.Events {
		if i > 0 {
			line("")
		}
		line(e.Title())
		for _, l := range e.Lines() {
			line("  " + l)
		}
	}
	line("")
	line("-- ")
	line("ShieldMon, channel " + msg.Channel)
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
