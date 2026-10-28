package notifytest

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Plaintext is an SMTPServer mode: a server that does not offer STARTTLS.
const Plaintext Mode = 100

// SMTPServer is a fake SMTP relay on 127.0.0.1 offering STARTTLS (a certificate TLS trusts)
// and AUTH PLAIN after it. It records each mail with its body decoded.
type SMTPServer struct {
	Host string
	Port int
	// TLS trusts the server's certificate.
	TLS  *tls.Config
	mu   sync.Mutex
	mail []string
}

// NewSMTPServer starts a server answering in mode (Accept, Reject: AUTH refused while echoing
// the credentials, Hang: no greeting, Plaintext: no STARTTLS) for user and password; it stops
// at the end of the test.
func NewSMTPServer(t *testing.T, mode Mode, user, password string) *SMTPServer {
	t.Helper()
	// httptest's certificate is valid for 127.0.0.1.
	certSrv := httptest.NewTLSServer(http.NotFoundHandler())
	serverTLS := &tls.Config{Certificates: certSrv.TLS.Certificates, MinVersion: tls.VersionTLS12}
	clientTLS := certSrv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	certSrv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &SMTPServer{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, TLS: clientTLS}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	t.Cleanup(func() {
		close(stop)
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				go func() { <-stop; _ = conn.Close() }()
				s.session(conn, mode, serverTLS, user, password)
			}()
		}
	}()
	return s
}

func (s *SMTPServer) session(conn net.Conn, mode Mode, serverTLS *tls.Config, user, password string) {
	if mode == Hang {
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	tp := textproto.NewConn(conn)
	secure := false
	reply := func(format string, args ...any) { _ = tp.PrintfLine(format, args...) }
	reply("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			switch {
			case secure:
				reply("250-fake\r\n250 AUTH PLAIN")
			case mode == Plaintext:
				reply("250-fake\r\n250 AUTH PLAIN")
			default:
				reply("250-fake\r\n250 STARTTLS")
			}
		case "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(conn, serverTLS)
			if tc.Handshake() != nil {
				return
			}
			conn, secure = tc, true
			tp = textproto.NewConn(tc)
		case "AUTH":
			creds, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(arg, "PLAIN "))
			parts := strings.Split(string(creds), "\x00")
			if mode == Reject || len(parts) != 3 || parts[1] != user || parts[2] != password {
				reply("535 5.7.8 rejected %q", creds)
				continue
			}
			reply("235 ok")
		case "MAIL", "RCPT":
			reply("250 ok")
		case "DATA":
			reply("354 go ahead")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			s.record(data)
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unknown")
		}
	}
}

func (s *SMTPServer) record(data []byte) {
	head, body, _ := strings.Cut(string(data), "\n\n")
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if err != nil {
		decoded = []byte(body)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mail = append(s.mail, head+"\n\n"+string(decoded))
}

// Mail returns the mails received so far: headers, then the decoded body.
func (s *SMTPServer) Mail() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.mail...)
}

// Addr is host:port.
func (s *SMTPServer) Addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }
