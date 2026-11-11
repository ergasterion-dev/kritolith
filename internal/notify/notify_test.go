package notify

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http/httptest"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// fakeSMTP is a small in-process mail server. It records what a
// client sent so tests can assert on the real bytes on the wire.
type fakeSMTP struct {
	ln       net.Listener
	startTLS *tls.Config // nil: STARTTLS is not offered
	implicit bool        // TLS from the first byte (port 465 style)
	rejectTo string

	mu       sync.Mutex
	from     string
	to       []string
	data     []byte
	authLine string
	sawTLS   bool
}

// newFakeSMTP starts a server. configure runs before it accepts
// anything, so the options are never changed under a running server.
func newFakeSMTP(t *testing.T, configure ...func(*fakeSMTP)) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	for _, c := range configure {
		c(f)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if f.implicit {
		tc := tls.Server(c, f.startTLS)
		if tc.Handshake() != nil {
			return
		}
		c = tc
		f.mu.Lock()
		f.sawTLS = true
		f.mu.Unlock()
	}
	r := bufio.NewReader(c)
	say := func(s string) { io.WriteString(c, s+"\r\n") }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "EHLO", "HELO":
			f.mu.Lock()
			tlsOn := f.sawTLS
			f.mu.Unlock()
			if f.startTLS != nil && !tlsOn {
				say("250-fake")
				say("250-STARTTLS")
				say("250 AUTH PLAIN")
			} else {
				say("250-fake")
				say("250 AUTH PLAIN")
			}
		case "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, f.startTLS)
			if tc.Handshake() != nil {
				return
			}
			c, r = tc, bufio.NewReader(tc)
			f.mu.Lock()
			f.sawTLS = true
			f.mu.Unlock()
		case "AUTH":
			f.mu.Lock()
			f.authLine = line
			f.mu.Unlock()
			say("235 ok")
		case "MAIL":
			f.mu.Lock()
			f.from = line
			f.mu.Unlock()
			say("250 ok")
		case "RCPT":
			if f.rejectTo != "" && strings.Contains(line, f.rejectTo) {
				say("550 no such user")
				continue
			}
			f.mu.Lock()
			f.to = append(f.to, line)
			f.mu.Unlock()
			say("250 ok")
		case "DATA":
			say("354 send it")
			var buf bytes.Buffer
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				buf.WriteString(strings.TrimPrefix(l, "."))
			}
			f.mu.Lock()
			f.data = buf.Bytes()
			f.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("502 what")
		}
	}
}

func (f *fakeSMTP) addr() string { return f.ln.Addr().String() }

// got is what the server has received so far.
type got struct {
	from, authLine string
	to             []string
	data           []byte
	sawTLS         bool
}

func (f *fakeSMTP) got() got {
	f.mu.Lock()
	defer f.mu.Unlock()
	return got{from: f.from, authLine: f.authLine, to: append([]string(nil), f.to...), data: append([]byte(nil), f.data...), sawTLS: f.sawTLS}
}

// testTLS returns a server config and a client config that trusts it,
// for a certificate valid for example.com and 127.0.0.1.
func testTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &tls.Config{Certificates: srv.TLS.Certificates}, &tls.Config{RootCAs: pool, ServerName: "example.com"}
}

func testMessage() Message {
	return Message{
		To:      []string{"sec@example.org", "second@example.org"},
		Report:  report.Report{ID: "R1", Repo: "owner/name", Title: "Over-read in parser\r\nBcc: attacker@evil.example \x1b[31m"},
		Verdict: report.Verdict{ReportID: "R1", Outcome: report.OutcomeGroundingFailed},
		Text:    "Kritolith: GROUNDING_FAILED at v1\n• function p.X — not declared\n.\n.leading dot line\n" + strings.Repeat("long ", 400) + "\n",
		SentAt:  time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC),
	}
}

func parse(t *testing.T, raw []byte) (*mail.Message, string, []byte) {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the message sent is not valid mail: %v\n%s", err, raw)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	decode := func(r io.Reader) []byte {
		b, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, r))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if mediaType == "text/plain" {
		return msg, string(decode(msg.Body)), nil
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	p1, err := mr.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	text := decode(p1)
	p2, err := mr.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p2.Header.Get("Content-Disposition"), `filename="verdict.tar"`) {
		t.Errorf("attachment header = %v", p2.Header)
	}
	return msg, string(text), decode(p2)
}

func TestSendToLoopbackWithoutTLS(t *testing.T) {
	f := newFakeSMTP(t)
	s, err := NewSender(Config{Addr: f.addr(), From: "kritolith@example.org"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := testMessage()
	if err := s.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.got().from, "<kritolith@example.org>") || len(f.got().to) != 2 || !strings.Contains(f.got().to[1], "<second@example.org>") {
		t.Errorf("envelope: %q -> %q", f.got().from, f.got().to)
	}
	for _, line := range strings.Split(string(f.got().data), "\r\n") {
		if len(line) > 200 {
			t.Fatalf("a %d-byte line was sent; SMTP allows 998 and careful servers less", len(line))
		}
	}
	msg, text, bundle := parse(t, f.got().data)
	if bundle != nil {
		t.Error("an unsigned verdict was sent with an attachment")
	}
	// The hostile title must not have added a header or kept its
	// control characters.
	if msg.Header.Get("Bcc") != "" || len(msg.Header) != 10 {
		t.Errorf("headers = %v", msg.Header)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(subject, "[kritolith] GROUNDING_FAILED: Over-read in parser") || !strings.HasSuffix(subject, "(owner/name)") || strings.ContainsAny(subject, "\r\n\x1b") {
		t.Errorf("subject = %q", subject)
	}
	if msg.Header.Get("Auto-Submitted") != "auto-generated" || msg.Header.Get("X-Kritolith-Report") != "R1" {
		t.Errorf("headers = %v", msg.Header)
	}
	// The body arrives intact, including lines that are a lone dot.
	if !strings.Contains(text, "• function p.X — not declared\r\n.\r\n.leading dot line\r\n") {
		t.Errorf("body = %q", text)
	}
	if !strings.Contains(text, "does not decide") {
		t.Errorf("body lacks the standing notice: %q", text)
	}
}

func TestSendWithSTARTTLSAuthAndBundle(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.startTLS = serverTLS })
	s, err := NewSender(Config{Addr: "example.com:587", From: "kritolith@example.org", Username: "user", PasswordEnv: "SMTP_PW"},
		func(name string) string { return map[string]string{"SMTP_PW": "s3cret"}[name] })
	if err != nil {
		t.Fatal(err)
	}
	s.tlsConfig = clientTLS
	s.dial = func(ctx context.Context, addr string) (net.Conn, error) { return net.Dial("tcp", f.addr()) }
	m := testMessage()
	m.Bundle = []byte("tar bytes \x00\x01\x02")
	if err := s.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if !f.got().sawTLS {
		t.Fatal("the message was not sent over TLS")
	}
	want := base64.StdEncoding.EncodeToString([]byte("\x00user\x00s3cret"))
	if !strings.Contains(f.got().authLine, want) {
		t.Errorf("auth = %q", f.got().authLine)
	}
	_, text, bundle := parse(t, f.got().data)
	if !bytes.Equal(bundle, m.Bundle) {
		t.Errorf("attachment = %q", bundle)
	}
	if !strings.Contains(text, "verify-bundle") {
		t.Errorf("body doesn't say how to check the bundle: %q", text)
	}
}

func TestSendImplicitTLS(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.startTLS, f.implicit = serverTLS, true })
	s, err := NewSender(Config{Addr: "example.com:465", From: "kritolith@example.org"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.tlsConfig = clientTLS
	s.dial = func(ctx context.Context, addr string) (net.Conn, error) { return net.Dial("tcp", f.addr()) }
	if err := s.Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	if !f.got().sawTLS || len(f.got().data) == 0 {
		t.Fatal("nothing was delivered over TLS")
	}
}

// A remote server with no TLS must get neither the verdict nor a
// password.
func TestSendRefusesCleartextToRemote(t *testing.T) {
	f := newFakeSMTP(t) // offers no STARTTLS
	for name, cfg := range map[string]Config{
		"no auth":   {Addr: "mail.example.org:25", From: "kritolith@example.org"},
		"with auth": {Addr: "mail.example.org:25", From: "kritolith@example.org", Username: "u", PasswordEnv: "PW"},
	} {
		s, err := NewSender(cfg, func(string) string { return "pw" })
		if err != nil {
			t.Fatal(err)
		}
		s.dial = func(ctx context.Context, addr string) (net.Conn, error) { return net.Dial("tcp", f.addr()) }
		err = s.Send(context.Background(), testMessage())
		if err == nil || !strings.Contains(err.Error(), "does not offer TLS") {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(f.got().data) != 0 || f.got().authLine != "" || f.got().from != "" {
			t.Errorf("%s: something was sent in the clear: auth %q, from %q", name, f.got().authLine, f.got().from)
		}
	}
}

// A certificate that doesn't check out is a failure, not a reason to
// fall back to cleartext.
func TestSendRefusesUntrustedCertificate(t *testing.T) {
	serverTLS, _ := testTLS(t)
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.startTLS = serverTLS })
	s, err := NewSender(Config{Addr: "example.com:587", From: "kritolith@example.org"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.dial = func(ctx context.Context, addr string) (net.Conn, error) { return net.Dial("tcp", f.addr()) }
	if err := s.Send(context.Background(), testMessage()); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v", err)
	}
	if len(f.got().data) != 0 {
		t.Fatal("the message was sent despite a bad certificate")
	}
}

func TestSendErrors(t *testing.T) {
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.rejectTo = "second@" })
	s, _ := NewSender(Config{Addr: f.addr(), From: "kritolith@example.org"}, nil)
	if err := s.Send(context.Background(), testMessage()); err == nil || !strings.Contains(err.Error(), "refused recipient second@example.org") {
		t.Errorf("rejected recipient: err = %v", err)
	}
	m := testMessage()
	m.To = nil
	if err := s.Send(context.Background(), m); err == nil {
		t.Error("sent with no recipients")
	}
	m.To = []string{"x@example.org\r\nRCPT TO:<evil@example.org>"}
	if err := s.Send(context.Background(), m); err == nil {
		t.Error("accepted a recipient with a line break")
	}
	dead, _ := NewSender(Config{Addr: "127.0.0.1:1", From: "kritolith@example.org"}, nil)
	if err := dead.Send(context.Background(), testMessage()); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Errorf("unreachable server: err = %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	if err := (Config{}).Validate(); err != nil {
		t.Errorf("an absent section must be valid: %v", err)
	}
	ok := Config{Addr: "mail.example.org:587", From: "k@example.org", Username: "u", PasswordEnv: "PW"}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"no port":           func(c *Config) { c.Addr = "mail.example.org" },
		"empty host":        func(c *Config) { c.Addr = ":587" },
		"from with name":    func(c *Config) { c.From = "Kritolith <k@example.org>" },
		"from not address":  func(c *Config) { c.From = "nope" },
		"from with newline": func(c *Config) { c.From = "k@example.org\r\nBcc: x@y.z" },
		"user, no password": func(c *Config) { c.PasswordEnv = "" },
		"password, no user": func(c *Config) { c.Username = "" },
	} {
		c := ok
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewSender(ok, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "PW") {
		t.Errorf("empty password variable: err = %v", err)
	}
	if _, err := NewSender(Config{}, nil); err == nil {
		t.Error("a sender with no config")
	}
}
