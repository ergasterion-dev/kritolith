// Package notify delivers a verdict to a project's maintainers by
// email. A verdict describes an unfixed vulnerability, so mail leaves
// the machine only over TLS, or to a server on the machine itself.
package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

const (
	dialTimeout    = 15 * time.Second
	sessionTimeout = 60 * time.Second
	maxSubject     = 150 // runes of report title in the subject
)

// Config is the "smtp" section of kritolith.json.
type Config struct {
	// Addr is the mail server as host:port. Port 465 means TLS from
	// the first byte; any other port means STARTTLS.
	Addr string `json:"addr"`
	// From is the sender address.
	From string `json:"from"`
	// Username and PasswordEnv are optional. The password is read from
	// the named environment variable, never from the config file.
	Username    string `json:"username,omitempty"`
	PasswordEnv string `json:"password_env,omitempty"`
}

// Configured reports whether an smtp section was given at all.
func (c Config) Configured() bool { return c != Config{} }

// Validate checks a configured section.
func (c Config) Validate() error {
	if !c.Configured() {
		return nil
	}
	host, port, err := net.SplitHostPort(c.Addr)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("smtp.addr %q must be host:port", c.Addr)
	}
	if _, err := parseBareAddress(c.From); err != nil {
		return fmt.Errorf("smtp.from: %w", err)
	}
	if (c.Username == "") != (c.PasswordEnv == "") {
		return errors.New("smtp.username and smtp.password_env must be given together")
	}
	return nil
}

// parseBareAddress accepts "user@host" and returns it. A display name
// is refused: the value goes into SMTP commands, where only the bare
// address belongs.
func parseBareAddress(s string) (string, error) {
	a, err := mail.ParseAddress(s)
	if err != nil {
		return "", fmt.Errorf("%q is not an email address", s)
	}
	if a.Name != "" || a.Address != strings.TrimSpace(s) || strings.ContainsAny(a.Address, "\r\n <>") {
		return "", fmt.Errorf("%q must be a bare address like user@example.org", s)
	}
	return a.Address, nil
}

// Message is one verdict to deliver.
type Message struct {
	To       []string // maintainers' addresses, already validated by config
	Report   report.Report
	Verdict  report.Verdict
	Text     string // the rendered verdict
	Bundle   []byte // the signed evidence bundle, or nil if the verdict is unsigned
	SentAt   time.Time
	Hostname string // for the Message-ID; empty means the From address's domain
}

// Sender delivers messages through one SMTP server.
type Sender struct {
	cfg      Config
	password string
	// tlsConfig and dial are nil outside tests.
	tlsConfig *tls.Config
	dial      func(ctx context.Context, addr string) (net.Conn, error)
}

// NewSender returns a Sender for cfg. getenv supplies the password.
func NewSender(cfg Config, getenv func(string) string) (*Sender, error) {
	if !cfg.Configured() {
		return nil, errors.New("notify: no smtp section in the config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("notify: %w", err)
	}
	s := &Sender{cfg: cfg}
	if cfg.PasswordEnv != "" {
		if s.password = getenv(cfg.PasswordEnv); s.password == "" {
			return nil, fmt.Errorf("notify: environment variable %s (smtp.password_env) is empty", cfg.PasswordEnv)
		}
	}
	return s, nil
}

// Send delivers m. It refuses to hand the message, or a password, to
// a remote server without TLS.
func (s *Sender) Send(ctx context.Context, m Message) error {
	if len(m.To) == 0 {
		return errors.New("notify: no recipients")
	}
	from, err := parseBareAddress(s.cfg.From)
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	var to []string
	for _, addr := range m.To {
		a, err := parseBareAddress(addr)
		if err != nil {
			return fmt.Errorf("notify: recipient: %w", err)
		}
		to = append(to, a)
	}
	raw, err := compose(from, to, m)
	if err != nil {
		return err
	}

	host, port, _ := net.SplitHostPort(s.cfg.Addr)
	tlsCfg := s.tlsConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	ctx, cancel := context.WithTimeout(ctx, sessionTimeout)
	defer cancel()
	dial := s.dial
	if dial == nil {
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: dialTimeout}
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	conn, err := dial(ctx, s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("notify: connect to %s: %w", s.cfg.Addr, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	encrypted := false
	if port == "465" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("notify: TLS with %s: %w", s.cfg.Addr, err)
		}
		conn, encrypted = tc, true
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("notify: %s: %w", s.cfg.Addr, err)
	}
	defer c.Close()
	if !encrypted {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("notify: STARTTLS with %s: %w", s.cfg.Addr, err)
			}
			encrypted = true
		}
	}
	if !encrypted && !isLoopback(host) {
		return fmt.Errorf("notify: %s does not offer TLS; refusing to send an embargoed verdict in the clear", s.cfg.Addr)
	}
	if s.cfg.Username != "" {
		if !encrypted {
			return fmt.Errorf("notify: %s does not offer TLS; refusing to send a password in the clear", s.cfg.Addr)
		}
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.password, host)); err != nil {
			return fmt.Errorf("notify: login to %s failed: %w", s.cfg.Addr, err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("notify: %s refused the sender: %w", s.cfg.Addr, err)
	}
	for _, a := range to {
		if err := c.Rcpt(a); err != nil {
			return fmt.Errorf("notify: %s refused recipient %s: %w", s.cfg.Addr, a, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("notify: %s: %w", s.cfg.Addr, err)
	}
	if _, err := w.Write(raw); err != nil {
		return fmt.Errorf("notify: sending to %s: %w", s.cfg.Addr, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notify: %s did not accept the message: %w", s.cfg.Addr, err)
	}
	// The message is accepted at this point; a failed QUIT changes
	// nothing.
	_ = c.Quit()
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// compose builds the RFC 5322 message. Everything that came from the
// report is either in the body, where it is only text, or encoded:
// the title in the subject goes through Printable and RFC 2047
// encoding, so it can't add a header.
func compose(from string, to []string, m Message) ([]byte, error) {
	sentAt := m.SentAt
	if sentAt.IsZero() {
		sentAt = time.Now()
	}
	title := []rune(report.Printable(m.Report.Title))
	if len(title) > maxSubject {
		title = title[:maxSubject]
	}
	subject := fmt.Sprintf("[kritolith] %s: %s (%s)", m.Verdict.Outcome, string(title), report.Printable(m.Report.Repo))

	var idRand [12]byte
	if _, err := rand.Read(idRand[:]); err != nil {
		return nil, fmt.Errorf("notify: %w", err)
	}
	domain := m.Hostname
	if domain == "" {
		_, domain, _ = strings.Cut(from, "@")
	}

	var b bytes.Buffer
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", from)
	header("To", strings.Join(to, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", sentAt.Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(idRand[:])+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Auto-Submitted", "auto-generated")
	header("X-Kritolith-Report", report.Printable(m.Report.ID))

	text := "This is an automated first pass by Kritolith. It gathers evidence; it does not decide.\r\n" +
		"The report it describes may concern an unfixed vulnerability: handle this message accordingly.\r\n\r\n" +
		crlf(m.Text)
	if len(m.Bundle) > 0 {
		text += "\r\nThe signed evidence bundle is attached. Check it with: kritolith verify-bundle --pubkey <key> verdict.tar\r\n"
	}

	if len(m.Bundle) == 0 {
		header("Content-Type", "text/plain; charset=utf-8")
		header("Content-Transfer-Encoding", "base64")
		b.WriteString("\r\n")
		writeBase64(&b, []byte(text))
		return b.Bytes(), nil
	}
	boundary := "kritolith-" + hex.EncodeToString(idRand[:])
	header("Content-Type", `multipart/mixed; boundary="`+boundary+`"`)
	b.WriteString("\r\n--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	writeBase64(&b, []byte(text))
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: application/x-tar; name=\"verdict.tar\"\r\nContent-Disposition: attachment; filename=\"verdict.tar\"\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	writeBase64(&b, m.Bundle)
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes(), nil
}

func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

// writeBase64 writes data as base64 in 76-column lines, which keeps
// every line of the message within SMTP's length limit whatever the
// report's text looks like.
func writeBase64(w io.Writer, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		io.WriteString(w, enc[:76]+"\r\n")
		enc = enc[76:]
	}
	io.WriteString(w, enc+"\r\n")
}
