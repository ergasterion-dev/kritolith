package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// mailSink is a loopback SMTP server that keeps the last message.
type mailSink struct {
	ln   net.Listener
	mu   sync.Mutex
	rcpt []string
	data string
}

func newMailSink(t *testing.T) *mailSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &mailSink{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(c)
		}
	}()
	return m
}

func (m *mailSink) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	say := func(s string) { io.WriteString(c, s+"\r\n") }
	say("220 sink")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		switch verb := strings.ToUpper(strings.Fields(line + " x")[0]); verb {
		case "EHLO", "HELO":
			say("250 sink")
		case "RCPT":
			m.mu.Lock()
			m.rcpt = append(m.rcpt, strings.TrimSpace(line))
			m.mu.Unlock()
			say("250 ok")
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			m.mu.Lock()
			m.data = b.String()
			m.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (m *mailSink) received() (rcpt []string, data string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.rcpt...), m.data
}

func TestCheckNotify(t *testing.T) {
	ctx := context.Background()
	sink := newMailSink(t)
	dataDir := filepath.Join(t.TempDir(), "data")
	p := writeReport(t, "# Over-read in parser\n\nno ref here")
	cfg := writeConfigFile(t, fmt.Sprintf(`{"projects":[{"repo":"a/b","notify":["sec@example.org","two@example.org"]},{"repo":"c/d"}],"smtp":{"addr":%q,"from":"kritolith@example.org"}}`, sink.ln.Addr().String()))

	// Unsigned: plain text, no attachment.
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"check", "--repo", "a/b", "--config", cfg, "--data-dir", dataDir, "--notify", p}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	rcpt, data := sink.received()
	if len(rcpt) != 2 || !strings.Contains(rcpt[0], "sec@example.org") || !strings.Contains(rcpt[1], "two@example.org") {
		t.Errorf("recipients = %q", rcpt)
	}
	if !strings.Contains(data, "Subject: [kritolith] NEEDS_INFO: Over-read in parser (a/b)\r\n") || strings.Contains(data, "verdict.tar") {
		t.Errorf("message:\n%s", data)
	}
	if !strings.HasPrefix(out.String(), "Kritolith: NEEDS_INFO") {
		t.Errorf("stdout = %q", out.String())
	}

	// Signed: the bundle rides along.
	if code := run(ctx, []string{"keygen", "--data-dir", dataDir}, &out, &errOut); code != 0 {
		t.Fatalf("keygen failed: %s", errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"check", "--json", "--repo", "a/b", "--config", cfg, "--data-dir", dataDir, "--notify", p}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	if _, data := sink.received(); !strings.Contains(data, `filename="verdict.tar"`) {
		t.Errorf("signed verdict sent without its bundle:\n%s", data)
	}
}

func TestNotifyErrors(t *testing.T) {
	ctx := context.Background()
	sink := newMailSink(t)
	dataDir := filepath.Join(t.TempDir(), "data")
	p := writeReport(t, "# Title\n\nbody")
	addr := sink.ln.Addr().String()
	withSMTP := writeConfigFile(t, fmt.Sprintf(`{"projects":[{"repo":"a/b","notify":["sec@example.org"]},{"repo":"c/d"}],"smtp":{"addr":%q,"from":"k@example.org"}}`, addr))
	noSMTP := writeConfigFile(t, `{"projects":[{"repo":"a/b","notify":["sec@example.org"]}]}`)
	dead := writeConfigFile(t, `{"projects":[{"repo":"a/b","notify":["sec@example.org"]}],"smtp":{"addr":"127.0.0.1:1","from":"k@example.org"}}`)
	needsPW := writeConfigFile(t, fmt.Sprintf(`{"projects":[{"repo":"a/b","notify":["sec@example.org"]}],"smtp":{"addr":%q,"from":"k@example.org","username":"u","password_env":"KRITOLITH_TEST_UNSET_PW"}}`, addr))
	t.Setenv("KRITOLITH_TEST_UNSET_PW", "")

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantErr    string
		wantStdout bool // the verdict was produced before the failure
	}{
		{"no config", []string{"check", "--repo", "a/b", "--data-dir", dataDir, "--notify", p}, 1, "--notify: needs --config with an smtp section", false},
		{"config without smtp", []string{"check", "--repo", "a/b", "--config", noSMTP, "--data-dir", dataDir, "--notify", p}, 1, "--notify: needs --config with an smtp section", false},
		{"project without addresses", []string{"check", "--repo", "c/d", "--config", withSMTP, "--data-dir", dataDir, "--notify", p}, 1, "has no notify addresses", false},
		{"password variable unset", []string{"check", "--repo", "a/b", "--config", needsPW, "--data-dir", dataDir, "--notify", p}, 1, "KRITOLITH_TEST_UNSET_PW", false},
		{"server unreachable", []string{"check", "--repo", "a/b", "--config", dead, "--data-dir", dataDir, "--notify", p}, 1, "the verdict is stored, but emailing it failed", true},
		{"bad smtp section", []string{"check", "--repo", "a/b", "--config", writeConfigFile(t, `{"smtp":{"addr":"nohostport","from":"k@example.org"}}`), "--data-dir", dataDir, p}, 1, "smtp.addr", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(ctx, tt.args, &out, &errOut)
			if code != tt.wantCode || !strings.Contains(errOut.String(), tt.wantErr) {
				t.Fatalf("code = %d (want %d), stderr = %q (want %q)", code, tt.wantCode, errOut.String(), tt.wantErr)
			}
			if (out.Len() > 0) != tt.wantStdout {
				t.Fatalf("stdout = %q, want output: %v", out.String(), tt.wantStdout)
			}
		})
	}
	// Without --notify nothing is ever sent, even with smtp configured.
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"check", "--repo", "a/b", "--config", withSMTP, "--data-dir", dataDir, p}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	if rcpt, data := sink.received(); len(rcpt) != 0 || data != "" {
		t.Fatalf("mail was sent without --notify: %q", rcpt)
	}
}
