package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

const (
	fakeBridgeURL   = "http://169.254.7.1:41000"
	fakeBridgeNetns = "/run/netns/kvc0123abcd"
)

// fakeBridges is a bridgeProvider for runner tests. It records every
// Open and Close, and how many containers had run when each bridge was
// closed.
type fakeBridges struct {
	mu        sync.Mutex
	drv       *fakeDriver
	openErr   error
	closeErr  error
	upstreams []string
	opened    int
	closed    int
	// callsAtClose is len(drv.calls) when each bridge closed.
	callsAtClose []int
}

type fakeBridge struct {
	p    *fakeBridges
	once sync.Once
}

func (f *fakeBridges) Open(_ context.Context, upstream string) (fetchBridge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upstreams = append(f.upstreams, upstream)
	if f.openErr != nil {
		return nil, f.openErr
	}
	f.opened++
	return &fakeBridge{p: f}, nil
}

func (b *fakeBridge) NetnsPath() string { return fakeBridgeNetns }
func (b *fakeBridge) ProxyURL() string  { return fakeBridgeURL }
func (b *fakeBridge) Close() error {
	b.once.Do(func() {
		n := 0
		if b.p.drv != nil {
			b.p.drv.mu.Lock()
			n = len(b.p.drv.calls)
			b.p.drv.mu.Unlock()
		}
		b.p.mu.Lock()
		b.p.closed++
		b.p.callsAtClose = append(b.p.callsAtClose, n)
		b.p.mu.Unlock()
	})
	return b.p.closeErr
}

// The fetch uses the bridge: GOPROXY is the bridge URL, the container
// joins the bridge netns, Open gets the configured proxy, and each
// bridge is closed right after its fetch, before the build runs.
func TestRunnerFetchUsesBridge(t *testing.T) {
	fx := newFixture(t, map[string]step{"ref/run": stepPanic, "head/run": stepPass})
	res := fx.run(t, Request{})
	if res.Repro == nil || !res.Repro.Reproduced {
		t.Fatalf("setup: %+v", res)
	}
	fb := fx.bridges
	if fb.opened != 2 || fb.closed != 2 {
		t.Fatalf("bridges opened %d closed %d, want 2 and 2", fb.opened, fb.closed)
	}
	for _, u := range fb.upstreams {
		if u != testCfg(fx.rootfs).GoProxy {
			t.Errorf("bridge upstream %q, want the configured proxy", u)
		}
	}
	// ref fetch is call 1, head fetch call 4: each bridge closes before
	// the next container (the build) starts.
	if fmt.Sprint(fb.callsAtClose) != "[1 4]" {
		t.Errorf("bridges closed after %v containers, want [1 4]", fb.callsAtClose)
	}
	for _, c := range fx.drv.calls {
		env := envMap(t, c.spec.Container.Env)
		if c.phase == PhaseFetch {
			if env["GOPROXY"] != fakeBridgeURL || c.spec.Container.NetnsPath != fakeBridgeNetns || !c.spec.Container.Network {
				t.Errorf("%s/fetch: GOPROXY %q netns %q", c.who, env["GOPROXY"], c.spec.Container.NetnsPath)
			}
			continue
		}
		if c.spec.Container.Network || c.spec.Container.NetnsPath != "" {
			t.Errorf("%s/%s has network", c.who, c.phase)
		}
		for _, e := range c.spec.Container.Env {
			if strings.Contains(e, "proxy.example.org") || strings.Contains(e, fakeBridgeURL) {
				t.Errorf("%s/%s env carries a proxy: %q", c.who, c.phase, e)
			}
		}
	}
}

// No bridge, or a bridge that cannot be built, ends the fetch
// INCONCLUSIVE without running a container: never a rejection.
func TestRunnerBridgeUnavailableIsInconclusive(t *testing.T) {
	cases := map[string]func(*fixture){
		"open fails": func(fx *fixture) { fx.bridges.openErr = errors.New("ip: netns add failed") },
		"unavailable": func(fx *fixture) {
			fx.runner.bridge = unavailableBridge{reason: "the fetch phase's network bridge needs root"}
		},
		"nil provider": func(fx *fixture) { fx.runner.bridge = nil },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t, map[string]step{"ref/run": stepPanic})
			setup(fx)
			res := fx.run(t, Request{})
			if res.Inconclusive == "" || !strings.Contains(res.Inconclusive, "bridge") {
				t.Fatalf("Inconclusive = %q, want a bridge reason", res.Inconclusive)
			}
			if res.Skipped != "" || res.NeedsInfo != "" || res.Passed || (res.Repro != nil && res.Repro.Reproduced) {
				t.Fatalf("result %+v", res)
			}
			if len(fx.drv.calls) != 0 {
				t.Fatalf("containers ran without a bridge: %v", fx.drv.phases())
			}
		})
	}
}

// The bridge is torn down on every path: fetch failure, driver error,
// cancellation, a panicking driver, a failed build and a close error
// (which only adds a note).
func TestRunnerBridgeAlwaysClosed(t *testing.T) {
	cases := map[string]struct {
		script   map[string]step
		ctx      func() context.Context
		closeErr error
	}{
		"fetch exit 1": {script: map[string]step{"ref/fetch": {out: RunOutput{ExitCode: 1}}}},
		"fetch error":  {script: map[string]step{"ref/fetch": {err: errors.New("runsc broke")}}},
		"fetch panic":  {script: map[string]step{"ref/fetch": {panic: true}}},
		"build fails":  {script: map[string]step{"ref/build": stepBuildE}},
		"cancelled": {script: map[string]step{}, ctx: func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
		"close error": {script: map[string]step{"ref/run": stepPass}, closeErr: errors.New("netns busy")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t, c.script)
			fx.bridges.closeErr = c.closeErr
			ctx := context.Background()
			if c.ctx != nil {
				ctx = c.ctx()
			}
			res := fx.runner.Run(ctx, Request{Report: report.Report{PoC: testPoC}, ResolvedRef: refSHA, Claims: []report.Claim{parseClaim}})
			assertScratchEmpty(t, fx.scratch)
			if fx.bridges.opened != fx.bridges.closed {
				t.Fatalf("bridges opened %d closed %d", fx.bridges.opened, fx.bridges.closed)
			}
			if c.closeErr != nil {
				if res.Repro == nil || !strings.Contains(strings.Join(res.Repro.Notes, "\n"), "fetch bridge could not be fully removed") {
					t.Fatalf("no note for a failed bridge close: %+v", res.Repro)
				}
			}
			if res.Repro != nil && res.Repro.Reproduced && name != "close error" {
				t.Fatalf("%s reproduced", name)
			}
		})
	}
}

func TestBridgeNames(t *testing.T) {
	for range 100 {
		id, err := newBridgeID()
		if err != nil {
			t.Fatal(err)
		}
		c, b, err := bridgeNames(id)
		if err != nil || !bridgeNameRe.MatchString(c) || !bridgeNameRe.MatchString(b) || c[:3] != "kvc" || b[:3] != "kvb" {
			t.Fatalf("id %q: %q %q %v", id, c, b, err)
		}
		if len(c) > 15 {
			t.Fatalf("interface name %q longer than IFNAMSIZ-1", c)
		}
	}
	for _, bad := range []string{"", "0123abc", "0123abcde", "0123ABCD", "../12345", "0123abc\x00", "0123abc ", "kvc01234"} {
		if _, _, err := bridgeNames(bad); err == nil {
			t.Errorf("bridgeNames(%q) accepted", bad)
		}
	}
}

func TestPickSubnet(t *testing.T) {
	seen := map[string]bool{}
	for i := range 2000 {
		rnd := bytes.NewReader([]byte{byte(i), byte(i >> 3), byte(i * 7), byte(i >> 5)})
		s, err := pickSubnet(rnd, nil)
		if err != nil {
			t.Fatal(err)
		}
		b := s.base.To4()
		if b[0] != 169 || b[1] != 254 || b[2] < 1 || b[2] > 168 || b[3]%4 != 0 {
			t.Fatalf("subnet %v out of range", s.base)
		}
		if !s.host.Equal(net.IPv4(169, 254, b[2], b[3]+1)) || !s.ctr.Equal(net.IPv4(169, 254, b[2], b[3]+2)) {
			t.Fatalf("ends %v %v for %v", s.host, s.ctr, s.base)
		}
		if s.ipNet().Contains(net.ParseIP("169.254.169.254")) {
			t.Fatal("the metadata address is in the bridge subnet")
		}
		seen[s.base.String()] = true
	}
	if len(seen) < 100 {
		t.Errorf("only %d distinct subnets", len(seen))
	}

	// A taken network is avoided: everything but one /30 is taken.
	_, all, _ := net.ParseCIDR("169.254.0.0/16")
	if _, err := pickSubnet(bytes.NewReader(bytes.Repeat([]byte{1}, 1024)), []*net.IPNet{all}); err == nil {
		t.Error("a fully taken range still gave a subnet")
	}
	_, small, _ := net.ParseCIDR("169.254.2.4/32")
	// First draw hits 169.254.2.4/30 (x=1+1, y=4); the second is free.
	s, err := pickSubnet(bytes.NewReader([]byte{1, 4, 2, 8}), []*net.IPNet{small})
	if err != nil {
		t.Fatal(err)
	}
	if s.base.String() == "169.254.2.4" {
		t.Error("picked a /30 holding a host address")
	}
	_, wide, _ := net.ParseCIDR("169.254.2.0/24")
	if s, err := pickSubnet(bytes.NewReader([]byte{1, 4, 1, 4, 3, 0}), []*net.IPNet{wide}); err != nil || s.base.String() == "169.254.2.4" {
		t.Errorf("picked %v inside a host route: %v", s.base, err)
	}
	if _, err := pickSubnet(bytes.NewReader(nil), nil); err == nil {
		t.Error("no randomness, still a subnet")
	}
}

// fwdEnv is a forwarder on loopback in front of an upstream test server,
// with a second server that nothing may ever reach.
type fwdEnv struct {
	fwd           *forwarder
	addr          string
	upstreamHits  atomic.Int64
	otherHits     atomic.Int64
	upstream      *httptest.Server
	other         *httptest.Server
	mu            sync.Mutex
	lastPath      string
	lastHeader    http.Header
	lastHost      string
	upstreamReply func(w http.ResponseWriter, r *http.Request)
}

func newFwdEnv(t *testing.T, allowed string) *fwdEnv {
	t.Helper()
	e := &fwdEnv{}
	e.other = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		e.otherHits.Add(1)
		fmt.Fprint(w, "other")
	}))
	t.Cleanup(e.other.Close)
	e.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.upstreamHits.Add(1)
		e.mu.Lock()
		e.lastPath, e.lastHeader, e.lastHost = r.URL.RequestURI(), r.Header.Clone(), r.Host
		reply := e.upstreamReply
		e.mu.Unlock()
		if reply != nil {
			reply(w, r)
			return
		}
		fmt.Fprint(w, "module data")
	}))
	t.Cleanup(e.upstream.Close)
	fwd, err := newForwarder(e.upstream.URL+"/base", nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fwd.serve(l, net.ParseIP(allowed))
	t.Cleanup(func() { _ = fwd.close() })
	e.fwd, e.addr = fwd, l.Addr().String()
	return e
}

// raw sends one raw HTTP/1.1 request and returns the status code (0 if
// the connection was closed without a response).
func (e *fwdEnv) raw(t *testing.T, req string) int {
	t.Helper()
	c, err := net.DialTimeout("tcp", e.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestForwarderRelaysOnlyToUpstream(t *testing.T) {
	e := newFwdEnv(t, "127.0.0.1")
	otherHost := strings.TrimPrefix(e.other.URL, "http://")
	req := "GET /golang.org/x/text/@v/list?x=1 HTTP/1.1\r\nHost: " + otherHost +
		"\r\nUser-Agent: Go-http-client/1.1\r\nAuthorization: Bearer secret\r\nCookie: a=b\r\nX-Forwarded-Host: " + otherHost +
		"\r\nX-Forwarded-For: 1.2.3.4\r\nForwarded: host=" + otherHost + "\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if code := e.raw(t, req); code != 200 {
		t.Fatalf("status %d", code)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastPath != "/base/golang.org/x/text/@v/list?x=1" {
		t.Errorf("upstream path %q", e.lastPath)
	}
	if e.lastHost != strings.TrimPrefix(e.upstream.URL, "http://") {
		t.Errorf("upstream saw Host %q", e.lastHost)
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Forwarded-Host", "X-Forwarded-For", "Forwarded"} {
		if e.lastHeader.Get(h) != "" {
			t.Errorf("header %s passed upstream: %q", h, e.lastHeader.Get(h))
		}
	}
	if e.lastHeader.Get("User-Agent") != "Go-http-client/1.1" || e.lastHeader.Get("Accept") != "*/*" {
		t.Errorf("allowed headers dropped: %v", e.lastHeader)
	}
	if e.otherHits.Load() != 0 {
		t.Error("the other server was reached")
	}
}

func TestForwarderRefuses(t *testing.T) {
	e := newFwdEnv(t, "127.0.0.1")
	otherHost := strings.TrimPrefix(e.other.URL, "http://")
	h := "Host: x\r\nConnection: close\r\n\r\n"
	cases := map[string]string{
		"POST":             "POST /a HTTP/1.1\r\nContent-Length: 0\r\n" + h,
		"PUT":              "PUT /a HTTP/1.1\r\nContent-Length: 0\r\n" + h,
		"DELETE":           "DELETE /a HTTP/1.1\r\n" + h,
		"OPTIONS":          "OPTIONS /a HTTP/1.1\r\n" + h,
		"PATCH":            "PATCH /a HTTP/1.1\r\n" + h,
		"CONNECT":          "CONNECT " + otherHost + " HTTP/1.1\r\n" + h,
		"absolute URL":     "GET " + e.other.URL + "/a HTTP/1.1\r\n" + h,
		"asterisk":         "GET * HTTP/1.1\r\n" + h,
		"dotdot":           "GET /../a HTTP/1.1\r\n" + h,
		"inner dotdot":     "GET /a/../b HTTP/1.1\r\n" + h,
		"dot":              "GET /a/./b HTTP/1.1\r\n" + h,
		"encoded dotdot":   "GET /a/%2e%2e/b HTTP/1.1\r\n" + h,
		"encoded slash":    "GET /a%2f..%2fb HTTP/1.1\r\n" + h,
		"encoded nul":      "GET /a%00b HTTP/1.1\r\n" + h,
		"encoded bslash":   "GET /a%5cb HTTP/1.1\r\n" + h,
		"backslash":        "GET /a\\b HTTP/1.1\r\n" + h,
		"double slash":     "GET //" + otherHost + "/a HTTP/1.1\r\n" + h,
		"trailing slash":   "GET /a/ HTTP/1.1\r\n" + h,
		"no leading slash": "GET a HTTP/1.1\r\n" + h,
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			code := e.raw(t, req)
			if code == 200 || (code != 0 && code < 400) {
				t.Fatalf("status %d", code)
			}
		})
	}
	if n := e.upstreamHits.Load(); n != 0 {
		t.Errorf("upstream hit %d times by refused requests", n)
	}
	if e.otherHits.Load() != 0 {
		t.Error("the other server was reached")
	}
	if code := e.raw(t, "HEAD /ok HTTP/1.1\r\n"+h); code != 200 {
		t.Errorf("HEAD status %d", code)
	}
}

// A connection from any IP but the container's is closed unread.
func TestForwarderWrongRemoteIP(t *testing.T) {
	e := newFwdEnv(t, "169.254.7.2")
	if code := e.raw(t, "GET /a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); code != 0 {
		t.Fatalf("a foreign client got status %d", code)
	}
	if e.upstreamHits.Load() != 0 {
		t.Error("a foreign client reached the upstream")
	}
}

// Redirects off the upstream are refused unless https; on the same
// host they are followed.
func TestForwarderRedirects(t *testing.T) {
	e := newFwdEnv(t, "127.0.0.1")
	e.upstreamReply = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/base/off":
			http.Redirect(w, r, e.other.URL+"/x", http.StatusFound)
		case "/base/same":
			http.Redirect(w, r, "/base/target", http.StatusFound)
		default:
			fmt.Fprint(w, "ok")
		}
	}
	h := " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
	if code := e.raw(t, "GET /off"+h); code != http.StatusBadGateway {
		t.Errorf("off-host http redirect: status %d", code)
	}
	if e.otherHits.Load() != 0 {
		t.Error("an off-host redirect was followed")
	}
	if code := e.raw(t, "GET /same"+h); code != 200 {
		t.Errorf("same-host redirect: status %d", code)
	}
	up, _ := http.NewRequest("GET", "http://proxy.example/", nil)
	for to, want := range map[string]bool{
		"https://storage.example/x":     true,
		"http://proxy.example/y":        true,
		"http://other.example/y":        false,
		"http://169.254.169.254/":       false,
		"ftp://proxy.example/":          false,
		"https://user:pw@other.example": false,
	} {
		u, _ := http.NewRequest("GET", to, nil)
		if got := redirectAllowed(up.URL, u.URL); got != want {
			t.Errorf("redirect to %s allowed = %v", to, got)
		}
	}
}

// The per-response and total caps cut the connection instead of
// passing a short body.
func TestForwarderCaps(t *testing.T) {
	e := newFwdEnv(t, "127.0.0.1")
	e.fwd.maxResp, e.fwd.maxTotal = 10, 25
	e.upstreamReply = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/base/big" {
			fmt.Fprint(w, strings.Repeat("x", 11))
			return
		}
		fmt.Fprint(w, "12345678")
	}
	h := " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
	if code := e.raw(t, "GET /big"+h); code == 200 {
		// Content-Length 11 > 10 is refused up front.
		t.Error("an oversized response was relayed")
	}
	for range 3 {
		_ = e.raw(t, "GET /small"+h)
	}
	if code := e.raw(t, "GET /small"+h); code == 200 {
		t.Errorf("the total budget did not stop relaying (%d bytes relayed)", e.fwd.relayed.Load())
	}
}

func TestNewForwarderRejectsBadUpstream(t *testing.T) {
	for _, u := range []string{"", "ftp://x", "http://", "https://u:p@x", "https://x/?q", "https://x/#f", "file:///x", "x"} {
		if _, err := newForwarder(u, nil); err == nil {
			t.Errorf("newForwarder(%q) accepted", u)
		}
	}
}
