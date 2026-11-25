package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The fetch bridge is how the fetch phase reaches the module proxy and
// nothing else. For each fetch Kritolith creates two network
// namespaces joined by a veth pair: the container namespace (kvc<id>),
// which the fetch container joins, and a bridge namespace (kvb<id>),
// which holds the other end of the pair and the listening socket of an
// in-process HTTP forwarder. The pair has no default route, the host
// does no forwarding and no NAT, so the only thing the container can
// reach is that socket. The forwarder relays GET and HEAD requests to
// the one configured proxy, and /sumdb/sum.golang.org/ requests to the
// fixed checksum database (sumdbUpstream), from the host's own
// namespace. Keeping the
// host end out of the root namespace matters: otherwise the container
// could reach every host service bound to the wildcard address at that
// IP.

// bridgeProvider sets up one fetch bridge per fetch run. The Runner
// gets it through this interface so tests can inject a fake.
type bridgeProvider interface {
	// Open creates a bridge whose forwarder relays to upstream (the
	// configured, already validated GOPROXY). Any error means the fetch
	// phase cannot have a network; the caller ends it INCONCLUSIVE.
	Open(ctx context.Context, upstream string) (fetchBridge, error)
}

// fetchBridge is one live bridge. Close tears it down and must be
// called on every path, exactly once; it is safe to call again.
type fetchBridge interface {
	// NetnsPath is the container namespace to join, e.g.
	// /run/netns/kvc0123abcd.
	NetnsPath() string
	// ProxyURL is the GOPROXY the container uses: http://<host ip>:<port>.
	ProxyURL() string
	Close() error
}

// unavailableBridge is the provider on a host where no bridge can be
// built (not root, not Linux, no iproute2). Every Open fails with the
// reason.
type unavailableBridge struct{ reason string }

func (u unavailableBridge) Open(context.Context, string) (fetchBridge, error) {
	return nil, errors.New(u.reason)
}

// bridgeNameRe is the only shape of a namespace or link name Kritolith
// creates: kv, b (bridge side) or c (container side), 8 hex digits.
var bridgeNameRe = regexp.MustCompile(`^kv[bc][0-9a-f]{8}$`)

// bridgeIDRe is the id part shared by both names.
var bridgeIDRe = regexp.MustCompile(`^[0-9a-f]{8}$`)

// newBridgeID returns 8 random hex digits from crypto/rand.
func newBridgeID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("sandbox: bridge id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// bridgeNames returns the container and bridge names for id, checked
// against bridgeNameRe.
func bridgeNames(id string) (ctr, br string, err error) {
	if !bridgeIDRe.MatchString(id) {
		return "", "", fmt.Errorf("sandbox: bad bridge id %q", id)
	}
	ctr, br = "kvc"+id, "kvb"+id
	if !bridgeNameRe.MatchString(ctr) || !bridgeNameRe.MatchString(br) {
		return "", "", fmt.Errorf("sandbox: bad bridge name for id %q", id)
	}
	return ctr, br, nil
}

// bridgeSubnet is a /30 out of 169.254.0.0/16: host (the forwarder's
// end) is .1 of the block, ctr (the container's end) .2.
type bridgeSubnet struct {
	base      net.IP // network address
	host, ctr net.IP
}

func (s bridgeSubnet) ipNet() *net.IPNet {
	return &net.IPNet{IP: s.base, Mask: net.CIDRMask(30, 32)}
}

// pickSubnet chooses a random /30 in 169.254.X.Y/30, X in 1..168 (never
// 169, so 169.254.169.254 is never an end of the pair), that overlaps
// none of taken (the host's addresses and routes). rnd supplies the
// randomness; it is crypto/rand in production.
func pickSubnet(rnd io.Reader, taken []*net.IPNet) (bridgeSubnet, error) {
	for range 64 {
		var b [2]byte
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return bridgeSubnet{}, fmt.Errorf("sandbox: bridge subnet: %w", err)
		}
		v := binary.BigEndian.Uint16(b[:])
		x := byte(1 + int(v>>8)%168)
		y := byte(v&0xff) &^ 3
		s := bridgeSubnet{
			base: net.IPv4(169, 254, x, y).To4(),
			host: net.IPv4(169, 254, x, y+1).To4(),
			ctr:  net.IPv4(169, 254, x, y+2).To4(),
		}
		n := s.ipNet()
		clash := false
		for _, t := range taken {
			if t == nil {
				continue
			}
			if t.Contains(n.IP) || n.Contains(t.IP) {
				clash = true
				break
			}
		}
		if !clash {
			return s, nil
		}
	}
	return bridgeSubnet{}, errors.New("sandbox: no free 169.254.x.y/30 for the fetch bridge")
}

// hostNets lists the networks of the host's interface addresses.
func hostNets() ([]*net.IPNet, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("sandbox: list host addresses: %w", err)
	}
	var out []*net.IPNet
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// Forwarder limits.
const (
	// fwdMaxResponse caps one relayed response body. Module zips are at
	// most 500 MiB.
	fwdMaxResponse = 512 << 20
	// fwdMaxTotal caps all bytes relayed for one fetch.
	fwdMaxTotal = 2 << 30
	// fwdRequestTimeout bounds one upstream request, body included.
	fwdRequestTimeout = 10 * time.Minute
	fwdMaxRedirects   = 10
	fwdMaxHeaderBytes = 64 << 10
)

// The checksum database go uses by default (GOSUMDB is left at its
// default). go asks the proxy <proxy>/sumdb/sum.golang.org/supported
// and, on 200, fetches the database through <proxy>/sumdb/sum.golang.org/;
// the forwarder answers the first itself and relays the rest here.
// go verifies the database's signed tree heads with its built-in key,
// so the relay cannot forge entries.
const (
	sumdbUpstream      = "https://sum.golang.org"
	sumdbPrefix        = "/sumdb/sum.golang.org/"
	sumdbSupportedPath = sumdbPrefix + "supported"
)

// fwdRequestHeaders are the only request headers passed upstream.
var fwdRequestHeaders = []string{"Accept", "Accept-Encoding", "User-Agent"}

// fwdResponseHeaders are the only response headers passed back.
var fwdResponseHeaders = []string{"Content-Type", "Content-Length", "Content-Encoding", "Cache-Control", "Etag", "Last-Modified"}

// forwarder is the HTTP relay behind the fetch bridge: GET and HEAD
// only, to one upstream, for one client IP.
type forwarder struct {
	upstream *url.URL
	// sumdb is the checksum database the forwarder relays
	// /sumdb/sum.golang.org/ to: sumdbUpstream, never taken from config
	// or a request. Tests point it at a local server.
	sumdb  *url.URL
	client *http.Client
	// maxResp and maxTotal are fwdMaxResponse and fwdMaxTotal; tests
	// lower them.
	maxResp, maxTotal int64
	srv               *http.Server
	relayed           atomic.Int64
	done              chan struct{}
	once              sync.Once
	closeErr          error
}

// newForwarder builds a forwarder relaying to upstream (an http or
// https URL with no query, userinfo or fragment). rt is the transport
// for upstream requests; nil means a fresh one that ignores the host's
// proxy environment.
func newForwarder(upstream string, rt http.RoundTripper) (*forwarder, error) {
	u, err := url.Parse(upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("sandbox: forwarder upstream must be a plain http(s) URL")
	}
	if rt == nil {
		rt = &http.Transport{
			Proxy:                  nil,
			DialContext:            (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:    30 * time.Second,
			ResponseHeaderTimeout:  2 * time.Minute,
			MaxResponseHeaderBytes: fwdMaxHeaderBytes,
			MaxIdleConns:           4,
			IdleConnTimeout:        30 * time.Second,
			ForceAttemptHTTP2:      true,
		}
	}
	sdb, err := url.Parse(sumdbUpstream)
	if err != nil {
		return nil, fmt.Errorf("sandbox: sumdb upstream: %w", err)
	}
	f := &forwarder{upstream: u, sumdb: sdb, maxResp: fwdMaxResponse, maxTotal: fwdMaxTotal, done: make(chan struct{})}
	f.client = &http.Client{
		Transport: rt,
		Timeout:   fwdRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= fwdMaxRedirects {
				return errors.New("too many redirects")
			}
			// Measured against the upstream this request was first sent
			// to: the proxy or the checksum database.
			if !redirectAllowed(via[0].URL, req.URL) {
				return errors.New("redirect off the upstream refused")
			}
			return nil
		},
	}
	return f, nil
}

// redirectAllowed: a redirect may stay on the upstream's scheme and
// host, or go anywhere over https.
func redirectAllowed(upstream, to *url.URL) bool {
	if to.User != nil {
		return false
	}
	if to.Scheme == "https" {
		return true
	}
	return to.Scheme == upstream.Scheme && strings.EqualFold(to.Host, upstream.Host)
}

// serve accepts on l, keeps only connections from allowed (every other
// is closed unread), and relays requests until close. It returns at
// once; the server runs in its own goroutine.
func (f *forwarder) serve(l net.Listener, allowed net.IP) {
	f.srv = &http.Server{
		Handler:           f,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    fwdMaxHeaderBytes,
		ErrorLog:          nil,
	}
	fl := &filterListener{Listener: l, allowed: allowed}
	go func() {
		defer close(f.done)
		_ = f.srv.Serve(fl)
	}()
}

// close stops the server and every connection it holds, and waits for
// the accept loop to end. It is idempotent.
func (f *forwarder) close() error {
	f.once.Do(func() {
		if f.srv == nil {
			return
		}
		f.closeErr = f.srv.Close()
		<-f.done
		f.client.CloseIdleConnections()
	})
	return f.closeErr
}

// filterListener closes every accepted connection whose remote IP is
// not the allowed one.
type filterListener struct {
	net.Listener
	allowed net.IP
}

func (l *filterListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if a, ok := c.RemoteAddr().(*net.TCPAddr); ok && a.IP.Equal(l.allowed) {
			return c, nil
		}
		c.Close()
	}
}

// cleanProxyPath checks a request target and returns the path to relay.
// It accepts only origin-form targets ("/..."): no absolute URL, no
// authority (CONNECT), no "*"; no NUL, control byte or backslash, no
// "." or ".." segment, no empty segment, nothing that path.Clean would
// change.
func cleanProxyPath(r *http.Request) (string, bool) {
	if !strings.HasPrefix(r.RequestURI, "/") || r.URL == nil || r.URL.IsAbs() || r.URL.Host != "" || r.URL.Opaque != "" {
		return "", false
	}
	p := r.URL.Path
	raw := r.URL.EscapedPath()
	for _, s := range []string{p, raw, r.URL.RawQuery} {
		for i := 0; i < len(s); i++ {
			if c := s[i]; c < 0x20 || c == 0x7f || c == '\\' {
				return "", false
			}
		}
	}
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.Contains(p, "//") {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	// A percent-encoded dot segment or slash would be decoded upstream.
	low := strings.ToLower(raw)
	if strings.Contains(low, "%2e") || strings.Contains(low, "%2f") || strings.Contains(low, "%5c") || strings.Contains(low, "%00") {
		return "", false
	}
	return p, true
}

// ServeHTTP relays one request to the upstream.
func (f *forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, ok := cleanProxyPath(r)
	if !ok {
		http.Error(w, "bad request path", http.StatusBadRequest)
		return
	}
	if f.relayed.Load() >= f.maxTotal {
		http.Error(w, "fetch byte budget exhausted", http.StatusForbidden)
		return
	}
	// The upstream URL is a fixed base plus this path and query: the
	// checksum database for /sumdb/sum.golang.org/..., the configured
	// proxy for everything else. Nothing else from the request (Host,
	// X-Forwarded-*, absolute targets) can change where it goes.
	base, rest := f.upstream, p
	if strings.HasPrefix(p, "/sumdb/") {
		if p == sumdbSupportedPath {
			// The forwarder proxies the checksum database itself, so it
			// tells go so: go then never connects to it directly.
			w.WriteHeader(http.StatusOK)
			return
		}
		sub, ok := strings.CutPrefix(p, sumdbPrefix)
		if !ok || sub == "" {
			http.Error(w, "unknown checksum database", http.StatusForbidden)
			return
		}
		base, rest = f.sumdb, "/"+sub
	}
	target := *base
	target.Path = strings.TrimSuffix(base.Path, "/") + rest
	target.RawPath = ""
	target.RawQuery = r.URL.RawQuery
	target.Fragment = ""
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for _, h := range fwdRequestHeaders {
		if v := r.Header.Values(h); len(v) > 0 {
			out.Header[h] = append([]string(nil), v...)
		}
	}
	if out.Header.Get("User-Agent") == "" {
		out.Header.Set("User-Agent", "kritolith-fetch-bridge")
	}
	resp, err := f.client.Do(out)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	limit := f.maxResp
	if left := f.maxTotal - f.relayed.Load(); left < limit {
		limit = left
	}
	if resp.ContentLength > limit {
		http.Error(w, "upstream response too large", http.StatusBadGateway)
		return
	}
	for _, h := range fwdResponseHeaders {
		if v := resp.Header.Values(h); len(v) > 0 {
			w.Header()[h] = append([]string(nil), v...)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	n, err := io.Copy(w, &countingReader{r: io.LimitReader(resp.Body, limit+1), n: &f.relayed})
	if n > limit || err != nil {
		// Over the cap or a broken upstream: cut the connection so the
		// client sees a failure, never a silently short body.
		panic(http.ErrAbortHandler)
	}
}

// countingReader adds every byte read to n.
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n.Add(int64(k))
	return k, err
}
