package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// netnsDir is where `ip netns` keeps its named namespaces.
	netnsDir = "/run/netns"
	// bridgeMarkerDir, under the work dir, holds one empty file per live
	// bridge id, so SweepOrphans removes only this work dir's leftovers.
	bridgeMarkerDir = "fetch-bridges"
	// ipTimeout bounds each `ip` invocation.
	ipTimeout = 15 * time.Second
)

// ipBridges builds fetch bridges with iproute2's `ip` (an absolute
// path found at construction).
type ipBridges struct {
	ip      string
	markers string // <workDir>/fetch-bridges
}

// newHostBridges returns the production bridge provider for workDir:
// iproute2 bridges when this process is root and `ip` is installed,
// otherwise a provider whose every Open fails with the reason.
func newHostBridges(workDir string) bridgeProvider {
	if os.Geteuid() != 0 {
		return unavailableBridge{reason: "the fetch phase's network bridge needs root"}
	}
	ip, err := findIP()
	if err != nil {
		return unavailableBridge{reason: "the fetch phase's network bridge needs iproute2 (`ip`), which was not found"}
	}
	markers := filepath.Join(workDir, bridgeMarkerDir)
	if err := ensurePrivateDir(markers); err != nil {
		return unavailableBridge{reason: "the fetch bridge marker directory could not be prepared"}
	}
	return &ipBridges{ip: ip, markers: markers}
}

// findIP looks for `ip` in the fixed runsc PATH directories only.
func findIP() (string, error) {
	for _, d := range filepath.SplitList(runscPath) {
		if p, err := exec.LookPath(filepath.Join(d, "ip")); err == nil && filepath.IsAbs(p) {
			return p, nil
		}
	}
	return "", errors.New("ip not found")
}

// ipCmd runs `ip args...` with an empty environment and a fixed PATH,
// bounded by ipTimeout, and returns its capped combined output.
func ipCmd(ip string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ipTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ip, args...)
	cmd.Env = []string{"PATH=" + runscPath}
	cmd.Dir = "/"
	w := &capWriter{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = w, w
	err := cmd.Run()
	out, _ := w.result()
	if err != nil {
		return out, fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return out, nil
}

// ipBridge is one live bridge.
type ipBridge struct {
	p        *ipBridges
	id       string
	ctr, br  string
	subnet   bridgeSubnet
	fwd      *forwarder
	proxyURL string
	once     sync.Once
	err      error
}

func (b *ipBridge) NetnsPath() string { return filepath.Join(netnsDir, b.ctr) }
func (b *ipBridge) ProxyURL() string  { return b.proxyURL }

// Close stops the forwarder and removes both namespaces, the veth pair
// and the marker. It is idempotent.
func (b *ipBridge) Close() error {
	b.once.Do(func() {
		var errs []error
		if b.fwd != nil {
			if err := b.fwd.close(); err != nil {
				errs = append(errs, fmt.Errorf("sandbox: close fetch forwarder: %w", err))
			}
		}
		if err := b.p.removeBridge(b.id); err != nil {
			errs = append(errs, err)
		}
		b.err = errors.Join(errs...)
	})
	return b.err
}

// Open implements bridgeProvider.
func (p *ipBridges) Open(ctx context.Context, upstream string) (_ fetchBridge, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fwd, err := newForwarder(upstream, nil)
	if err != nil {
		return nil, err
	}
	id, err := newBridgeID()
	if err != nil {
		return nil, err
	}
	ctr, br, err := bridgeNames(id)
	if err != nil {
		return nil, err
	}
	taken, err := hostNets()
	if err != nil {
		return nil, err
	}
	subnet, err := pickSubnet(rand.Reader, taken)
	if err != nil {
		return nil, err
	}
	b := &ipBridge{p: p, id: id, ctr: ctr, br: br, subnet: subnet}
	// The marker goes first, so a crash at any later point leaves
	// something SweepOrphans can find.
	mf, err := os.OpenFile(filepath.Join(p.markers, id), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("sandbox: fetch bridge marker: %w", err)
	}
	mf.Close()
	defer func() {
		if err != nil {
			if cerr := b.Close(); cerr != nil {
				err = errors.Join(err, cerr)
			}
		}
	}()

	hostCIDR := subnet.host.String() + "/30"
	ctrCIDR := subnet.ctr.String() + "/30"
	for _, args := range [][]string{
		{"netns", "add", ctr},
		{"netns", "add", br},
		{"link", "add", ctr, "type", "veth", "peer", "name", br},
		{"link", "set", ctr, "netns", ctr},
		{"link", "set", br, "netns", br},
		{"-n", ctr, "addr", "add", ctrCIDR, "dev", ctr},
		{"-n", br, "addr", "add", hostCIDR, "dev", br},
		{"-n", ctr, "link", "set", "lo", "up"},
		{"-n", br, "link", "set", "lo", "up"},
		{"-n", ctr, "link", "set", ctr, "up"},
		{"-n", br, "link", "set", br, "up"},
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := ipCmd(p.ip, args...); err != nil {
			return nil, fmt.Errorf("sandbox: fetch bridge setup: %w", err)
		}
	}
	l, err := listenInNetns(filepath.Join(netnsDir, br), net.JoinHostPort(subnet.host.String(), "0"))
	if err != nil {
		return nil, fmt.Errorf("sandbox: fetch bridge listener: %w", err)
	}
	b.fwd = fwd
	fwd.serve(l, subnet.ctr)
	port := l.Addr().(*net.TCPAddr).Port
	b.proxyURL = "http://" + net.JoinHostPort(subnet.host.String(), strconv.Itoa(port))
	return b, nil
}

// removeBridge deletes the namespaces and links of bridge id and then
// its marker. Things already gone are not errors.
func (p *ipBridges) removeBridge(id string) error {
	ctr, br, err := bridgeNames(id)
	if err != nil {
		return err
	}
	var errs []error
	for _, n := range []string{ctr, br} {
		if _, err := ipCmd(p.ip, "netns", "del", n); err != nil {
			if _, serr := os.Lstat(filepath.Join(netnsDir, n)); serr == nil {
				errs = append(errs, fmt.Errorf("sandbox: remove fetch bridge namespace: %w", err))
			}
		}
	}
	// A pair that never left the root namespace (setup failed before
	// the move) is deleted there; deleting one end removes both.
	for _, n := range []string{ctr, br} {
		if _, err := net.InterfaceByName(n); err == nil {
			if _, err := ipCmd(p.ip, "link", "del", n); err != nil {
				if _, ierr := net.InterfaceByName(n); ierr == nil {
					errs = append(errs, fmt.Errorf("sandbox: remove fetch bridge link: %w", err))
				}
			}
		}
	}
	if len(errs) == 0 {
		if err := os.Remove(filepath.Join(p.markers, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("sandbox: remove fetch bridge marker: %w", err))
		}
	}
	return errors.Join(errs...)
}

// listenInNetns opens a TCP listener on addr inside the network
// namespace at nsPath. The calling goroutine's thread switches into the
// namespace for the socket call only. If switching back fails, the
// thread stays locked, so the runtime discards it when this goroutine
// exits instead of reusing a thread in the wrong namespace; the
// function runs on a goroutine of its own for that reason.
func listenInNetns(nsPath, addr string) (net.Listener, error) {
	type result struct {
		l   net.Listener
		err error
	}
	ch := make(chan result, 1)
	go func() {
		l, err := listenInNetnsLocked(nsPath, addr)
		ch <- result{l, err}
	}()
	r := <-ch
	return r.l, r.err
}

func listenInNetnsLocked(nsPath, addr string) (net.Listener, error) {
	runtime.LockOSThread()
	orig, err := os.OpenFile("/proc/thread-self/ns/net", os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("open own netns: %w", err)
	}
	defer orig.Close()
	target, err := os.OpenFile(nsPath, os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("open netns: %w", err)
	}
	defer target.Close()
	if err := setns(int(target.Fd())); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("enter netns: %w", err)
	}
	l, lerr := net.Listen("tcp4", addr)
	if err := setns(int(orig.Fd())); err != nil {
		// Leave the thread locked: it is in the wrong namespace and
		// must die with this goroutine.
		if l != nil {
			l.Close()
		}
		return nil, fmt.Errorf("return to own netns: %w", err)
	}
	runtime.UnlockOSThread()
	if lerr != nil {
		return nil, lerr
	}
	return l, nil
}

func setns(fd int) error {
	if _, _, e := syscall.RawSyscall(sysSetns, uintptr(fd), uintptr(syscall.CLONE_NEWNET), 0); e != 0 {
		return e
	}
	return nil
}

// sweepBridges removes the bridges a crashed earlier run of this work
// dir left behind: one per marker file whose name is a bridge id. It
// is best effort and needs root and `ip`; without them there is
// nothing it could have created.
func sweepBridges(workDir string) error {
	markers := filepath.Join(workDir, bridgeMarkerDir)
	fi, err := os.Lstat(markers)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("sandbox: sweep: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("sandbox: sweep: %s is not a directory", markers)
	}
	if err := checkPrivateDir(markers); err != nil {
		return fmt.Errorf("sandbox: sweep: %w", err)
	}
	if os.Geteuid() != 0 {
		return nil
	}
	ip, err := findIP()
	if err != nil {
		return nil
	}
	ents, err := os.ReadDir(markers)
	if err != nil {
		return fmt.Errorf("sandbox: sweep: %w", err)
	}
	p := &ipBridges{ip: ip, markers: markers}
	var errs []error
	for _, e := range ents {
		if !bridgeIDRe.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		if err := p.removeBridge(e.Name()); err != nil {
			errs = append(errs, fmt.Errorf("sandbox: sweep: %w", err))
		}
	}
	return errors.Join(errs...)
}
