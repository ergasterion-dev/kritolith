package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Mount is one extra mount inside the container. A Tmpfs mount has no
// host source, needs SizeMB and must be Writable; any other mount binds
// Source from the host at Dest, read-only unless Writable is set (a
// writable bind may not lie in or contain the rootfs).
//
// Callers must EvalSymlinks every Source and the Rootfs before BuildOCI
// and re-check the result: this function is pure and cannot see links.
type Mount struct {
	Source, Dest string
	Writable     bool
	SizeMB       int
	Tmpfs        bool
}

// ContainerSpec describes one locked-down container. Every limit is
// required: a container without limits is a bug, not a default.
type ContainerSpec struct {
	Rootfs string
	Args   []string
	Env    []string
	Cwd    string
	Mounts []Mount
	// Network asks for network access (the runtime's --network=sandbox).
	// It needs NetnsPath: a container with network but no prepared
	// namespace is refused, so nothing silently runs in an empty one.
	Network bool
	// NetnsPath is the fetch bridge's container namespace
	// (/run/netns/kvc<8 hex>) that the container joins. Empty means a
	// fresh, empty network namespace (build and run).
	NetnsPath              string
	MemoryMB, CPUs, PIDs   int
	CPUSeconds, FileSizeKB int
	UID, GID               int
	// Forbidden lists extra host path prefixes (the data directory, key
	// files) that no mount source may equal or lie under.
	Forbidden []string
}

// builtinDeny are host paths that may never be mounted into a container.
var builtinDeny = []string{"/var/run", "/run", "/proc", "/sys", "/dev", "/etc"}

// destDeny are in-container paths the runtime provides itself.
var destDeny = []string{"/proc", "/sys", "/dev"}

const (
	ociVersion = "1.0.2"
	cpuPeriod  = 100000
	noFileMax  = 1024

	maxMemoryMB   = 1 << 20
	maxCPUs       = 1024
	maxPIDs       = 1 << 20
	maxCPUSeconds = 86400
	maxFileSizeKB = 1 << 30
)

// OCI runtime-spec v1 config.json, only the fields we set.
type ociConfig struct {
	OCIVersion string     `json:"ociVersion"`
	Process    ociProcess `json:"process"`
	Root       ociRoot    `json:"root"`
	Hostname   string     `json:"hostname"`
	Mounts     []ociMount `json:"mounts"`
	Linux      ociLinux   `json:"linux"`
}

type ociProcess struct {
	Terminal        bool        `json:"terminal"`
	User            ociUser     `json:"user"`
	Args            []string    `json:"args"`
	Env             []string    `json:"env"`
	Cwd             string      `json:"cwd"`
	Capabilities    ociCaps     `json:"capabilities"`
	Rlimits         []ociRlimit `json:"rlimits"`
	NoNewPrivileges bool        `json:"noNewPrivileges"`
}

type ociUser struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}

type ociCaps struct {
	Bounding    []string `json:"bounding"`
	Effective   []string `json:"effective"`
	Inheritable []string `json:"inheritable"`
	Permitted   []string `json:"permitted"`
	Ambient     []string `json:"ambient"`
}

type ociRlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

type ociRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type ociMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type,omitempty"`
	Source      string   `json:"source,omitempty"`
	Options     []string `json:"options,omitempty"`
}

type ociLinux struct {
	Namespaces    []ociNamespace `json:"namespaces"`
	Devices       []ociDevice    `json:"devices"`
	Resources     ociResources   `json:"resources"`
	MaskedPaths   []string       `json:"maskedPaths"`
	ReadonlyPaths []string       `json:"readonlyPaths"`
}

type ociNamespace struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}

type ociDevice struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Major    int64  `json:"major"`
	Minor    int64  `json:"minor"`
	FileMode uint32 `json:"fileMode"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
}

type ociResources struct {
	Memory ociMemory `json:"memory"`
	CPU    ociCPU    `json:"cpu"`
	Pids   ociPids   `json:"pids"`
}

type ociMemory struct {
	Limit int64 `json:"limit"`
}

type ociCPU struct {
	Quota  int64  `json:"quota"`
	Period uint64 `json:"period"`
}

type ociPids struct {
	Limit int64 `json:"limit"`
}

func under(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, strings.TrimSuffix(prefix, "/")+"/")
}

func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if under(p, pre) {
			return true
		}
	}
	return false
}

func hasDotDot(p string) bool {
	for _, e := range strings.Split(p, "/") {
		if e == ".." {
			return true
		}
	}
	return false
}

// checkSource validates a host path (mount source or rootfs). It
// rejects paths equal to, under, or containing (an ancestor of) any
// denied or forbidden prefix, so "/" and "/var" are refused too.
func checkSource(src string, forbidden []string) error {
	if src == "" || strings.ContainsRune(src, 0) {
		return errors.New("empty or malformed host path")
	}
	if !strings.HasPrefix(src, "/") {
		return fmt.Errorf("host path %q is not absolute", src)
	}
	if hasDotDot(src) {
		return fmt.Errorf("host path %q contains ..", src)
	}
	c := filepath.Clean(src)
	if c == "/" {
		return errors.New("host path / is not allowed")
	}
	for _, list := range [][]string{builtinDeny, forbidden} {
		for _, pre := range list {
			if under(c, pre) || under(pre, c) {
				return fmt.Errorf("host path %q overlaps forbidden path %q", src, pre)
			}
		}
	}
	for _, e := range strings.Split(c, "/") {
		if e == "docker.sock" {
			return fmt.Errorf("host path %q is a docker socket", src)
		}
	}
	return nil
}

func checkDest(dest string) error {
	if !strings.HasPrefix(dest, "/") || strings.ContainsRune(dest, 0) || filepath.Clean(dest) != dest {
		return fmt.Errorf("mount destination %q must be absolute and clean", dest)
	}
	if dest == "/" || underAny(dest, destDeny) {
		return fmt.Errorf("mount destination %q is not allowed", dest)
	}
	return nil
}

// checkBindAliases rejects a writable bind whose host source overlaps
// (equals, lies under, or contains) any other bind's source: otherwise a
// read-only bind could be reached writably through the other mount.
func checkBindAliases(ms []Mount) error {
	for i, a := range ms {
		if a.Tmpfs || !a.Writable {
			continue
		}
		ac := filepath.Clean(a.Source)
		for j, b := range ms {
			if i == j || b.Tmpfs {
				continue
			}
			bc := filepath.Clean(b.Source)
			if under(ac, bc) || under(bc, ac) {
				return fmt.Errorf("writable mount %q overlaps mount source %q", a.Source, b.Source)
			}
		}
	}
	return nil
}

// netnsNameRe is the only namespace a container may join: the
// container side of a fetch bridge.
var netnsNameRe = regexp.MustCompile(`^kvc[0-9a-f]{8}$`)

// checkNetns validates ContainerSpec's network settings: Network and
// NetnsPath come together, and the path is a clean, absolute fetch
// bridge namespace directly under /run/netns or /var/run/netns.
func checkNetns(network bool, p string) error {
	switch {
	case network && p == "":
		return errors.New("network access needs a prepared network namespace (the fetch bridge)")
	case !network && p != "":
		return errors.New("a network namespace path without network access")
	case p == "":
		return nil
	}
	if strings.ContainsRune(p, 0) || !strings.HasPrefix(p, "/") || hasDotDot(p) || filepath.Clean(p) != p {
		return fmt.Errorf("network namespace path %q must be absolute and clean", p)
	}
	if d := filepath.Dir(p); d != "/run/netns" && d != "/var/run/netns" {
		return fmt.Errorf("network namespace path %q is not under /run/netns", p)
	}
	if !netnsNameRe.MatchString(filepath.Base(p)) {
		return fmt.Errorf("network namespace path %q is not a fetch bridge namespace", p)
	}
	return nil
}

func validate(s ContainerSpec) ([]string, error) {
	if len(s.Args) == 0 {
		return nil, errors.New("no command")
	}
	if err := checkNetns(s.Network, s.NetnsPath); err != nil {
		return nil, err
	}
	if strings.ContainsRune(s.Cwd, 0) || !strings.HasPrefix(s.Cwd, "/") || hasDotDot(s.Cwd) || filepath.Clean(s.Cwd) != s.Cwd {
		return nil, errors.New("cwd must be absolute and clean")
	}
	for _, a := range s.Args {
		if strings.ContainsRune(a, 0) {
			return nil, errors.New("NUL in argument")
		}
	}
	for _, e := range s.Env {
		if i := strings.IndexByte(e, '='); i < 1 || strings.ContainsRune(e, 0) {
			return nil, fmt.Errorf("malformed environment entry %q", e)
		}
	}
	for _, l := range []struct {
		name   string
		v, max int
	}{
		{"MemoryMB", s.MemoryMB, maxMemoryMB}, {"CPUs", s.CPUs, maxCPUs}, {"PIDs", s.PIDs, maxPIDs},
		{"CPUSeconds", s.CPUSeconds, maxCPUSeconds}, {"FileSizeKB", s.FileSizeKB, maxFileSizeKB},
	} {
		if l.v <= 0 || l.v > l.max {
			return nil, fmt.Errorf("%s must be in 1..%d: a container without limits is a bug", l.name, l.max)
		}
	}
	if s.UID <= 0 || s.GID <= 0 {
		return nil, errors.New("container must run as an unprivileged user (uid > 0, gid > 0)")
	}
	forbidden := make([]string, 0, len(s.Forbidden))
	for _, f := range s.Forbidden {
		if !strings.HasPrefix(f, "/") || hasDotDot(f) || strings.ContainsRune(f, 0) {
			return nil, fmt.Errorf("forbidden prefix %q must be absolute, without .. or NUL", f)
		}
		forbidden = append(forbidden, filepath.Clean(f))
	}
	if err := checkSource(s.Rootfs, forbidden); err != nil {
		return nil, fmt.Errorf("rootfs: %w", err)
	}
	return forbidden, nil
}

// BuildOCI renders the OCI runtime-spec config.json for s. It is pure:
// it reads no environment and touches no files.
func BuildOCI(s ContainerSpec) ([]byte, error) {
	forbidden, err := validate(s)
	if err != nil {
		return nil, err
	}
	mounts := []ociMount{
		{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "noexec", "mode=755", "size=64k"}},
	}
	rootfs := filepath.Clean(s.Rootfs)
	if err := checkBindAliases(s.Mounts); err != nil {
		return nil, err
	}
	dests := []string{}
	for _, m := range s.Mounts {
		if err := checkDest(m.Dest); err != nil {
			return nil, err
		}
		for _, d := range dests {
			if under(m.Dest, d) || under(d, m.Dest) {
				return nil, fmt.Errorf("mount destination %q overlaps %q", m.Dest, d)
			}
		}
		dests = append(dests, m.Dest)
		if m.Tmpfs {
			if !m.Writable {
				return nil, fmt.Errorf("tmpfs mount %q must be writable", m.Dest)
			}
			if m.SizeMB <= 0 || m.SizeMB > maxMemoryMB {
				return nil, fmt.Errorf("tmpfs mount %q size must be between 1 and %d MB", m.Dest, maxMemoryMB)
			}
			mounts = append(mounts, ociMount{Destination: m.Dest, Type: "tmpfs", Source: "tmpfs",
				Options: []string{"nosuid", "nodev", fmt.Sprintf("size=%dm", m.SizeMB)}})
			continue
		}
		if err := checkSource(m.Source, forbidden); err != nil {
			return nil, err
		}
		opts := []string{"rbind", "nosuid", "nodev", "ro"}
		if m.Writable {
			if under(filepath.Clean(m.Source), rootfs) || under(rootfs, filepath.Clean(m.Source)) {
				return nil, fmt.Errorf("writable mount %q overlaps the rootfs", m.Source)
			}
			opts[3] = "rw"
		}
		mounts = append(mounts, ociMount{Destination: m.Dest, Type: "bind", Source: filepath.Clean(m.Source), Options: opts})
	}
	env := append([]string{}, s.Env...)
	rl := func(t string, v uint64) ociRlimit { return ociRlimit{Type: t, Hard: v, Soft: v} }
	chr := func(p string, minor int64) ociDevice {
		return ociDevice{Path: p, Type: "c", Major: map[bool]int64{true: 5, false: 1}[p == "/dev/tty"], Minor: minor, FileMode: 0o666}
	}
	cfg := ociConfig{
		OCIVersion: ociVersion,
		Process: ociProcess{
			User: ociUser{UID: s.UID, GID: s.GID}, Args: append([]string{}, s.Args...), Env: env, Cwd: s.Cwd,
			Capabilities: ociCaps{Bounding: []string{}, Effective: []string{}, Inheritable: []string{}, Permitted: []string{}, Ambient: []string{}},
			Rlimits: []ociRlimit{
				rl("RLIMIT_CPU", uint64(s.CPUSeconds)),
				rl("RLIMIT_FSIZE", uint64(s.FileSizeKB)*1024),
				rl("RLIMIT_NOFILE", noFileMax),
				// RLIMIT_NPROC counts per UID, not per container; fine under gVisor.
				rl("RLIMIT_NPROC", uint64(s.PIDs)),
			},
			NoNewPrivileges: true,
		},
		Root:     ociRoot{Path: s.Rootfs, Readonly: true},
		Hostname: "kritolith",
		Mounts:   mounts,
		Linux: ociLinux{
			// Only the network namespace may carry a path (the fetch
			// bridge's, checked by validate); every other is created fresh.
			Namespaces: []ociNamespace{{Type: "pid"}, {Type: "network", Path: s.NetnsPath}, {Type: "ipc"}, {Type: "uts"}, {Type: "mount"}},
			Devices:    []ociDevice{chr("/dev/null", 3), chr("/dev/zero", 5), chr("/dev/urandom", 9), chr("/dev/tty", 0)},
			Resources: ociResources{
				Memory: ociMemory{Limit: int64(s.MemoryMB) << 20},
				CPU:    ociCPU{Quota: int64(s.CPUs) * cpuPeriod, Period: cpuPeriod},
				Pids:   ociPids{Limit: int64(s.PIDs)},
			},
			MaskedPaths:   []string{"/proc/kcore", "/proc/keys", "/proc/timer_list", "/proc/sched_debug", "/sys/firmware"},
			ReadonlyPaths: []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
