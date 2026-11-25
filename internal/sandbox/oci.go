package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Mount is one extra mount inside the container. A Tmpfs mount has no
// host source and needs SizeMB; any other mount binds Source from the
// host at Dest.
type Mount struct {
	Source, Dest string
	ReadOnly     bool
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
	// Network records that the caller wants network access. It does not
	// change the OCI config: the network namespace is always a fresh,
	// empty one, and access is granted by the runtime's network flag
	// (see the runner), never by joining a host namespace.
	Network                bool
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

func checkSource(src string, forbidden []string) error {
	if src == "" || strings.ContainsRune(src, 0) {
		return errors.New("empty or malformed mount source")
	}
	if !strings.HasPrefix(src, "/") {
		return fmt.Errorf("mount source %q is not absolute", src)
	}
	if hasDotDot(src) {
		return fmt.Errorf("mount source %q contains ..", src)
	}
	c := filepath.Clean(src)
	if underAny(c, builtinDeny) || underAny(c, forbidden) {
		return fmt.Errorf("mount source %q is under a forbidden path", src)
	}
	for _, e := range strings.Split(c, "/") {
		if e == "docker.sock" {
			return fmt.Errorf("mount source %q is a docker socket", src)
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

func validate(s ContainerSpec) ([]string, error) {
	if !strings.HasPrefix(s.Rootfs, "/") || strings.ContainsRune(s.Rootfs, 0) {
		return nil, errors.New("rootfs must be an absolute path")
	}
	if len(s.Args) == 0 {
		return nil, errors.New("no command")
	}
	if !strings.HasPrefix(s.Cwd, "/") {
		return nil, errors.New("cwd must be absolute")
	}
	for _, e := range s.Env {
		if i := strings.IndexByte(e, '='); i < 1 {
			return nil, fmt.Errorf("malformed environment entry %q", e)
		}
	}
	for name, v := range map[string]int{"MemoryMB": s.MemoryMB, "CPUs": s.CPUs, "PIDs": s.PIDs,
		"CPUSeconds": s.CPUSeconds, "FileSizeKB": s.FileSizeKB} {
		if v <= 0 {
			return nil, fmt.Errorf("%s must be positive: a container without limits is a bug", name)
		}
	}
	if s.UID <= 0 || s.GID < 0 {
		return nil, errors.New("container must run as an unprivileged user (uid > 0, gid >= 0)")
	}
	forbidden := make([]string, 0, len(s.Forbidden))
	for _, f := range s.Forbidden {
		if !strings.HasPrefix(f, "/") || hasDotDot(f) {
			return nil, fmt.Errorf("forbidden prefix %q must be absolute without ..", f)
		}
		forbidden = append(forbidden, filepath.Clean(f))
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
	for _, m := range s.Mounts {
		if err := checkDest(m.Dest); err != nil {
			return nil, err
		}
		if m.Tmpfs {
			if m.SizeMB <= 0 {
				return nil, fmt.Errorf("tmpfs mount %q needs a positive size", m.Dest)
			}
			mounts = append(mounts, ociMount{Destination: m.Dest, Type: "tmpfs", Source: "tmpfs",
				Options: []string{"nosuid", "nodev", fmt.Sprintf("size=%dm", m.SizeMB)}})
			continue
		}
		if err := checkSource(m.Source, forbidden); err != nil {
			return nil, err
		}
		opts := []string{"rbind", "nosuid", "nodev"}
		if m.ReadOnly {
			opts = append(opts, "ro")
		} else {
			opts = append(opts, "rw")
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
				rl("RLIMIT_NPROC", uint64(s.PIDs)),
			},
			NoNewPrivileges: true,
		},
		Root:     ociRoot{Path: s.Rootfs, Readonly: true},
		Hostname: "kritolith",
		Mounts:   mounts,
		Linux: ociLinux{
			// No namespace carries a path, so each is created fresh.
			Namespaces: []ociNamespace{{Type: "pid"}, {Type: "network"}, {Type: "ipc"}, {Type: "uts"}, {Type: "mount"}},
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
