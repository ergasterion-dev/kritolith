package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func goodSpec() ContainerSpec {
	return ContainerSpec{
		Rootfs: "/srv/kritolith/rootfs", Args: []string{"/usr/local/go/bin/go", "test"},
		Env: []string{"GOFLAGS=-mod=mod", "HOME=/tmp"}, Cwd: "/work",
		Mounts: []Mount{
			{Source: "/srv/kritolith/src", Dest: "/work", ReadOnly: true},
			{Dest: "/tmp", Tmpfs: true, SizeMB: 64},
		},
		MemoryMB: 512, CPUs: 2, PIDs: 128, CPUSeconds: 60, FileSizeKB: 1024,
		UID: 1000, GID: 1000, Forbidden: []string{"/srv/kritolith/data"},
	}
}

func TestBuildOCIDecodesAndHardens(t *testing.T) {
	t.Setenv("PATH", "/leaky/path")
	b, err := BuildOCI(goodSpec())
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	var o ociConfig
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(o.Process.Env, ","); got != "GOFLAGS=-mod=mod,HOME=/tmp" {
		t.Fatalf("env = %q", got)
	}
	if !o.Root.Readonly || !o.Process.NoNewPrivileges || o.Process.Terminal {
		t.Fatalf("root/process not locked down: %+v", o)
	}
	c := o.Process.Capabilities
	if len(c.Bounding)+len(c.Effective)+len(c.Inheritable)+len(c.Permitted)+len(c.Ambient) != 0 {
		t.Fatalf("capabilities not empty: %+v", c)
	}
	if o.Process.User.UID != 1000 {
		t.Fatalf("uid = %d", o.Process.User.UID)
	}
	if o.Linux.Resources.Memory.Limit != 512<<20 || o.Linux.Resources.CPU.Quota != 200000 ||
		o.Linux.Resources.CPU.Period != 100000 || o.Linux.Resources.Pids.Limit != 128 {
		t.Fatalf("resources: %+v", o.Linux.Resources)
	}
	rl := map[string]uint64{}
	for _, r := range o.Process.Rlimits {
		rl[r.Type] = r.Hard
		if r.Soft != r.Hard {
			t.Fatalf("soft != hard for %s", r.Type)
		}
	}
	for k, want := range map[string]uint64{"RLIMIT_CPU": 60, "RLIMIT_FSIZE": 1024 * 1024, "RLIMIT_NPROC": 128} {
		if rl[k] != want {
			t.Fatalf("%s = %d want %d", k, rl[k], want)
		}
	}
	if rl["RLIMIT_NOFILE"] == 0 {
		t.Fatal("no NOFILE limit")
	}
	var devs []string
	for _, d := range o.Linux.Devices {
		devs = append(devs, d.Path)
	}
	if strings.Join(devs, ",") != "/dev/null,/dev/zero,/dev/urandom,/dev/tty" {
		t.Fatalf("devices = %v", devs)
	}
	nsTypes := map[string]bool{}
	for _, n := range o.Linux.Namespaces {
		if n.Path != "" {
			t.Fatalf("namespace %s joins host path %q", n.Type, n.Path)
		}
		nsTypes[n.Type] = true
	}
	for _, n := range []string{"pid", "network", "ipc", "uts", "mount"} {
		if !nsTypes[n] {
			t.Fatalf("missing namespace %s", n)
		}
	}
	var sawTmp bool
	for _, m := range o.Mounts {
		if m.Destination == "/tmp" {
			sawTmp = true
			if m.Type != "tmpfs" || !strings.Contains(strings.Join(m.Options, ","), "size=64m") {
				t.Fatalf("tmp mount: %+v", m)
			}
		}
	}
	if !sawTmp {
		t.Fatal("no tmpfs")
	}
}

func TestBuildOCINoHostPathLeaks(t *testing.T) {
	for _, network := range []bool{false, true} {
		s := goodSpec()
		s.Network = network
		b, err := BuildOCI(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"/Users", "/home", "/var/lib", "/var/run/docker.sock", "/srv/kritolith/data", "/leaky"} {
			if strings.Contains(string(b), bad) {
				t.Fatalf("network=%v: output contains %q", network, bad)
			}
		}
	}
}

func TestBuildOCIRejects(t *testing.T) {
	cases := map[string]func(*ContainerSpec){
		"forbidden prefix":   func(s *ContainerSpec) { s.Mounts[0].Source = "/srv/kritolith/data/keys" },
		"forbidden exact":    func(s *ContainerSpec) { s.Mounts[0].Source = "/srv/kritolith/data" },
		"var run":            func(s *ContainerSpec) { s.Mounts[0].Source = "/var/run/x" },
		"run":                func(s *ContainerSpec) { s.Mounts[0].Source = "/run" },
		"proc":               func(s *ContainerSpec) { s.Mounts[0].Source = "/proc/1" },
		"sys":                func(s *ContainerSpec) { s.Mounts[0].Source = "/sys" },
		"dev":                func(s *ContainerSpec) { s.Mounts[0].Source = "/dev/sda" },
		"etc":                func(s *ContainerSpec) { s.Mounts[0].Source = "/etc/passwd" },
		"docker sock":        func(s *ContainerSpec) { s.Mounts[0].Source = "/opt/x/docker.sock" },
		"relative source":    func(s *ContainerSpec) { s.Mounts[0].Source = "src" },
		"dotdot source":      func(s *ContainerSpec) { s.Mounts[0].Source = "/srv/kritolith/src/../data/x" },
		"relative dest":      func(s *ContainerSpec) { s.Mounts[0].Dest = "work" },
		"uncleaned dest":     func(s *ContainerSpec) { s.Mounts[0].Dest = "/work/../x" },
		"dest proc":          func(s *ContainerSpec) { s.Mounts[0].Dest = "/proc/x" },
		"dest sys":           func(s *ContainerSpec) { s.Mounts[0].Dest = "/sys" },
		"dest dev":           func(s *ContainerSpec) { s.Mounts[1].Dest = "/dev/shm" },
		"tmpfs no size":      func(s *ContainerSpec) { s.Mounts[1].SizeMB = 0 },
		"zero memory":        func(s *ContainerSpec) { s.MemoryMB = 0 },
		"negative cpus":      func(s *ContainerSpec) { s.CPUs = -1 },
		"zero pids":          func(s *ContainerSpec) { s.PIDs = 0 },
		"zero cpu seconds":   func(s *ContainerSpec) { s.CPUSeconds = 0 },
		"zero file size":     func(s *ContainerSpec) { s.FileSizeKB = 0 },
		"uid zero":           func(s *ContainerSpec) { s.UID = 0 },
		"negative gid":       func(s *ContainerSpec) { s.GID = -1 },
		"no args":            func(s *ContainerSpec) { s.Args = nil },
		"relative cwd":       func(s *ContainerSpec) { s.Cwd = "work" },
		"relative rootfs":    func(s *ContainerSpec) { s.Rootfs = "rootfs" },
		"malformed env":      func(s *ContainerSpec) { s.Env = []string{"NOEQUALS"} },
		"relative forbidden": func(s *ContainerSpec) { s.Forbidden = []string{"data"} },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			s := goodSpec()
			mut(&s)
			if _, err := BuildOCI(s); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestBuildOCIPrefixBoundary(t *testing.T) {
	s := goodSpec()
	s.Mounts[0].Source = "/srv/kritolith/data-other/x" // sibling, not under the forbidden prefix
	if _, err := BuildOCI(s); err != nil {
		t.Fatalf("sibling of forbidden prefix wrongly rejected: %v", err)
	}
}
