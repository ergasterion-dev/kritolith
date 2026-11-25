package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/sandbox"
)

type fakeSandbox struct {
	closes int
}

func (f *fakeSandbox) Run(context.Context, sandbox.Request) sandbox.Result {
	return sandbox.Result{Skipped: "fake"}
}

func (f *fakeSandbox) Close() error { f.closes++; return nil }

// stubSandbox replaces the sweep and constructor seams for one test.
func stubSandbox(t *testing.T, sweep func(runtime, workDir string) error, build func(cfg config.Sandbox, resolve sandbox.SourceResolver, workDir, dataDir string) (sandboxRunner, error)) {
	t.Helper()
	oldSweep, oldNew := sweepSandboxOrphans, newSandboxRunner
	t.Cleanup(func() { sweepSandboxOrphans, newSandboxRunner = oldSweep, oldNew })
	sweepSandboxOrphans, newSandboxRunner = sweep, build
}

func sandboxCfg(rootfs string) *config.Config {
	return &config.Config{Sandbox: config.Sandbox{Rootfs: rootfs}}
}

// With no sandbox section nothing sandbox-related runs.
func TestNewProcessorSandboxDisabled(t *testing.T) {
	stubSandbox(t,
		func(string, string) error { t.Error("sweep called with the sandbox disabled"); return nil },
		func(config.Sandbox, sandbox.SourceResolver, string, string) (sandboxRunner, error) {
			t.Error("constructor called with the sandbox disabled")
			return nil, nil
		})
	for _, cfg := range []*config.Config{nil, {}} {
		var errOut bytes.Buffer
		pr, err := newProcessor(context.Background(), cfg, filepath.Join(t.TempDir(), "data"), &errOut)
		if err != nil {
			t.Fatal(err)
		}
		if pr.sandbox != nil || errOut.Len() != 0 {
			t.Fatalf("sandbox = %v, stderr = %q", pr.sandbox, errOut.String())
		}
		pr.close()
	}
}

// The real constructor on a host without a usable sandbox (no Linux,
// or no rootfs at that path): one stderr line, and the command goes on.
func TestNewProcessorSandboxUnavailableRealHost(t *testing.T) {
	var errOut bytes.Buffer
	data := filepath.Join(t.TempDir(), "data")
	pr, err := newProcessor(context.Background(), sandboxCfg(filepath.Join(t.TempDir(), "no-rootfs")), data, &errOut)
	if err != nil {
		t.Fatalf("newProcessor = %v; an unavailable sandbox must not fail the command", err)
	}
	defer pr.close()
	if pr.sandbox != nil {
		t.Fatal("sandbox set although it is unavailable")
	}
	line := errOut.String()
	if !strings.HasPrefix(line, "kritolith: sandbox unavailable: ") || !strings.HasSuffix(line, "; PoCs will not be run\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("stderr = %q, want one 'sandbox unavailable' line", line)
	}
}

func TestNewProcessorSandboxWiring(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	fake := &fakeSandbox{}
	var order []string
	stubSandbox(t,
		func(runtime, workDir string) error {
			order = append(order, "sweep")
			if runtime != "runsc" || workDir != data+"-sandbox" {
				t.Errorf("sweep(%q, %q)", runtime, workDir)
			}
			return errors.New("leftover container would not die")
		},
		func(cfg config.Sandbox, resolve sandbox.SourceResolver, workDir, dataDir string) (sandboxRunner, error) {
			order = append(order, "new")
			if workDir != data+"-sandbox" || dataDir != data || cfg.Rootfs != "/srv/rootfs" {
				t.Errorf("new(%+v, %q, %q)", cfg, workDir, dataDir)
			}
			if src, err := resolve("owner/name"); err != nil || src == nil {
				t.Errorf("resolve(owner/name) = %v, %v", src, err)
			}
			if _, err := resolve("../etc"); err == nil {
				t.Error("resolve accepted an invalid repository")
			}
			return fake, nil
		})
	var errOut bytes.Buffer
	pr, err := newProcessor(context.Background(), sandboxCfg("/srv/rootfs"), data, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "sweep,new" {
		t.Fatalf("order = %v, want the sweep once, before the runner is built", order)
	}
	if pr.sandbox != fake {
		t.Fatalf("sandbox = %v", pr.sandbox)
	}
	if !strings.Contains(errOut.String(), "leftover container would not die") {
		t.Errorf("a failed sweep must be reported: stderr = %q", errOut.String())
	}
	pr.close()
	pr.close()
	if fake.closes != 1 {
		t.Fatalf("Close called %d times, want 1", fake.closes)
	}
}

func TestNewProcessorSandboxErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantErr  bool
		wantLine string
	}{
		{"unavailable", &sandbox.Unavailable{Reason: "gVisor needs a Linux host"}, false, "kritolith: sandbox unavailable: gVisor needs a Linux host; PoCs will not be run\n"},
		{"other error", errors.New("boom"), true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubSandbox(t, func(string, string) error { return nil },
				func(config.Sandbox, sandbox.SourceResolver, string, string) (sandboxRunner, error) {
					return nil, tt.err
				})
			var errOut bytes.Buffer
			pr, err := newProcessor(context.Background(), sandboxCfg("/srv/rootfs"), filepath.Join(t.TempDir(), "data"), &errOut)
			if tt.wantErr {
				if err == nil {
					pr.close()
					t.Fatal("want a startup error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer pr.close()
			if pr.sandbox != nil || errOut.String() != tt.wantLine {
				t.Fatalf("sandbox = %v, stderr = %q", pr.sandbox, errOut.String())
			}
		})
	}
}

func TestNewProcessorIgnoreCgroupsWarns(t *testing.T) {
	stubSandbox(t, func(string, string) error { return nil },
		func(cfg config.Sandbox, _ sandbox.SourceResolver, _, _ string) (sandboxRunner, error) {
			if !cfg.IgnoreCgroups {
				t.Error("ignore_cgroups not passed to the constructor")
			}
			return &fakeSandbox{}, nil
		})
	cfg := sandboxCfg("/srv/rootfs")
	cfg.Sandbox.IgnoreCgroups = true
	var errOut bytes.Buffer
	pr, err := newProcessor(context.Background(), cfg, filepath.Join(t.TempDir(), "data"), &errOut)
	if err != nil {
		t.Fatal(err)
	}
	defer pr.close()
	if !strings.Contains(errOut.String(), "WARNING: sandbox.ignore_cgroups") {
		t.Fatalf("stderr = %q, want a loud warning", errOut.String())
	}
}

func TestSandboxWorkDir(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	linkIntoData := filepath.Join(base, "link")
	if err := os.Symlink(data, linkIntoData); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name            string
		workDir, rootfs string
		want            string // "" means an error
	}{
		{"default sibling", "", "", data + "-sandbox"},
		{"explicit elsewhere", filepath.Join(base, "work"), "", filepath.Join(base, "work")},
		{"equal to data dir", data, "", ""},
		{"inside data dir", filepath.Join(data, "sandbox"), "", ""},
		{"contains data dir", base, "", ""},
		{"through a symlink into the data dir", filepath.Join(linkIntoData, "work"), "", ""},
		{"rootfs inside data dir", "", filepath.Join(data, "rootfs"), ""},
		{"rootfs elsewhere", "", filepath.Join(base, "rootfs"), data + "-sandbox"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sandboxWorkDir(config.Sandbox{WorkDir: tt.workDir, Rootfs: tt.rootfs}, data)
			if tt.want == "" {
				if err == nil || !strings.Contains(err.Error(), "outside the data dir") {
					t.Fatalf("sandboxWorkDir = %q, %v; want an 'outside the data dir' error", got, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("sandboxWorkDir = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
	if _, err := sandboxWorkDir(config.Sandbox{}, "relative"); err == nil {
		t.Error("a relative data dir was accepted")
	}
	if _, err := sandboxWorkDir(config.Sandbox{}, "/"); err == nil {
		t.Error("data dir / has no sibling and must be refused")
	}
}

// A work dir that overlaps the data dir stops newProcessor before any
// sweep or runner.
func TestNewProcessorRefusesWorkDirInDataDir(t *testing.T) {
	stubSandbox(t,
		func(string, string) error { t.Error("sweep ran"); return nil },
		func(config.Sandbox, sandbox.SourceResolver, string, string) (sandboxRunner, error) {
			t.Error("constructor ran")
			return nil, nil
		})
	data := filepath.Join(t.TempDir(), "data")
	cfg := sandboxCfg("/srv/rootfs")
	cfg.Sandbox.WorkDir = filepath.Join(data, "sandbox")
	var errOut bytes.Buffer
	if pr, err := newProcessor(context.Background(), cfg, data, &errOut); err == nil {
		pr.close()
		t.Fatal("want an error")
	}
}

func TestSandboxLogSink(t *testing.T) {
	data := t.TempDir()
	sink := newSandboxLogSink(data)
	sink("01JREPORT", map[string][]byte{
		"run":           []byte("hostile output"),
		"control/build": []byte("build log"),
		"../escape":     []byte("x"),
		"Run":           []byte("x"),
		"a b":           []byte("x"),
		"":              []byte("x"),
	})
	dir := filepath.Join(data, sandboxLogsDir, "01JREPORT")
	for _, d := range []string{filepath.Join(data, sandboxLogsDir), dir} {
		fi, err := os.Lstat(d)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v, %v; want a 0700 directory", d, fi, err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
		fi, err := os.Lstat(filepath.Join(dir, e.Name()))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v; want a 0600 regular file", e.Name(), fi, err)
		}
	}
	if strings.Join(names, ",") != "control-build.log,run.log" {
		t.Fatalf("files = %v, want only the two sane phase names", names)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "run.log")); string(b) != "hostile output" {
		t.Fatalf("run.log = %q", b)
	}
	if _, err := os.Lstat(filepath.Join(data, sandboxLogsDir, "escape.log")); err == nil {
		t.Fatal("a phase name escaped the report directory")
	}

	// A second write of the same report never replaces a kept log.
	sink("01JREPORT", map[string][]byte{"run": []byte("replaced")})
	if b, _ := os.ReadFile(filepath.Join(dir, "run.log")); string(b) != "hostile output" {
		t.Fatalf("run.log replaced: %q", b)
	}
}

func TestSandboxLogSinkRefuses(t *testing.T) {
	t.Run("odd report id", func(t *testing.T) {
		data := t.TempDir()
		for _, id := range []string{"", "../x", "a/b", ".", "x y"} {
			if err := writeSandboxLogs(data, id, map[string][]byte{"run": []byte("x")}); err == nil {
				t.Errorf("report id %q accepted", id)
			}
		}
		if _, err := os.Lstat(filepath.Join(data, sandboxLogsDir)); err == nil {
			t.Error("a directory was created for a refused report id")
		}
	})
	t.Run("symlinked logs dir", func(t *testing.T) {
		data, elsewhere := t.TempDir(), t.TempDir()
		if err := os.Symlink(elsewhere, filepath.Join(data, sandboxLogsDir)); err != nil {
			t.Fatal(err)
		}
		if err := writeSandboxLogs(data, "R1", map[string][]byte{"run": []byte("x")}); err == nil {
			t.Fatal("wrote through a symlinked sandbox-logs dir")
		}
		if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
			t.Fatalf("files written through the link: %v", ents)
		}
	})
	t.Run("symlinked log file", func(t *testing.T) {
		data, elsewhere := t.TempDir(), t.TempDir()
		dir := filepath.Join(data, sandboxLogsDir, "R1")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(data, sandboxLogsDir), 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(elsewhere, "victim")
		if err := os.Symlink(target, filepath.Join(dir, "run.log")); err != nil {
			t.Fatal(err)
		}
		if err := writeSandboxLogs(data, "R1", map[string][]byte{"run": []byte("x")}); err == nil {
			t.Fatal("wrote through a symlinked log file")
		}
		if _, err := os.Lstat(target); err == nil {
			t.Fatal("the link target was created")
		}
	})
}

// check with a sandbox section on a host where it cannot run: the
// command succeeds and says once that PoCs will not be run.
func TestCheckSandboxUnavailableContinues(t *testing.T) {
	cfg := writeConfigFile(t, `{"sandbox":{"rootfs":"`+filepath.Join(t.TempDir(), "no-rootfs")+`"}}`)
	p := writeReport(t, "no ref report")
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"check", "--repo", "a/b", "--config", cfg, "--data-dir", filepath.Join(t.TempDir(), "data"), p}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	if strings.Count(errOut.String(), "kritolith: sandbox unavailable: ") != 1 || !strings.Contains(errOut.String(), "; PoCs will not be run") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}
