package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestParseGoRelease(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		major, minor int
		ok           bool
	}{
		{"release with time line", "go1.27.4\ntime 2026-07-01T21:24:27Z\n", 1, 27, true},
		{"release, no newline", "go1.27.4", 1, 27, true},
		{"first release of a line", "go1.23\n", 1, 23, true},
		{"point zero", "go1.23.0\n", 1, 23, true},
		{"older", "go1.22.9\n", 1, 22, true},
		{"release candidate", "go1.23rc1\n", 1, 23, true},
		{"beta", "go1.24beta2\n", 1, 24, true},
		{"crlf", "go1.26.0\r\n", 1, 26, true},
		{"go 2", "go2.0\n", 2, 0, true},
		{"devel", "devel go1.27-3b2a1c0 Tue Jul 1 21:24:27 2026 +0000\n", 0, 0, false},
		{"devel plus", "devel +3b2a1c0\n", 0, 0, false},
		{"empty", "", 0, 0, false},
		{"blank first line", "\ngo1.27.4\n", 0, 0, false},
		{"garbage", "\x00\xff not a version", 0, 0, false},
		{"no minor", "go1\n", 0, 0, false},
		{"trailing text", "go1.27.4 X:something\n", 0, 0, false},
		{"leading space", " go1.27.4\n", 0, 0, false},
		{"signed", "go1.-23\n", 0, 0, false},
		{"huge number", "go1.99999999999999999999\n", 0, 0, false},
		{"version on a later line", "x\ngo1.27.4\n", 0, 0, false},
		{"first line fills the read", "go1.27.4" + strings.Repeat("9", goVersionBytes), 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := []byte(tt.in)
			if len(in) > goVersionBytes {
				in = in[:goVersionBytes]
			}
			major, minor, ok := parseGoRelease(in)
			if major != tt.major || minor != tt.minor || ok != tt.ok {
				t.Fatalf("parseGoRelease(%q) = %d, %d, %v; want %d, %d, %v", tt.in, major, minor, ok, tt.major, tt.minor, tt.ok)
			}
		})
	}
}

// writeGoVersion writes the rootfs's usr/local/go/VERSION.
func writeGoVersion(t *testing.T, rootfs, content string) {
	t.Helper()
	dir := filepath.Join(rootfs, "usr", "local", "go")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRootfsLinknameCheckOff(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, rootfs string)
		want  bool
	}{
		{"go1.27.4", func(t *testing.T, r string) { writeGoVersion(t, r, "go1.27.4\ntime 2026-07-01T21:24:27Z\n") }, true},
		{"go1.23", func(t *testing.T, r string) { writeGoVersion(t, r, "go1.23\n") }, true},
		{"go1.23rc1", func(t *testing.T, r string) { writeGoVersion(t, r, "go1.23rc1\n") }, true},
		{"go2.0", func(t *testing.T, r string) { writeGoVersion(t, r, "go2.0\n") }, true},
		{"go1.22.9", func(t *testing.T, r string) { writeGoVersion(t, r, "go1.22.9\n") }, false},
		{"devel", func(t *testing.T, r string) { writeGoVersion(t, r, "devel go1.27-3b2a1c0\n") }, false},
		{"empty file", func(t *testing.T, r string) { writeGoVersion(t, r, "") }, false},
		{"garbage", func(t *testing.T, r string) { writeGoVersion(t, r, "\x00\xff\x01") }, false},
		{"large file", func(t *testing.T, r string) { writeGoVersion(t, r, strings.Repeat("go1.27.4", 1<<16)) }, false},
		{"missing file", func(t *testing.T, r string) {}, false},
		{"missing rootfs", nil, false},
		{"a directory", func(t *testing.T, r string) {
			if err := os.MkdirAll(filepath.Join(r, "usr", "local", "go", "VERSION"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"a symlink", func(t *testing.T, r string) {
			target := filepath.Join(t.TempDir(), "VERSION")
			if err := os.WriteFile(target, []byte("go1.27.4\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(r, "usr", "local", "go"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(r, "usr", "local", "go", "VERSION")); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"unreadable", func(t *testing.T, r string) {
			if os.Geteuid() == 0 {
				t.Skip("root reads any file")
			}
			writeGoVersion(t, r, "go1.27.4\n")
			if err := os.Chmod(filepath.Join(r, "usr", "local", "go", "VERSION"), 0); err != nil {
				t.Fatal(err)
			}
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootfs := t.TempDir()
			if tt.setup == nil {
				rootfs = filepath.Join(rootfs, "nope")
			} else {
				tt.setup(t, rootfs)
			}
			if got := rootfsLinknameCheckOff(rootfs); got != tt.want {
				t.Fatalf("rootfsLinknameCheckOff = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRunnerBuildLinknameFlag checks the exact build command of every
// PoC shape, at the ref and at the HEAD control, with and without a
// rootfs Go that has the linker's linkname check.
func TestRunnerBuildLinknameFlag(t *testing.T) {
	const flag = " -ldflags=-checklinkname=0"
	fuzzPass := "=== RUN   FuzzParse\n=== RUN   FuzzParse/seed.1\n--- PASS: FuzzParse (0.00s)\n    --- PASS: FuzzParse/seed.1 (0.00s)\nPASS\n"
	shapes := []struct {
		name       string
		pocName    string
		req        Request
		script     map[string]step
		builds     int    // build containers: 2 when the control runs
		pre, post  string // the build command around the flag
		wantResult func(Result) bool
	}{
		{
			name: "test", pocName: "poc_test.go",
			script: map[string]step{"ref/run": stepPanic, "head/run": stepPass}, builds: 2,
			pre: "go test -c -o /out/poc.test -vet=off -race", post: " -cover -coverpkg=example.com/m/vuln ./vuln",
			wantResult: func(r Result) bool {
				return r.Repro != nil && r.Repro.Reproduced && r.Repro.ControlState == ControlFixed
			},
		},
		{
			name: "fuzz", pocName: "seed.1",
			req:    Request{Report: report.Report{PoC: []report.Artifact{{Name: "testdata/fuzz/FuzzParse/seed.1", Content: []byte("go test fuzz v1\n[]byte(\"\")\n")}}}, PoCDirHint: "vuln"},
			script: map[string]step{"ref/run": {out: RunOutput{Output: []byte(fuzzPass)}}}, builds: 1,
			pre: "go test -c -o /out/poc.test -vet=off -race", post: " -cover -coverpkg=example.com/m/vuln ./vuln",
			wantResult: func(r Result) bool { return r.Passed },
		},
		{
			name: "program", pocName: "main.go",
			req:    Request{Report: report.Report{PoC: []report.Artifact{{Name: "main.go", Content: []byte("package main\n\nimport \"example.com/m/vuln\"\n\nfunc main() { vuln.Parse(nil) }\n")}}}},
			script: map[string]step{"ref/run": {out: RunOutput{Output: []byte("done\n")}}}, builds: 1,
			pre: "go build -o /out/poc -race", post: " ./cmd/kritolith-poc",
			wantResult: func(r Result) bool { return r.Passed },
		},
	}
	versions := []struct {
		name    string
		version *string // nil: no VERSION file
		flag    bool
	}{
		{"go1.27.4", ptr("go1.27.4\ntime 2026-07-01T21:24:27Z\n"), true},
		{"go1.23", ptr("go1.23\n"), true},
		{"go1.22.9", ptr("go1.22.9\n"), false},
		{"devel", ptr("devel go1.27-3b2a1c0\n"), false},
		{"garbage", ptr("\x00\xff"), false},
		{"missing", nil, false},
	}
	for _, sh := range shapes {
		for _, v := range versions {
			t.Run(sh.name+"/"+v.name, func(t *testing.T) {
				fx := newFixture(t, sh.script)
				fx.drv.pocName = sh.pocName
				if v.version != nil {
					writeGoVersion(t, fx.rootfs, *v.version)
				}
				res := fx.run(t, sh.req)
				if !sh.wantResult(res) {
					t.Fatalf("result %+v (repro %+v)", res, res.Repro)
				}
				want := sh.pre + sh.post
				if v.flag {
					want = sh.pre + flag + sh.post
				}
				builds := 0
				for _, c := range fx.drv.calls {
					got := strings.Join(c.spec.Container.Args, " ")
					if c.phase != PhaseBuild {
						if strings.Contains(got, "ldflags") || strings.Contains(got, "checklinkname") {
							t.Errorf("%s/%s: linker flag outside the build: %q", c.who, c.phase, got)
						}
						continue
					}
					builds++
					if got != want {
						t.Errorf("%s build args\n got %q\nwant %q", c.who, got, want)
					}
					if env := envMap(t, c.spec.Container.Env); env["GOFLAGS"] != "-mod=mod" {
						t.Errorf("%s build GOFLAGS = %q, want it unchanged", c.who, env["GOFLAGS"])
					}
				}
				if builds != sh.builds {
					t.Fatalf("%d build containers, want %d: %v", builds, sh.builds, fx.drv.phases())
				}
			})
		}
	}
}

func ptr(s string) *string { return &s }
