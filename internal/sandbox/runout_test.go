package sandbox

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// fakeOutFS records the size-capped /out mounts the Runner asks for.
type fakeOutFS struct {
	mu         sync.Mutex
	drv        *fakeDriver
	mountErr   error
	releaseErr error
	mounts     []fakeOutMount
	active     int
}

type fakeOutMount struct {
	dir      string
	size     int64
	inodes   int
	uid, gid int
	// callsAtMount and callsAtRelease are len(drv.calls) then.
	callsAtMount, callsAtRelease int
	released                     bool
}

func (f *fakeOutFS) Mount(dir string, size int64, inodes, uid, gid int) (func() error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mountErr != nil {
		return nil, f.mountErr
	}
	f.drv.mu.Lock()
	n := len(f.drv.calls)
	f.drv.mu.Unlock()
	f.mounts = append(f.mounts, fakeOutMount{dir: dir, size: size, inodes: inodes, uid: uid, gid: gid, callsAtMount: n})
	i := len(f.mounts) - 1
	f.active++
	return func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.drv.mu.Lock()
		f.mounts[i].callsAtRelease = len(f.drv.calls)
		f.drv.mu.Unlock()
		f.mounts[i].released = true
		f.active--
		return f.releaseErr
	}, nil
}

// The run phase's writable /out is a size-capped mount made just
// before the run container and released before the scratch tree goes,
// on every path; the coverage profile is still read back.
func TestRunnerRunOutIsSizeCapped(t *testing.T) {
	fx := newFixture(t, map[string]step{"ref/run": stepAssert, "head/run": stepPass})
	res := fx.run(t, Request{})
	if !res.Repro.Reproduced || res.Repro.ControlState != ControlFixed {
		t.Fatalf("coverage not read back through the capped /out: %s", resText(res))
	}
	m := fx.outFS.mounts
	if len(m) != 2 {
		t.Fatalf("%d /out mounts, want one per run phase (ref and control)", len(m))
	}
	for i, mt := range m {
		run := fx.drv.calls[mt.callsAtMount]
		if run.phase != PhaseRun || mountSource(run.spec, ctrOut) != mt.dir {
			t.Errorf("mount %d on %s is not the next run's /out (%s)", i, mt.dir, run.phase)
		}
		if mt.size != runOutBytes || mt.size > 16<<20 || mt.inodes != runOutInodes {
			t.Errorf("mount %d: size %d inodes %d", i, mt.size, mt.inodes)
		}
		if mt.uid != fx.runner.uid || mt.gid != fx.runner.gid {
			t.Errorf("mount %d owned by %d:%d, want the container user", i, mt.uid, mt.gid)
		}
		if !mt.released || mt.callsAtRelease != mt.callsAtMount+1 {
			t.Errorf("mount %d: released %v after %d calls, want right after the run", i, mt.released, mt.callsAtRelease)
		}
	}
	if fx.outFS.active != 0 {
		t.Fatalf("%d mounts left", fx.outFS.active)
	}
}

// Without a cap on /out the run never starts: INCONCLUSIVE, not a
// verdict, and nothing is left mounted.
func TestRunnerRunOutMountFailureIsInconclusive(t *testing.T) {
	fx := newFixture(t, map[string]step{"ref/run": stepPanic})
	fx.outFS.mountErr = errors.New("operation not permitted")
	res := fx.run(t, Request{})
	if !strings.Contains(res.Inconclusive, "/out") || res.Passed || (res.Repro != nil && res.Repro.Reproduced) {
		t.Fatalf("want INCONCLUSIVE naming /out: %s", resText(res))
	}
	for _, c := range fx.drv.calls {
		if c.phase == PhaseRun {
			t.Fatal("the run container started without a capped /out")
		}
	}

	fx = newFixture(t, map[string]step{"ref/run": stepPanic})
	fx.runner.outFS = nil
	if res := fx.run(t, Request{}); !strings.Contains(res.Inconclusive, "/out") {
		t.Fatalf("no mounter: %s", resText(res))
	}
}

// A release failure is noted; the result stands.
func TestRunnerRunOutReleaseFailureNoted(t *testing.T) {
	fx := newFixture(t, map[string]step{"ref/run": stepPanic, "head/run": stepPass})
	fx.outFS.releaseErr = errors.New("device busy")
	res := fx.run(t, Request{})
	if !strings.Contains(strings.Join(res.Repro.Notes, "\n"), "/out") {
		t.Fatalf("notes %q, want the release failure", res.Repro.Notes)
	}
}

func resText(res Result) string {
	s := fmt.Sprintf("%+v", res)
	if res.Repro != nil {
		s += fmt.Sprintf(" repro %+v", *res.Repro)
	}
	return s
}
