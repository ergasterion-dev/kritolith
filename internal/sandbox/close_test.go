package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls cond (a state the test itself caused) for up to 10s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Close waits for an in-flight Run: the work dir lock is held and
// Close does not return until the Run (and its kill/delete) is done.
// A Run after Close is refused.
func TestRunscDriverCloseWaitsForRun(t *testing.T) {
	f := newFakeRunsc(t, `while [ ! -e "$D/release" ]; do sleep 0.02; done`, ``)
	workDir := realTempDir(t)
	d, err := newRunscDriver(f.path, workDir)
	if err != nil {
		t.Fatal(err)
	}
	var runDone atomic.Bool
	runErr := make(chan error, 1)
	go func() {
		_, err := d.Run(context.Background(), testSpec(t))
		runDone.Store(true)
		runErr <- err
	}()
	waitFor(t, "the container to start", func() bool { _, err := os.Stat(filepath.Join(f.dir, "started")); return err == nil })

	closed := make(chan bool, 1)
	go func() {
		_ = d.Close()
		closed <- runDone.Load()
	}()
	waitFor(t, "Close to mark the driver closed", func() bool { d.mu.Lock(); defer d.mu.Unlock(); return d.closed })
	if l, err := lockWorkDir(workDir); err == nil {
		unlockWorkDir(l)
		t.Fatal("the work dir lock was dropped while a Run was in flight")
	}
	if err := os.WriteFile(filepath.Join(f.dir, "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-runErr; err != nil {
		t.Fatalf("in-flight Run: %v", err)
	}
	if !<-closed {
		t.Fatal("Close returned before the in-flight Run")
	}
	if _, err := d.Run(context.Background(), testSpec(t)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Run after Close: %v", err)
	}
	if l, err := lockWorkDir(workDir); err != nil {
		t.Fatalf("lock not released after Close: %v", err)
	} else {
		unlockWorkDir(l)
	}
}

// Runner.Close waits for an in-flight Runner.Run, including its
// cleanup, before releasing the driver; Run after Close is skipped.
func TestRunnerCloseWaitsForRun(t *testing.T) {
	fx := newFixture(t, nil)
	block := make(chan struct{})
	entered := make(chan struct{})
	fx.drv.hook = func(phase string) {
		if phase == PhaseRun {
			close(entered)
			<-block
		}
	}
	var closerCalledAfterRun atomic.Bool
	var runDone atomic.Bool
	fx.runner.closer = func() error { closerCalledAfterRun.Store(runDone.Load()); return nil }
	done := make(chan Result, 1)
	go func() {
		res := fx.runner.Run(context.Background(), Request{Report: reportWithPoC(), ResolvedRef: refSHA, Claims: defaultClaims()})
		runDone.Store(true)
		done <- res
	}()
	<-entered
	closeDone := make(chan struct{})
	go func() { _ = fx.runner.Close(); close(closeDone) }()
	waitFor(t, "Close to start waiting", func() bool { fx.runner.mu.Lock(); defer fx.runner.mu.Unlock(); return fx.runner.closed })
	close(block)
	<-done
	<-closeDone
	if !closerCalledAfterRun.Load() {
		t.Fatal("the driver was closed while the Run was in flight")
	}
	res := fx.runner.Run(context.Background(), Request{Report: reportWithPoC(), ResolvedRef: refSHA, Claims: defaultClaims()})
	if !strings.Contains(res.Skipped, "closed") {
		t.Fatalf("Run after Close: %+v", res)
	}
}
