package sandbox

import (
	"context"
	"time"
)

// RunSpec is one container run: the container, a host-enforced wall
// clock and a cap on the bytes of combined output kept.
type RunSpec struct {
	Container   ContainerSpec
	Timeout     time.Duration
	OutputLimit int
}

// driver runs one command in a fresh container and destroys it.
//
// A non-zero exit of the contained command is reported in
// RunOutput.ExitCode and is not an error. An error means the driver
// could not run the container at all (bad spec, bundle creation
// failed, runtime would not start) or the caller's ctx ended the run;
// either way the result is inconclusive, never a rejection. Failing to
// kill or delete the container afterwards is also an error, because it
// may still be running.
//
// After a cancel or timeout, cleanup can take up to about 65s in the
// worst case (runsc kill 30s, delete --force 30s, pipe drain 5s), so
// callers should budget shutdown for that. The runsc driver's and the
// Runner's Close wait for in-flight runs, so the work dir lock and the
// runsc state outlive that cleanup.
type driver interface {
	Run(ctx context.Context, s RunSpec) (RunOutput, error)
}
