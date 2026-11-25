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
// either way the result is inconclusive, never a rejection.
type driver interface {
	Run(ctx context.Context, s RunSpec) (RunOutput, error)
}
