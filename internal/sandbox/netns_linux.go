package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// nullNetnsName is the file runsc creates under its --root for
// --network=none. It is an nsfs bind mount that runsc never removes, so
// it outlives every container and blocks deleting the state directory
// (unlinkat: device or resource busy). Verified on runsc 20261102.0.
const nullNetnsName = "null-netns"

// unmountNullNetns releases runsc's null-netns mount under stateRoot. A
// missing file or a path that is not a mount point is not an error.
func unmountNullNetns(stateRoot string) error {
	p := filepath.Join(stateRoot, nullNetnsName)
	if err := syscall.Unmount(p, 0); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("sandbox: unmount %s: %w", nullNetnsName, err)
	}
	return nil
}
