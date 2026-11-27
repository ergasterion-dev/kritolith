//go:build sandbox && linux

package sandbox

import "path/filepath"

// keptMount is the one mount under a work dir that may stay while the
// driver lives: runsc's own null-netns in the state dir.
func keptMount(state string) string { return filepath.Join(state, nullNetnsName) }
