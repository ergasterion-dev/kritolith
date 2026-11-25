//go:build !linux

package sandbox

// unmountNullNetns is a no-op off Linux: runsc does not run there.
func unmountNullNetns(string) error { return nil }
