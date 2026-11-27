//go:build sandbox && !linux

package sandbox

// keptMount has nothing to name off Linux: there is no runsc, and
// mountPointsUnder reports no mounts.
func keptMount(string) string { return "" }
