//go:build !linux

package sandbox

// newHostBridges off Linux: network namespaces do not exist, so the
// fetch phase has no bridge.
func newHostBridges(string) bridgeProvider {
	return unavailableBridge{reason: "the fetch phase's network bridge needs Linux network namespaces"}
}

// sweepBridges is a no-op off Linux: no bridge was ever created.
func sweepBridges(string) error { return nil }
