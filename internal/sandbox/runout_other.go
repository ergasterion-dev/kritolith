//go:build !linux

package sandbox

import "errors"

type noOutFS struct{}

func newHostOutFS() outMounter { return noOutFS{} }

func (noOutFS) Mount(string, int64, int, int, int) (func() error, error) {
	return nil, errors.New("a size-capped tmpfs needs Linux")
}

func unmountRunOuts(string) error { return nil }

func mountPointsUnder(string) ([]string, error) { return nil, nil }
