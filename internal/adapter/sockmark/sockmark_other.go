//go:build !linux

package sockmark

import "syscall"

// Control returns nil on non-Linux platforms, leaving net.Dialer behavior unchanged.
func Control(mark uint32) func(network, address string, c syscall.RawConn) error {
	return nil
}
