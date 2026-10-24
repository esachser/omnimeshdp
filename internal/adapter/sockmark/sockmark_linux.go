//go:build linux

package sockmark

import (
	"log"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var warnOnce sync.Once

// Control returns a net.Dialer Control function that sets SO_MARK to mark on the
// socket before it connects. Marking is best-effort: it requires CAP_NET_ADMIN, and
// a failure is logged once instead of failing the dial (without the capability no
// redirection rules can be installed either, so there is no loop to prevent).
func Control(mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		if sockErr != nil {
			warnOnce.Do(func() {
				log.Printf("Warning: could not set SO_MARK 0x%x on proxy sockets (missing CAP_NET_ADMIN?): %v\n", mark, sockErr)
			})
		}
		return nil
	}
}
