//go:build linux

package linuxutils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"golang.org/x/sys/unix"
)

// ErrSocketNotFound indicates no local socket matched the requested endpoints.
var ErrSocketNotFound = errors.New("socket not found in /proc/net tables")

// OriginalDst returns the pre-NAT destination of a TCP connection that was
// redirected by netfilter (REDIRECT/DNAT), using SO_ORIGINAL_DST. Only IPv4
// sockets are supported.
func OriginalDst(fd uintptr) (netip.AddrPort, error) {
	// SO_ORIGINAL_DST fills a struct sockaddr_in (16 bytes). IPv6Mreq (20 bytes) is
	// the fixed-size getsockopt helper in x/sys/unix large enough to receive it.
	mreq, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", err)
	}
	return decodeSockaddrIn(mreq.Multiaddr[:])
}

// localAddr returns the local IPv4 endpoint of a socket.
func localAddr(fd uintptr) (netip.AddrPort, error) {
	sa, err := unix.Getsockname(int(fd))
	if err != nil {
		return netip.AddrPort{}, err
	}
	sa4, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("unexpected socket address type %T", sa)
	}
	return netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), uint16(sa4.Port)), nil
}

// FindSocketOwner returns the PID and UID of the local process owning the TCP
// socket with the given endpoints (as seen by that process).
// Resolving the PID requires permission to read /proc/<pid>/fd of the owner
// (root or CAP_SYS_PTRACE); the UID is returned even when the PID cannot be found.
func FindSocketOwner(local, remote netip.AddrPort) (pid int, uid uint32, err error) {
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())

	var sock procNetSocket
	found := false
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, openErr := os.Open(table)
		if openErr != nil {
			continue
		}
		sock, found, err = findProcNetSocket(f, local, remote)
		_ = f.Close()
		if err != nil {
			return 0, 0, fmt.Errorf("reading %s: %w", table, err)
		}
		if found {
			break
		}
	}
	if !found || sock.Inode == 0 {
		return 0, 0, fmt.Errorf("%w: %s -> %s", ErrSocketNotFound, local, remote)
	}

	pid, err = findPIDByInode(sock.Inode)
	if err != nil {
		return 0, sock.UID, err
	}
	return pid, sock.UID, nil
}

// findPIDByInode scans /proc/<pid>/fd for the process holding socket:[inode].
func findPIDByInode(inode uint64) (int, error) {
	target := "socket:[" + strconv.FormatUint(inode, 10) + "]"

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, proc := range procs {
		pid, err := strconv.Atoi(proc.Name())
		if err != nil || !proc.IsDir() {
			continue
		}
		fdDir := "/proc/" + proc.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process exited or not permitted
		}
		for _, fd := range fds {
			if link, err := os.Readlink(fdDir + "/" + fd.Name()); err == nil && link == target {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("no process owns socket inode %d", inode)
}

// GetOriginalPacketInfo resolves the pre-redirect destination and the owning PID of
// a connection accepted on a listener that netfilter redirected traffic to.
// addr is the accepted connection's remote address (the client's own local
// endpoint) and socket is the accepted connection's file descriptor.
// A missing PID is not an error: PID is left as 0 and identity lookup will fail.
func GetOriginalPacketInfo(addr net.Addr, socket uintptr) (*model.OriginalPacketInfo, error) {
	if socket == 0 {
		return nil, errors.New("invalid socket descriptor")
	}

	orig, err := OriginalDst(socket)
	if err != nil {
		return nil, err
	}
	// Without NAT, SO_ORIGINAL_DST returns the listener address itself; tunneling
	// that would loop back into the proxy.
	if local, err := localAddr(socket); err == nil && local == orig {
		return nil, fmt.Errorf("connection to %s was not redirected by netfilter", orig)
	}

	ip4 := orig.Addr().As4()
	info := &model.OriginalPacketInfo{
		IP:   binary.BigEndian.Uint32(ip4[:]),
		Port: orig.Port(),
	}

	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		if peerIP, ok := netip.AddrFromSlice(tcpAddr.IP); ok {
			peer := netip.AddrPortFrom(peerIP.Unmap(), uint16(tcpAddr.Port))
			if pid, _, err := FindSocketOwner(peer, orig); err == nil {
				info.PID = uint64(pid)
			}
		}
	}
	return info, nil
}

// GetIdentityByPID returns the effective UID of a process as a decimal string,
// the Linux counterpart of the Windows user SID.
func GetIdentityByPID(pid uint64) (string, bool) {
	if pid == 0 {
		return "", false
	}
	f, err := os.Open("/proc/" + strconv.FormatUint(pid, 10) + "/status")
	if err != nil {
		return "", false
	}
	defer f.Close()

	uid, err := parseStatusEffectiveUID(f)
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(uint64(uid), 10), true
}
