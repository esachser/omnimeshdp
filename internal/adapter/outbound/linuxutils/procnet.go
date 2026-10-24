package linuxutils

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// procNetSocket is a parsed row of /proc/net/tcp or /proc/net/tcp6.
type procNetSocket struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
	UID    uint32
	Inode  uint64
}

// findProcNetSocket scans a /proc/net/tcp{,6} table for the socket whose local and
// remote endpoints match. IPv4-mapped IPv6 addresses are compared as plain IPv4, so
// dual-stack client sockets are found too. Callers must pass unmapped addresses.
func findProcNetSocket(r io.Reader, local, remote netip.AddrPort) (procNetSocket, bool, error) {
	sc := bufio.NewScanner(r)
	header := true
	for sc.Scan() {
		if header {
			header = false
			continue
		}
		// sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode ...
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		l, err := parseProcNetAddr(fields[1])
		if err != nil || l != local {
			continue
		}
		rm, err := parseProcNetAddr(fields[2])
		if err != nil || rm != remote {
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return procNetSocket{}, false, fmt.Errorf("invalid uid %q: %w", fields[7], err)
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return procNetSocket{}, false, fmt.Errorf("invalid inode %q: %w", fields[9], err)
		}
		return procNetSocket{Local: l, Remote: rm, UID: uint32(uid), Inode: inode}, true, nil
	}
	return procNetSocket{}, false, sc.Err()
}

// parseProcNetAddr decodes an "ADDR:PORT" hex pair from /proc/net/tcp{,6}.
// The kernel prints each 32-bit word of the (network-order) address as a native
// integer, so the words must be re-encoded with the host byte order.
func parseProcNetAddr(s string) (netip.AddrPort, error) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("malformed address %q", s)
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("malformed port in %q: %w", s, err)
	}

	var addr netip.Addr
	switch len(hexIP) {
	case 8:
		var b [4]byte
		v, err := strconv.ParseUint(hexIP, 16, 32)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("malformed IPv4 in %q: %w", s, err)
		}
		binary.NativeEndian.PutUint32(b[:], uint32(v))
		addr = netip.AddrFrom4(b)
	case 32:
		var b [16]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(hexIP[i*8:(i+1)*8], 16, 32)
			if err != nil {
				return netip.AddrPort{}, fmt.Errorf("malformed IPv6 in %q: %w", s, err)
			}
			binary.NativeEndian.PutUint32(b[i*4:], uint32(v))
		}
		addr = netip.AddrFrom16(b).Unmap()
	default:
		return netip.AddrPort{}, fmt.Errorf("unexpected address length in %q", s)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// parseStatusEffectiveUID extracts the effective UID from /proc/<pid>/status.
// The line format is "Uid:\t<real>\t<effective>\t<saved>\t<fs>".
func parseStatusEffectiveUID(r io.Reader) (uint32, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed Uid line %q", sc.Text())
		}
		uid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("malformed effective uid %q: %w", fields[1], err)
		}
		return uint32(uid), nil
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("Uid line not found")
}

// decodeSockaddrIn decodes a struct sockaddr_in (as filled by SO_ORIGINAL_DST):
// sin_family (host order), sin_port (network order), sin_addr (network order).
func decodeSockaddrIn(b []byte) (netip.AddrPort, error) {
	const afInet = 2
	if len(b) < 8 {
		return netip.AddrPort{}, fmt.Errorf("sockaddr_in too short: %d bytes", len(b))
	}
	if family := binary.NativeEndian.Uint16(b[0:2]); family != afInet {
		return netip.AddrPort{}, fmt.Errorf("unexpected address family %d (only IPv4 is supported)", family)
	}
	port := binary.BigEndian.Uint16(b[2:4])
	addr := netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]})
	return netip.AddrPortFrom(addr, port), nil
}
