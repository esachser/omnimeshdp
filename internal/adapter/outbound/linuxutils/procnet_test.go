package linuxutils

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// hexWord renders 4 network-order bytes the way the kernel prints them in /proc/net/tcp.
func hexWord(b []byte) string {
	return fmt.Sprintf("%08X", binary.NativeEndian.Uint32(b))
}

func procNetLine(sl int, local, remote netip.AddrPort, uid uint32, inode uint64, v6 bool) string {
	enc := func(ap netip.AddrPort) string {
		var hexIP string
		if v6 {
			b := ap.Addr().As16()
			hexIP = hexWord(b[0:4]) + hexWord(b[4:8]) + hexWord(b[8:12]) + hexWord(b[12:16])
		} else {
			b := ap.Addr().As4()
			hexIP = hexWord(b[:])
		}
		return fmt.Sprintf("%s:%04X", hexIP, ap.Port())
	}
	return fmt.Sprintf("%4d: %s %s 01 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 20 4 30 10 -1",
		sl, enc(local), enc(remote), uid, inode)
}

func TestFindProcNetSocket_IPv4(t *testing.T) {
	local := netip.MustParseAddrPort("192.168.1.5:54321")
	remote := netip.MustParseAddrPort("10.10.10.7:8080")
	table := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		procNetLine(0, netip.MustParseAddrPort("127.0.0.1:15001"), netip.MustParseAddrPort("0.0.0.0:0"), 0, 111, false),
		procNetLine(1, local, netip.MustParseAddrPort("10.10.10.8:8080"), 1001, 222, false),
		procNetLine(2, local, remote, 1000, 333, false),
	}, "\n")

	sock, found, err := findProcNetSocket(strings.NewReader(table), local, remote)
	if err != nil || !found {
		t.Fatalf("expected socket to be found, found=%v err=%v", found, err)
	}
	if sock.UID != 1000 || sock.Inode != 333 {
		t.Fatalf("unexpected socket: %+v", sock)
	}
}

func TestFindProcNetSocket_IPv4MappedInTCP6(t *testing.T) {
	local := netip.MustParseAddrPort("192.168.1.5:40000")
	remote := netip.MustParseAddrPort("10.10.12.1:443")
	mapped := func(ap netip.AddrPort) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom16(ap.Addr().As16()), ap.Port())
	}
	table := "header\n" + procNetLine(0, mapped(local), mapped(remote), 42, 999, true)

	sock, found, err := findProcNetSocket(strings.NewReader(table), local, remote)
	if err != nil || !found {
		t.Fatalf("expected v4-mapped socket to be found, found=%v err=%v", found, err)
	}
	if sock.UID != 42 || sock.Inode != 999 {
		t.Fatalf("unexpected socket: %+v", sock)
	}
}

func TestFindProcNetSocket_NotFound(t *testing.T) {
	table := "header\n" + procNetLine(0,
		netip.MustParseAddrPort("192.168.1.5:1"), netip.MustParseAddrPort("10.0.0.1:2"), 0, 1, false)
	_, found, err := findProcNetSocket(strings.NewReader(table),
		netip.MustParseAddrPort("192.168.1.5:3"), netip.MustParseAddrPort("10.0.0.1:2"))
	if err != nil || found {
		t.Fatalf("expected not found without error, found=%v err=%v", found, err)
	}
}

func TestParseStatusEffectiveUID(t *testing.T) {
	status := "Name:\tcurl\nState:\tS (sleeping)\nUid:\t1000\t1001\t1001\t1001\nGid:\t1000\t1000\t1000\t1000\n"
	uid, err := parseStatusEffectiveUID(strings.NewReader(status))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != 1001 {
		t.Fatalf("expected effective uid 1001, got %d", uid)
	}

	if _, err := parseStatusEffectiveUID(strings.NewReader("Name:\tx\n")); err == nil {
		t.Fatalf("expected error when Uid line is missing")
	}
}

func TestDecodeSockaddrIn(t *testing.T) {
	b := make([]byte, 16)
	binary.NativeEndian.PutUint16(b[0:2], 2) // AF_INET
	binary.BigEndian.PutUint16(b[2:4], 8080)
	copy(b[4:8], []byte{10, 10, 10, 7})

	ap, err := decodeSockaddrIn(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap != netip.MustParseAddrPort("10.10.10.7:8080") {
		t.Fatalf("unexpected address: %v", ap)
	}

	binary.NativeEndian.PutUint16(b[0:2], 10) // AF_INET6
	if _, err := decodeSockaddrIn(b); err == nil {
		t.Fatalf("expected error for non-IPv4 family")
	}
}
