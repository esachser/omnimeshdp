//go:build windows

package windivert

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	LayerNetwork        = 0
	LayerNetworkForward = 1
	LayerFlow           = 2
	LayerSocket         = 3
	LayerReflect        = 4

	FlagSniff    = 0x0001
	FlagDrop     = 0x0002
	FlagRecvOnly = 0x0004
	FlagSendOnly = 0x0008

	MTUMax = 40 + 0xFFFF // 65575 bytes
)

// Address matches WINDIVERT_ADDRESS layout (80 bytes total).
type Address struct {
	Timestamp int64
	Bitfield  uint32 // Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1, IPv6:1, IPChecksum:1, TCPChecksum:1, UDPChecksum:1, Reserved1:8
	Reserved2 uint32
	Data      [64]byte
}

func (a *Address) Outbound() bool {
	return (a.Bitfield & (1 << 17)) != 0
}

func (a *Address) Loopback() bool {
	return (a.Bitfield & (1 << 18)) != 0
}

func (a *Address) SetLoopback(v bool) {
	if v {
		a.Bitfield |= (1 << 18)
	} else {
		a.Bitfield &= ^uint32(1 << 18)
	}
}

// IpHdr matches WINDIVERT_IPHDR (20 bytes min).
type IpHdr struct {
	HdrLengthVersion uint8 // HdrLength:4, Version:4
	TOS              uint8
	Length           uint16
	ID               uint16
	FragOff0         uint16
	TTL              uint8
	Protocol         uint8
	Checksum         uint16
	SrcAddr          uint32
	DstAddr          uint32
}

// TcpHdr matches WINDIVERT_TCPHDR (20 bytes min).
type TcpHdr struct {
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32
	AckNum   uint32
	Flags    uint16 // Reserved1:4, HdrLength:4, FIN..URG
	Window   uint16
	Checksum uint16
	UrgPtr   uint16
}

func (t *TcpHdr) SYN() bool {
	// Syn is bit 9 in flags (assuming little endian representation of the 16-bit word)
	// In C: Reserved1:4, HdrLength:4, Fin:1, Syn:1...
	return (t.Flags & 0x0200) != 0
}

var (
	dllOnce sync.Once
	dllErr  error
	dll     *windows.DLL

	procWinDivertOpen                *windows.Proc
	procWinDivertRecv                *windows.Proc
	procWinDivertSend                *windows.Proc
	procWinDivertHelperParsePacket   *windows.Proc
	procWinDivertHelperCalcChecksums *windows.Proc
	procWinDivertClose               *windows.Proc
)

func initDLL() error {
	dllOnce.Do(func() {
		dllPath := findWinDivertDLL()
		loadedDLL, err := windows.LoadDLL(dllPath)
		if err != nil {
			dllErr = fmt.Errorf("failed to load WinDivert DLL from %q: %w", dllPath, err)
			return
		}
		dll = loadedDLL

		procWinDivertOpen = dll.MustFindProc("WinDivertOpen")
		procWinDivertRecv = dll.MustFindProc("WinDivertRecv")
		procWinDivertSend = dll.MustFindProc("WinDivertSend")
		procWinDivertHelperParsePacket = dll.MustFindProc("WinDivertHelperParsePacket")
		procWinDivertHelperCalcChecksums = dll.MustFindProc("WinDivertHelperCalcChecksums")
		procWinDivertClose = dll.MustFindProc("WinDivertClose")
	})
	return dllErr
}

func findWinDivertDLL() string {
	if envPath := os.Getenv("WINDIVERT_PATH"); envPath != "" {
		candidate := filepath.Join(envPath, "WinDivert.dll")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	knownLocations := []string{
		`C:\Users\eduar\OneDrive\Documentos\WinDivert-2.2.2-A\x64\WinDivert.dll`,
		"WinDivert.dll",
	}

	for _, loc := range knownLocations {
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}

	return "WinDivert.dll"
}

func winDivertOpen(filter string, layer uint32, priority int16, flags uint64) (windows.Handle, error) {
	if err := initDLL(); err != nil {
		return windows.InvalidHandle, err
	}

	filterBytes, err := windows.BytePtrFromString(filter)
	if err != nil {
		return windows.InvalidHandle, err
	}

	r1, _, err := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(filterBytes)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)

	h := windows.Handle(r1)
	if h == windows.InvalidHandle {
		return windows.InvalidHandle, fmt.Errorf("WinDivertOpen failed: %w", err)
	}

	return h, nil
}

func winDivertRecv(h windows.Handle, packet []byte, addr *Address) (uint32, error) {
	var packetLen uint32
	r1, _, err := procWinDivertRecv.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&packetLen)),
		uintptr(unsafe.Pointer(addr)),
	)

	if r1 == 0 {
		return 0, err
	}
	return packetLen, nil
}

func winDivertSend(h windows.Handle, packet []byte, packetLen uint32, addr *Address) (uint32, error) {
	var sendLen uint32
	r1, _, err := procWinDivertSend.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(packetLen),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)

	if r1 == 0 {
		return 0, err
	}
	return sendLen, nil
}

func winDivertHelperParsePacket(packet []byte, packetLen uint32, ppIpHdr **IpHdr, ppTcpHdr **TcpHdr) bool {
	r1, _, _ := procWinDivertHelperParsePacket.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(packetLen),
		uintptr(unsafe.Pointer(ppIpHdr)),
		0, // ppIpv6Hdr
		0, // pProtocol
		0, // ppIcmpHdr
		0, // ppIcmp6Hdr
		uintptr(unsafe.Pointer(ppTcpHdr)),
		0, // ppUdpHdr
		0, // ppData
		0, // pDataLen
		0, // ppNext
		0, // pNextLen
	)
	return r1 != 0
}

func winDivertHelperCalcChecksums(packet []byte, packetLen uint32, addr *Address, flags uint64) {
	procWinDivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(packetLen),
		uintptr(unsafe.Pointer(addr)),
		uintptr(flags),
	)
}

func winDivertClose(h windows.Handle) error {
	if procWinDivertClose == nil {
		return nil
	}
	r1, _, err := procWinDivertClose.Call(uintptr(h))
	if r1 == 0 {
		return err
	}
	return nil
}
