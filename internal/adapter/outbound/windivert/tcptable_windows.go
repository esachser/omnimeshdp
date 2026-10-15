//go:build windows

package windivert

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afInet                      = 2
	tcpTableOwnerPidConnections = 4
)

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

func getPIDFromLocalPort(port uint16) (int32, error) {
	var size uint32
	// First call to get required buffer size
	r1, _, _ := procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0, // bOrder = false
		uintptr(afInet),
		uintptr(tcpTableOwnerPidConnections),
		0,
	)

	if size == 0 {
		return -1, fmt.Errorf("GetExtendedTcpTable returned 0 size, code: %d", r1)
	}

	buf := make([]byte, size)
	r1, _, err := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(afInet),
		uintptr(tcpTableOwnerPidConnections),
		0,
	)

	if r1 != 0 {
		return -1, fmt.Errorf("GetExtendedTcpTable failed: %w (code %d)", err, r1)
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	rowSize := unsafe.Sizeof(mibTcpRowOwnerPid{})

	portBE := windows.Ntohs(port)

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibTcpRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		// LocalPort in MIB_TCPROW_OWNER_PID is stored in network byte order in lower 16 bits
		if uint16(row.LocalPort) == portBE {
			return int32(row.OwningPID), nil
		}
	}

	return -1, fmt.Errorf("port %d not found in TCP table", port)
}
