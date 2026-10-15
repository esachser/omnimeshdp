//go:build windows

package wfp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/winutils"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"golang.org/x/sys/windows"
)

const (
	// IOCTL_MESH_SET_CONFIG = CTL_CODE(FILE_DEVICE_NETWORK (0x12), 0x930, METHOD_OUT_DIRECT (2), FILE_WRITE_DATA|FILE_READ_DATA (3))
	// ((0x12) << 16) | ((3) << 14) | ((0x930) << 2) | 2 = 0x0012E4C2 = 1238210
	ioctlMeshSetConfig = uint32(0x0012E4C2)

	// SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT is defined in mstcpip.h as _WSAIOW(IOC_VENDOR, 221) = 2550137053
	sioQueryWfpConnectionRedirectContext = uint32(2550137053)
)

var (
	modWs2_32    = windows.NewLazySystemDLL("ws2_32.dll")
	procWSAIoctl = modWs2_32.NewProc("WSAIoctl")
)

var _ outbound.PacketProcessor = (*WfpProcessor)(nil)

// WfpProcessor manages Windows Filtering Platform redirection via the OmniMesh driver.
type WfpProcessor struct {
	config       []model.ProxyConfig
	deviceHandle []windows.Handle
	mu           sync.Mutex
	closed       bool
}

// NewWfpProcessor creates a new WfpProcessor instance.
func NewWfpProcessor(config []model.ProxyConfig) (*WfpProcessor, error) {
	return &WfpProcessor{
		config: config,
	}, nil
}

// Run connects to the driver device and sends the redirection configuration.
func (w *WfpProcessor) Run(ctx context.Context) error {
	devicePath, err := windows.UTF16PtrFromString(`\\.\Omnimesh`)
	if err != nil {
		return fmt.Errorf("invalid device path: %w", err)
	}

	for _, cfg := range w.config {
		hDevice, err := windows.CreateFile(
			devicePath,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if err != nil {
			return fmt.Errorf("failed to open \\\\.\\Omnimesh driver: %w", err)
		}

		w.mu.Lock()
		w.deviceHandle = append(w.deviceHandle, hDevice)
		w.mu.Unlock()

		var bytesReturned uint32
		err = windows.DeviceIoControl(
			hDevice,
			ioctlMeshSetConfig,
			(*byte)(unsafe.Pointer(&cfg)),
			uint32(unsafe.Sizeof(cfg)),
			nil,
			0,
			&bytesReturned,
			nil,
		)
		if err != nil {
			windows.CloseHandle(hDevice)
			return fmt.Errorf("DeviceIoControl IOCTL_MESH_SET_CONFIG failed: %w", err)
		}
	}

	log.Println("WFP driver configuration successfully applied.")

	<-ctx.Done()
	return w.Close()
}

// GetIdentityByPID queries the Windows user SID for a process.
func (w *WfpProcessor) GetIdentityByPID(pid uint64) (string, bool) {
	sid, err := winutils.GetUserSIDFromPID(uint32(pid))
	if err != nil {
		return "", false
	}
	return sid, true
}

// GetOriginalPacketInfo queries the redirection context for the given socket using WSAIoctl.
func (w *WfpProcessor) GetOriginalPacketInfo(addr net.Addr, socket uintptr) (*model.OriginalPacketInfo, error) {
	if socket == 0 {
		return nil, fmt.Errorf("invalid socket handle")
	}

	var pktInfo model.OriginalPacketInfo
	var bytesReturned uint32

	r1, _, err := procWSAIoctl.Call(
		socket,
		uintptr(sioQueryWfpConnectionRedirectContext),
		0,
		0,
		uintptr(unsafe.Pointer(&pktInfo)),
		uintptr(unsafe.Sizeof(pktInfo)),
		uintptr(unsafe.Pointer(&bytesReturned)),
		0,
		0,
	)

	if r1 != 0 {
		return nil, fmt.Errorf("WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT failed: %w", err)
	}

	return &pktInfo, nil
}

// Close closes the driver handle.
func (w *WfpProcessor) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true

	var errs []error

	for _, device := range w.deviceHandle {
		if device != 0 && device != windows.InvalidHandle {
			err := windows.CloseHandle(device)
			if err != nil && err != syscall.EINVAL {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}
