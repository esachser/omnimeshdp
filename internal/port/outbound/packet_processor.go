package outbound

import (
	"context"
	"net"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

// PacketProcessor abstracts OS-level packet interception (WinDivert, WFP, or eBPF).
type PacketProcessor interface {
	// Run initializes and begins packet interception.
	Run(ctx context.Context) error

	// GetIdentityByPID queries the security identity (e.g., Windows SID) associated with the process.
	GetIdentityByPID(pid uint64) (string, bool)

	// GetOriginalPacketInfo resolves destination and process metadata for an intercepted socket or address.
	GetOriginalPacketInfo(addr net.Addr, socket uintptr) (*model.OriginalPacketInfo, error)

	// Close terminates packet interception and cleans up resources.
	Close() error
}
