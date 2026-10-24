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

// SubnetUpdater is an optional capability of a PacketProcessor that can replace
// the set of intercepted subnets while running, without restarting interception.
// Implementations must apply the change atomically: traffic is either matched by
// the old set or by the new set, never by neither.
type SubnetUpdater interface {
	// UpdateSubnets replaces the intercepted IPv4 CIDR subnets. An empty slice
	// removes every redirection while keeping the processor running.
	UpdateSubnets(subnets []string) error
}
