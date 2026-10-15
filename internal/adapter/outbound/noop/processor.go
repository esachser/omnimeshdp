package noop

import (
	"context"
	"log"
	"net"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

var _ outbound.PacketProcessor = (*NoOpProcessor)(nil)

// NoOpProcessor implements PacketProcessor as a harmless no-op for platforms or configurations without packet interception.
type NoOpProcessor struct{}

// NewNoOpProcessor constructs a NoOpProcessor instance.
func NewNoOpProcessor() *NoOpProcessor {
	return &NoOpProcessor{}
}

// Run logs and waits for context cancellation.
func (p *NoOpProcessor) Run(ctx context.Context) error {
	log.Println("NoOpProcessor running. No packet interception will be performed.")
	<-ctx.Done()
	return nil
}

// GetIdentityByPID returns no identity.
func (p *NoOpProcessor) GetIdentityByPID(pid uint64) (string, bool) {
	return "", false
}

// GetOriginalPacketInfo returns no packet info.
func (p *NoOpProcessor) GetOriginalPacketInfo(addr net.Addr, socket uintptr) (*model.OriginalPacketInfo, error) {
	return nil, nil
}

// Close is a no-op.
func (p *NoOpProcessor) Close() error {
	return nil
}
