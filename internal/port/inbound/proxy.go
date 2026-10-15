package inbound

import "context"

// ProxyService represents an inbound or outbound proxy listener service.
type ProxyService interface {
	// Start starts serving network traffic until context is canceled.
	Start(ctx context.Context) error
}
