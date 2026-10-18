package proxy

import (
	"context"
	"net"

	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
)

var _ inbound.ProxyService = (*ServerSideService)(nil)

// ServerSideService wraps the HTTP/2 HBONE server as an inbound proxy service.
type ServerSideService struct {
	server *hbone.Server
}

// NewServerSideService creates a new ServerSideService listening on listenAddr.
func NewServerSideService(listenAddr string) *ServerSideService {
	if listenAddr == "" {
		listenAddr = "0.0.0.0:15008"
	}
	return &ServerSideService{
		server: hbone.NewServer(listenAddr),
	}
}

// Start runs the HBONE server until context cancellation.
func (s *ServerSideService) Start(ctx context.Context) error {
	return s.server.Start(ctx)
}

// Serve serves traffic on the provided listener until context cancellation.
func (s *ServerSideService) Serve(ctx context.Context, ln net.Listener) error {
	return s.server.Serve(ctx, ln)
}

