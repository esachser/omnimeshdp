package proxy

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
)

var _ inbound.ProxyService = (*ServerSideService)(nil)

// ServerSideService wraps the HTTP/2 HBONE server as an inbound proxy service.
type ServerSideService struct {
	server *hbone.Server
}

// NewServerSideService creates a new ServerSideService listening on listenAddr.
// If serverTLS is provided, the server enforces HTTP/2 over TLS with mTLS.
func NewServerSideService(listenAddr string, serverTLS ...*tls.Config) *ServerSideService {
	if listenAddr == "" {
		listenAddr = "0.0.0.0:15008"
	}
	return &ServerSideService{
		server: hbone.NewServer(listenAddr, serverTLS...),
	}
}

// SetTLSConfig updates the server's mTLS configuration.
func (s *ServerSideService) SetTLSConfig(cfg *tls.Config) {
	s.server.SetTLSConfig(cfg)
}

// SetServices configures the locally deployed services used to resolve incoming HBONE service IDs.
func (s *ServerSideService) SetServices(services []model.NodeServiceInfo) {
	s.server.SetServices(services)
}

// UpdateServices incrementally adds/updates and removes locally deployed services.
func (s *ServerSideService) UpdateServices(added, removed []model.NodeServiceInfo) {
	s.server.UpdateServices(added, removed)
}

// Start runs the HBONE server until context cancellation.
func (s *ServerSideService) Start(ctx context.Context) error {
	return s.server.Start(ctx)
}

// Serve serves traffic on the provided listener until context cancellation.
func (s *ServerSideService) Serve(ctx context.Context, ln net.Listener) error {
	return s.server.Serve(ctx, ln)
}
