package spiffe

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var (
	_ outbound.TLSConfigProvider       = (*SpiffeTLSProvider)(nil)
	_ outbound.ServerTLSConfigProvider = (*SpiffeTLSProvider)(nil)
)

type SpiffeTLSProvider struct {
	source     *workloadapi.X509Source
	serverSVID spiffeid.ID
}

func NewSpiffeTLSProvider(ctx context.Context, socketPath string, serverSVID string) (*SpiffeTLSProvider, error) {
	clientOptions := []workloadapi.ClientOption{}
	if socketPath != "" {
		clientOptions = append(clientOptions, workloadapi.WithAddr(socketPath))
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(clientOptions...))
	if err != nil {
		return nil, err
	}
	serverID := spiffeid.RequireFromString(serverSVID)
	return &SpiffeTLSProvider{source: source, serverSVID: serverID}, nil
}

// GetTLSConfig returns the mTLS client config for connecting to the control plane.
func (s *SpiffeTLSProvider) GetTLSConfig() (*tls.Config, error) {
	tlsConfig := tlsconfig.MTLSClientConfig(s.source, s.source, tlsconfig.AuthorizeID(s.serverSVID))
	return tlsConfig, nil
}

// GetServerTLSConfig returns the mTLS server config for receiving inter-agent mesh traffic.
func (s *SpiffeTLSProvider) GetServerTLSConfig() (*tls.Config, error) {
	authorizer := tlsconfig.AuthorizeMemberOf(s.serverSVID.TrustDomain())
	tlsConfig := tlsconfig.MTLSServerConfig(s.source, s.source, authorizer)
	tlsConfig.NextProtos = []string{"h2"}
	return tlsConfig, nil
}

// Source returns the underlying SPIFFE X509Source (which also implements x509bundle.Source).
func (s *SpiffeTLSProvider) Source() *workloadapi.X509Source {
	return s.source
}

// ServerSVID returns the configured server SPIFFE ID.
func (s *SpiffeTLSProvider) ServerSVID() spiffeid.ID {
	return s.serverSVID
}

func (s *SpiffeTLSProvider) Close() error {
	return s.source.Close()
}
