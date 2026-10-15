package spiffe

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
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

func (s *SpiffeTLSProvider) GetTLSConfig() (*tls.Config, error) {
	tlsConfig := tlsconfig.MTLSClientConfig(s.source, s.source, tlsconfig.AuthorizeID(s.serverSVID))
	return tlsConfig, nil
}

func (s *SpiffeTLSProvider) Close() error {
	return s.source.Close()
}
