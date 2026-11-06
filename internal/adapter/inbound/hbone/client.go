package hbone

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/esachser/omnimeshdp/internal/adapter/sockmark"
	"github.com/esachser/omnimeshdp/internal/domain"
	"golang.org/x/net/http2"
)

const (
	// HeaderRealDest carries the intercepted destination IP:port.
	HeaderRealDest = "x-omnimesh-real-dest"
	// HeaderNodeServiceID carries the target service instance ID (NodeServiceInfo.ID / RouteName).
	HeaderNodeServiceID = "x-omnimesh-node-service-id"
	// HeaderCallerIdentity carries the caller SPIFFE identity.
	HeaderCallerIdentity = "x-omnimesh-caller-identity"
	// HeaderSourceIdentity carries the source SPIFFE identity.
	HeaderSourceIdentity = "x-omnimesh-source-identity"
)

// Client establishes and manages HTTP/2 HBONE tunnels to mesh endpoints.
type Client struct {
	httpClient *http.Client
	mu         sync.RWMutex
	tlsClients map[string]*http.Client
}

// NewClient constructs a new HBONE client supporting cleartext HTTP/2 (h2c) and mTLS.
func NewClient() *Client {
	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			// Mark proxy-originated sockets so Linux redirect rules skip them (no-op elsewhere).
			d := net.Dialer{Control: sockmark.Control(sockmark.ProxyMark)}
			return d.DialContext(ctx, network, addr)
		},
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
		},
		tlsClients: make(map[string]*http.Client),
	}
}

func (c *Client) getClient(targetHost string, tlsConfig *tls.Config) (*http.Client, string) {
	if tlsConfig == nil {
		return c.httpClient, "http://" + targetHost
	}

	key := fmt.Sprintf("%p|%s", tlsConfig, targetHost)
	c.mu.RLock()
	client, ok := c.tlsClients[key]
	c.mu.RUnlock()
	if ok {
		return client, "https://" + targetHost
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.tlsClients[key]; ok {
		return client, "https://" + targetHost
	}

	t := &http2.Transport{
		TLSClientConfig: tlsConfig,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			d := net.Dialer{Control: sockmark.Control(sockmark.ProxyMark)}
			return tls.DialWithDialer(&d, network, addr, cfg)
		},
	}

	client = &http.Client{Transport: t}
	c.tlsClients[key] = client
	return client, "https://" + targetHost
}

// Tunnel creates an HBONE CONNECT tunnel to targetHost, tunneling the provided localConn to realDest.
// If tlsConfig is provided, the tunnel connects via mTLS presenting the service's SVID;
// otherwise, cleartext HTTP/2 (h2c) is used.
func (c *Client) Tunnel(
	ctx context.Context,
	localConn net.Conn,
	targetHost string,
	realDest string,
	identity string,
	tlsConfig ...*tls.Config,
) error {
	return c.TunnelToService(ctx, localConn, targetHost, realDest, "", identity, tlsConfig...)
}

// TunnelToService creates an HBONE CONNECT tunnel to targetHost, carrying both the intercepted realDest
// and the target serviceID (via x-omnimesh-service-id) so the destination agent can connect to the
// locally configured service host and port.
func (c *Client) TunnelToService(
	ctx context.Context,
	localConn net.Conn,
	targetHost string,
	realDest string,
	nodeServiceID string,
	identity string,
	tlsConfig ...*tls.Config,
) error {
	pr, pw := io.Pipe()

	var cfg *tls.Config
	if len(tlsConfig) > 0 && tlsConfig[0] != nil {
		cfg = tlsConfig[0]
	}

	httpClient, reqURL := c.getClient(targetHost, cfg)

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, reqURL, pr)
	if err != nil {
		pw.Close()
		return fmt.Errorf("failed to create CONNECT request: %w", err)
	}

	req.Header.Set("Host", targetHost)
	req.Header.Set(HeaderRealDest, realDest)
	if nodeServiceID != "" {
		req.Header.Set(HeaderNodeServiceID, nodeServiceID)
	}
	if identity != "" {
		req.Header.Set(HeaderCallerIdentity, identity)
		req.Header.Set(HeaderSourceIdentity, identity)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		pw.Close()
		return fmt.Errorf("%w: %v", domain.ErrTunnelFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		pw.Close()
		return fmt.Errorf("%w: status %d", domain.ErrTunnelFailed, resp.StatusCode)
	}

	log.Printf("HBONE tunnel established to %s (destination %s, nodeServiceID %q, identity %q)\n", targetHost, realDest, nodeServiceID, identity)

	var wg sync.WaitGroup
	wg.Add(2)

	// Stream from local intercepted connection to HBONE pipe
	go func() {
		defer wg.Done()
		defer pw.Close()
		_, _ = io.Copy(pw, localConn)
	}()

	// Stream from HBONE response body back to local connection
	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, resp.Body)
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
	return nil
}
