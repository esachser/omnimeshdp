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
	"sync/atomic"
	"time"

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

// Tunnel represents an established HTTP/2 HBONE CONNECT tunnel (after HTTP 200 OK).
type Tunnel struct {
	pw     *io.PipeWriter
	body   io.ReadCloser
	cancel context.CancelFunc
	closed atomic.Bool
}

// Bridge streams data bidirectionally between localConn and the established HBONE tunnel
// until both directions complete, then releases tunnel resources.
func (t *Tunnel) Bridge(localConn net.Conn) error {
	if t == nil {
		return fmt.Errorf("%w: nil tunnel", domain.ErrTunnelFailed)
	}
	defer t.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Stream from local intercepted connection to HBONE pipe
	go func() {
		defer wg.Done()
		defer t.pw.Close()
		_, _ = io.Copy(t.pw, localConn)
	}()

	// Stream from HBONE response body back to local connection
	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, t.body)
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
	return nil
}

// Close closes the underlying HBONE stream pipes and cancels the request context.
func (t *Tunnel) Close() error {
	if t == nil || !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = t.pw.Close()
	err := t.body.Close()
	if t.cancel != nil {
		t.cancel()
	}
	return err
}

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
			return (&tls.Dialer{NetDialer: &d, Config: cfg}).DialContext(ctx, network, addr)
		},
	}

	client = &http.Client{Transport: t}
	c.tlsClients[key] = client
	return client, "https://" + targetHost
}

// OpenTunnel performs the HTTP/2 HBONE CONNECT handshake to targetHost without reading from
// or writing to any local connection. On HTTP 200 OK it returns an open *Tunnel ready for Bridge.
// Non-200 HTTP responses return *domain.TunnelStatusError (matching ErrBadGateway on 502).
func (c *Client) OpenTunnel(
	ctx context.Context,
	targetHost string,
	realDest string,
	nodeServiceID string,
	identity string,
	tlsConfig ...*tls.Config,
) (*Tunnel, error) {
	return c.OpenTunnelWithTimeout(ctx, 0, targetHost, realDest, nodeServiceID, identity, tlsConfig...)
}

// OpenTunnelWithTimeout performs the HTTP/2 HBONE CONNECT handshake with an optional per-attempt
// connectTimeout that applies only until the CONNECT response headers arrive, leaving the returned
// Tunnel bound to the parent ctx once HTTP 200 OK is received.
func (c *Client) OpenTunnelWithTimeout(
	ctx context.Context,
	connectTimeout time.Duration,
	targetHost string,
	realDest string,
	nodeServiceID string,
	identity string,
	tlsConfig ...*tls.Config,
) (*Tunnel, error) {
	pr, pw := io.Pipe()

	var cfg *tls.Config
	if len(tlsConfig) > 0 && tlsConfig[0] != nil {
		cfg = tlsConfig[0]
	}

	httpClient, reqURL := c.getClient(targetHost, cfg)

	reqCtx, cancelReq := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, reqURL, pr)
	if err != nil {
		_ = pw.Close()
		cancelReq()
		return nil, fmt.Errorf("failed to create CONNECT request: %w", err)
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

	var handshakeMu sync.Mutex
	handshakeDone := false
	var timedOut atomic.Bool
	var timer *time.Timer
	if connectTimeout > 0 {
		timer = time.AfterFunc(connectTimeout, func() {
			handshakeMu.Lock()
			done := handshakeDone
			if !done {
				timedOut.Store(true)
				cancelReq()
			}
			handshakeMu.Unlock()
		})
	}

	resp, err := httpClient.Do(req)

	handshakeMu.Lock()
	handshakeDone = true
	handshakeMu.Unlock()
	if timer != nil {
		timer.Stop()
	}

	if err != nil {
		_ = pw.Close()
		cancelReq()
		if timedOut.Load() && ctx.Err() == nil {
			return nil, fmt.Errorf("%w: %w", domain.ErrTunnelFailed, context.DeadlineExceeded)
		}
		return nil, fmt.Errorf("%w: %w", domain.ErrTunnelFailed, err)
	}

	if reqCtx.Err() != nil {
		_ = resp.Body.Close()
		_ = pw.Close()
		cancelReq()
		if timedOut.Load() && ctx.Err() == nil {
			return nil, fmt.Errorf("%w: %w", domain.ErrTunnelFailed, context.DeadlineExceeded)
		}
		return nil, fmt.Errorf("%w: %w", domain.ErrTunnelFailed, reqCtx.Err())
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		cancelReq()
		return nil, &domain.TunnelStatusError{StatusCode: resp.StatusCode}
	}

	log.Printf("HBONE tunnel established to %s (destination %s, nodeServiceID %q, identity %q)\n", targetHost, realDest, nodeServiceID, identity)

	return &Tunnel{
		pw:     pw,
		body:   resp.Body,
		cancel: cancelReq,
	}, nil
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
// and the target serviceID (via x-omnimesh-node-service-id) so the destination agent can connect to the
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
	tunnel, err := c.OpenTunnel(ctx, targetHost, realDest, nodeServiceID, identity, tlsConfig...)
	if err != nil {
		return err
	}
	return tunnel.Bridge(localConn)
}
