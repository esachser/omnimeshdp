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

	"github.com/esachser/omnimeshdp/internal/domain"
	"golang.org/x/net/http2"
)

// Client establishes and manages HTTP/2 HBONE tunnels to mesh endpoints.
type Client struct {
	httpClient *http.Client
}

// NewClient constructs a new HBONE client supporting cleartext HTTP/2 (h2c).
func NewClient() *Client {
	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
		},
	}
}

// Tunnel creates an HBONE CONNECT tunnel to targetHost, tunneling the provided localConn to realDest.
func (c *Client) Tunnel(
	ctx context.Context,
	localConn net.Conn,
	targetHost string,
	realDest string,
	identity string,
) error {
	pr, pw := io.Pipe()

	reqURL := "http://" + targetHost
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, reqURL, pr)
	if err != nil {
		pw.Close()
		return fmt.Errorf("failed to create CONNECT request: %w", err)
	}

	req.Header.Set("Host", targetHost)
	req.Header.Set("x-omnimesh-real-dest", realDest)
	if identity != "" {
		req.Header.Set("x-omnimesh-caller-identity", identity)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		pw.Close()
		return fmt.Errorf("%w: %v", domain.ErrTunnelFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		pw.Close()
		return fmt.Errorf("%w: status %d", domain.ErrTunnelFailed, resp.StatusCode)
	}

	log.Printf("HBONE tunnel established to %s (destination %s)\n", targetHost, realDest)

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
