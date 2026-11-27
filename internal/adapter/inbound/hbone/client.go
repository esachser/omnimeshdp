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
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
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
	// HeaderSourceNode carries the calling node ID across the HBONE CONNECT handshake.
	HeaderSourceNode = "x-omnimesh-source-node"
)

// TunnelOptions configures an HBONE CONNECT tunnel attempt.
type TunnelOptions struct {
	ConnectTimeout time.Duration
	TargetHost     string
	RealDest       string
	NodeServiceID  string
	SourceNodeID   string
	DestService    string
	DestNodeID     string
	Identity       string
	TLSConfig      *tls.Config
}

// Tunnel represents an established HTTP/2 HBONE CONNECT tunnel (after HTTP 200 OK).
type Tunnel struct {
	pw         *io.PipeWriter
	body       io.ReadCloser
	cancel     context.CancelFunc
	targetHost string
	peerNode   string
	metrics    outbound.MetricRecorder
	closed     atomic.Bool
}

// Conn returns a net.Conn view over the established HBONE tunnel stream.
func (t *Tunnel) Conn() net.Conn {
	return &tunnelConn{
		tunnel:     t,
		reader:     newDeadlineReader(t.body),
		remoteAddr: hboneAddr{addr: t.targetHost},
		localAddr:  hboneAddr{addr: "local"},
	}
}

type tunnelConn struct {
	tunnel     *Tunnel
	reader     *deadlineReader
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *tunnelConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if n > 0 && c.tunnel != nil && c.tunnel.metrics != nil {
		c.tunnel.metrics.AddCounter(context.Background(), outbound.MetricHBONEBytesReceived, int64(n),
			model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: c.tunnel.peerNode},
			model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
		)
	}
	return n, err
}

func (c *tunnelConn) Write(p []byte) (int, error) {
	n, err := c.tunnel.pw.Write(p)
	if n > 0 && c.tunnel != nil && c.tunnel.metrics != nil {
		c.tunnel.metrics.AddCounter(context.Background(), outbound.MetricHBONEBytesSent, int64(n),
			model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: c.tunnel.peerNode},
			model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
		)
	}
	return n, err
}
func (c *tunnelConn) Close() error                      { _ = c.reader.Close(); return c.tunnel.Close() }
func (c *tunnelConn) CloseWrite() error                 { return c.tunnel.pw.Close() }
func (c *tunnelConn) LocalAddr() net.Addr               { return c.localAddr }
func (c *tunnelConn) RemoteAddr() net.Addr              { return c.remoteAddr }
func (c *tunnelConn) SetDeadline(t time.Time) error     { return c.reader.SetReadDeadline(t) }
func (c *tunnelConn) SetReadDeadline(t time.Time) error { return c.reader.SetReadDeadline(t) }
func (c *tunnelConn) SetWriteDeadline(time.Time) error  { return nil }

type hboneAddr struct {
	addr string
}

func (a hboneAddr) Network() string { return "hbone" }
func (a hboneAddr) String() string  { return a.addr }

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
		var dst io.Writer = t.pw
		if t.metrics != nil {
			dst = &countingWriter{
				w: t.pw,
				onWrite: func(n int) {
					t.metrics.AddCounter(context.Background(), outbound.MetricHBONEBytesSent, int64(n),
						model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: t.peerNode},
						model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
					)
				},
			}
		}
		_, _ = io.Copy(dst, localConn)
	}()

	// Stream from HBONE response body back to local connection
	go func() {
		defer wg.Done()
		var src io.Reader = t.body
		if t.metrics != nil {
			src = &countingReader{
				r: t.body,
				onRead: func(n int) {
					t.metrics.AddCounter(context.Background(), outbound.MetricHBONEBytesReceived, int64(n),
						model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: t.peerNode},
						model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
					)
				},
			}
		}
		_, _ = io.Copy(localConn, src)
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
	if t.metrics != nil {
		t.metrics.AddUpDownCounter(context.Background(), outbound.MetricHBONEStreamsActive, -1,
			model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: t.peerNode},
			model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
		)
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
	httpClient  *http.Client
	mu          sync.RWMutex
	tlsClients  map[string]*http.Client
	telemetryMu sync.RWMutex
	telemetry   outbound.TelemetryProvider
}

// SetTelemetry configures the TelemetryProvider used for HBONE tunnel, mTLS, and trace propagation.
func (c *Client) SetTelemetry(tp outbound.TelemetryProvider) {
	if c == nil {
		return
	}
	c.telemetryMu.Lock()
	defer c.telemetryMu.Unlock()
	c.telemetry = tp
}

func (c *Client) metricsRecorder() outbound.MetricRecorder {
	if c == nil {
		return nil
	}
	c.telemetryMu.RLock()
	tp := c.telemetry
	c.telemetryMu.RUnlock()
	if tp == nil {
		return nil
	}
	return tp.Metrics()
}

func (c *Client) traceRecorder() outbound.TraceRecorder {
	if c == nil {
		return nil
	}
	c.telemetryMu.RLock()
	tp := c.telemetry
	c.telemetryMu.RUnlock()
	if tp == nil {
		return nil
	}
	return tp.Tracer()
}

// NewClient constructs a new HBONE client supporting cleartext HTTP/2 (h2c) and mTLS.
func NewClient() *Client {
	protos := new(http.Protocols)
	protos.SetUnencryptedHTTP2(true)

	c := &Client{
		tlsClients: make(map[string]*http.Client),
	}

	transport := &http.Transport{
		Protocols:         protos,
		HTTP2:             &http.HTTP2Config{},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Mark proxy-originated sockets so Linux redirect rules skip them (no-op elsewhere).
			d := net.Dialer{Control: sockmark.Control(sockmark.ProxyMark)}
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return wrapTrackedTransportConn(conn, addr, "egress", c.metricsRecorder()), nil
		},
	}

	c.httpClient = &http.Client{
		Transport: transport,
	}
	return c
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

	protos := new(http.Protocols)
	protos.SetHTTP2(true)

	cfg := tlsConfig.Clone()
	t := &http.Transport{
		Protocols:       protos,
		HTTP2:           &http.HTTP2Config{},
		TLSClientConfig: cfg,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Control: sockmark.Control(sockmark.ProxyMark)}
			metrics := c.metricsRecorder()
			rawConn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				if metrics != nil {
					metrics.AddCounter(ctx, outbound.MetricMTLSHandshakesTotal, 1,
						model.MetricAttribute{Key: outbound.MetricAttrPeerService, Value: "unknown"},
						model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
						model.MetricAttribute{Key: outbound.MetricAttrResult, Value: "failure"},
					)
				}
				return nil, err
			}

			trackedConn := wrapTrackedTransportConn(rawConn, targetHost, "egress", metrics)
			tlsConn := tls.Client(trackedConn, cfg)

			start := time.Now()
			err = tlsConn.HandshakeContext(ctx)
			durMs := float64(time.Since(start).Nanoseconds()) / 1e6

			if metrics != nil {
				result := "success"
				peerSvc := "unknown"
				if err != nil {
					result = "failure"
				} else {
					peerSvc = extractPeerServiceFromState(tlsConn.ConnectionState())
				}
				metrics.AddCounter(ctx, outbound.MetricMTLSHandshakesTotal, 1,
					model.MetricAttribute{Key: outbound.MetricAttrPeerService, Value: peerSvc},
					model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
					model.MetricAttribute{Key: outbound.MetricAttrResult, Value: result},
				)
				metrics.RecordHistogram(ctx, outbound.MetricMTLSHandshakesDurationMs, durMs,
					model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
				)
			}
			if err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		ForceAttemptHTTP2: true,
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
	var cfg *tls.Config
	if len(tlsConfig) > 0 && tlsConfig[0] != nil {
		cfg = tlsConfig[0]
	}
	return c.OpenTunnelWithOptions(ctx, TunnelOptions{
		ConnectTimeout: connectTimeout,
		TargetHost:     targetHost,
		RealDest:       realDest,
		NodeServiceID:  nodeServiceID,
		Identity:       identity,
		TLSConfig:      cfg,
	})
}

// OpenTunnelWithOptions performs the HTTP/2 HBONE CONNECT handshake configured by opts.
func (c *Client) OpenTunnelWithOptions(ctx context.Context, opts TunnelOptions) (*Tunnel, error) {
	pr, pw := io.Pipe()

	httpClient, reqURL := c.getClient(opts.TargetHost, opts.TLSConfig)

	reqCtx, cancelReq := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, reqURL, pr)
	if err != nil {
		_ = pw.Close()
		cancelReq()
		return nil, fmt.Errorf("failed to create CONNECT request: %w", err)
	}

	req.Header.Set("Host", opts.TargetHost)
	req.Header.Set(HeaderRealDest, opts.RealDest)
	if opts.NodeServiceID != "" {
		req.Header.Set(HeaderNodeServiceID, opts.NodeServiceID)
	}
	if opts.SourceNodeID != "" {
		req.Header.Set(HeaderSourceNode, opts.SourceNodeID)
	}
	if opts.Identity != "" {
		req.Header.Set(HeaderCallerIdentity, opts.Identity)
		req.Header.Set(HeaderSourceIdentity, opts.Identity)
	}
	if tracer := c.traceRecorder(); tracer != nil {
		tracer.InjectContext(ctx, outbound.HTTPHeaderCarrier(req.Header))
	}

	metrics := c.metricsRecorder()
	peerNode := opts.DestNodeID
	if peerNode == "" {
		peerNode = opts.TargetHost
	}
	destSvc := opts.DestService
	if destSvc == "" {
		destSvc = opts.NodeServiceID
	}
	if destSvc == "" {
		destSvc = opts.RealDest
	}

	recordStreamResult := func(result string) {
		if metrics == nil {
			return
		}
		metrics.AddCounter(ctx, outbound.MetricHBONEStreamsTotal, 1,
			model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: peerNode},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
			model.MetricAttribute{Key: outbound.MetricAttrResult, Value: result},
		)
	}

	var handshakeMu sync.Mutex
	handshakeDone := false
	var timedOut atomic.Bool
	var timer *time.Timer
	if opts.ConnectTimeout > 0 {
		timer = time.AfterFunc(opts.ConnectTimeout, func() {
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
			recordStreamResult("timeout")
			return nil, fmt.Errorf("%w: %w", domain.ErrTunnelFailed, context.DeadlineExceeded)
		}
		recordStreamResult("error")
		return nil, fmt.Errorf("%w: %w", domain.ErrTunnelFailed, err)
	}

	if reqCtx.Err() != nil {
		_ = resp.Body.Close()
		_ = pw.Close()
		cancelReq()
		if timedOut.Load() && ctx.Err() == nil {
			recordStreamResult("timeout")
			return nil, fmt.Errorf("%w: %w", domain.ErrTunnelFailed, context.DeadlineExceeded)
		}
		recordStreamResult("error")
		return nil, fmt.Errorf("%w: %w", domain.ErrTunnelFailed, reqCtx.Err())
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		cancelReq()
		recordStreamResult(streamStatusResult(resp.StatusCode))
		return nil, &domain.TunnelStatusError{StatusCode: resp.StatusCode}
	}

	recordStreamResult("success")
	if metrics != nil {
		metrics.AddUpDownCounter(ctx, outbound.MetricHBONEStreamsActive, 1,
			model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: peerNode},
			model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
		)
	}

	log.Printf("HBONE tunnel established to %s (destination %s, nodeServiceID %q, identity %q)\n", opts.TargetHost, opts.RealDest, opts.NodeServiceID, opts.Identity)

	return &Tunnel{
		pw:         pw,
		body:       resp.Body,
		cancel:     cancelReq,
		targetHost: opts.TargetHost,
		peerNode:   peerNode,
		metrics:    metrics,
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

type trackedTransportConn struct {
	net.Conn
	metrics   outbound.MetricRecorder
	peerNode  string
	direction string
	closeOnce sync.Once
}

func wrapTrackedTransportConn(conn net.Conn, peerNode, direction string, metrics outbound.MetricRecorder) net.Conn {
	if conn == nil || metrics == nil {
		return conn
	}
	metrics.AddUpDownCounter(context.Background(), outbound.MetricHBONETunnelsActive, 1,
		model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: peerNode},
		model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: direction},
	)
	return &trackedTransportConn{
		Conn:      conn,
		metrics:   metrics,
		peerNode:  peerNode,
		direction: direction,
	}
}

func (c *trackedTransportConn) Close() error {
	c.closeOnce.Do(func() {
		if c.metrics != nil {
			c.metrics.AddUpDownCounter(context.Background(), outbound.MetricHBONETunnelsActive, -1,
				model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: c.peerNode},
				model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: c.direction},
			)
		}
	})
	return c.Conn.Close()
}

type countingReader struct {
	r      io.Reader
	onRead func(int)
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 && cr.onRead != nil {
		cr.onRead(n)
	}
	return n, err
}

type countingWriter struct {
	w       io.Writer
	onWrite func(int)
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 && cw.onWrite != nil {
		cw.onWrite(n)
	}
	return n, err
}

func extractPeerServiceFromState(cs tls.ConnectionState) string {
	for _, cert := range cs.PeerCertificates {
		for _, uri := range cert.URIs {
			if uri.Scheme == "spiffe" {
				svc, _ := model.ParseCallerService(uri.String())
				return svc
			}
		}
	}
	return "unknown"
}

func streamStatusResult(statusCode int) string {
	switch statusCode {
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusBadGateway:
		return "bad_gateway"
	default:
		return "error"
	}
}
