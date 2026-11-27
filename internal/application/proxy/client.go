package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

var _ inbound.ProxyService = (*ClientSideService)(nil)

// ClientSideService listens for intercepted traffic on 127.0.0.1:15001 and forwards it over HBONE tunnels.
type ClientSideService struct {
	listenAddr      string
	targetHost      string
	nodeID          string
	mu              sync.RWMutex
	packetProcessor outbound.PacketProcessor
	hboneClient     *hbone.Client
	router          *Router
	svidProvider    outbound.WorkloadSVIDProvider
	httpBridge      inbound.HTTPStreamBridge
	telemetry       outbound.TelemetryProvider
	defaultRetry    model.RetryConfig
}

// NewClientSideService constructs a new ClientSideService.
func NewClientSideService(
	listenAddr string,
	targetHost string,
	processor outbound.PacketProcessor,
) *ClientSideService {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:15001"
	}
	if targetHost == "" {
		targetHost = os.Getenv("TARGET_HBONE_HOST")
	}

	defaultRetry, _ := model.DefaultRoutingConfig().ToRetryConfig()

	return &ClientSideService{
		listenAddr:      listenAddr,
		targetHost:      targetHost,
		packetProcessor: processor,
		hboneClient:     hbone.NewClient(),
		defaultRetry:    defaultRetry,
	}
}

// SetRouter configures the dynamic route table provider.
func (s *ClientSideService) SetRouter(r *Router) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.router = r
}

// SetRoutingConfig updates the fallback data-plane routing/retry defaults.
func (s *ClientSideService) SetRoutingConfig(cfg model.RoutingConfig) error {
	parsed, err := cfg.ToRetryConfig()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultRetry = parsed
	return nil
}

// SetPacketProcessor updates the packet processor.
func (s *ClientSideService) SetPacketProcessor(p outbound.PacketProcessor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packetProcessor = p
}

// SetWorkloadSVIDProvider configures the provider that fetches SVIDs by calling process PID.
func (s *ClientSideService) SetWorkloadSVIDProvider(p outbound.WorkloadSVIDProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.svidProvider = p
}

// SetNodeID configures the local node ID attached to outbound HBONE/HTTP metadata.
func (s *ClientSideService) SetNodeID(nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeID = nodeID
}

// SetHTTPBridge configures an L7 HTTPStreamBridge for outbound HTTP/1.1 and HTTP/2 inspection.
func (s *ClientSideService) SetHTTPBridge(bridge inbound.HTTPStreamBridge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.httpBridge = bridge
}

// SetTelemetry configures the TelemetryProvider for outbound connections, retries, HBONE, and tracing.
func (s *ClientSideService) SetTelemetry(tp outbound.TelemetryProvider) {
	s.mu.Lock()
	s.telemetry = tp
	hc := s.hboneClient
	s.mu.Unlock()
	if hc != nil {
		hc.SetTelemetry(tp)
	}
}

// WorkloadSVIDProvider returns the active WorkloadSVIDProvider, or nil if none is configured.
func (s *ClientSideService) WorkloadSVIDProvider() outbound.WorkloadSVIDProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.svidProvider
}

// Start begins accepting local connections and tunneling them over HBONE.
func (s *ClientSideService) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind client-side listener on %s: %w", s.listenAddr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on the provided pre-opened listener.
func (s *ClientSideService) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()

	log.Printf("Proxy HBONE client listening on %s...\n", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("ClientSideService accept error: %v\n", err)
				continue
			}
		}

		go s.handleConnection(ctx, conn)
	}
}

func (s *ClientSideService) handleConnection(ctx context.Context, localConn net.Conn) {
	defer localConn.Close()

	peerAddr := localConn.RemoteAddr()
	var socketHandle uintptr

	// Extract raw socket handle for Windows WFP IOCTL lookup
	if sysConn, ok := localConn.(syscall.Conn); ok {
		if rawConn, err := sysConn.SyscallConn(); err == nil {
			_ = rawConn.Control(func(fd uintptr) {
				socketHandle = fd
			})
		}
	}

	s.mu.RLock()
	processor := s.packetProcessor
	router := s.router
	svidProv := s.svidProvider
	fallbackHost := s.targetHost
	defaultRetry := s.defaultRetry
	nodeID := s.nodeID
	httpBridge := s.httpBridge
	telemetry := s.telemetry
	s.mu.RUnlock()

	var identity string
	var clientTLS *tls.Config

	if processor == nil {
		log.Printf("No packet processor configured for caller %s; closing connection\n", peerAddr)
		return
	}

	pktInfo, err := processor.GetOriginalPacketInfo(peerAddr, socketHandle)
	if err != nil || pktInfo == nil {
		log.Printf("Could not retrieve original packet info for peer %s: %v\n", peerAddr, err)
		return
	}

	// Retrieve SVID using PID of calling process to impersonate the service via mTLS
	if svidProv != nil && pktInfo.PID != 0 {
		tlsCfg, spiffeID, err := svidProv.GetClientTLSConfigByPID(ctx, pktInfo.PID)
		if err != nil {
			log.Printf("Could not retrieve SVID for caller PID %d: %v\n", pktInfo.PID, err)
			return
		}
		clientTLS = tlsCfg
		identity = spiffeID
	} else {
		identity, _ = processor.GetIdentityByPID(pktInfo.PID)
	}

	if pktInfo.IP == 0 || router == nil {
		log.Printf("No IP information or router defined, closing connection")
		return
	}

	_ = s.tunnelWithRetries(ctx, localConn, router, pktInfo.IP, pktInfo.Port, fallbackHost, nodeID, identity, clientTLS, defaultRetry, httpBridge, telemetry)
}

func (s *ClientSideService) singleTunnel(
	ctx context.Context,
	localConn net.Conn,
	targetHost string,
	realDest string,
	nodeServiceID string,
	sourceNodeID string,
	identity string,
	clientTLS *tls.Config,
	connectTimeout time.Duration,
	httpBridge inbound.HTTPStreamBridge,
) {
	if connectTimeout <= 0 {
		connectTimeout = model.DefaultConnectTimeout
	}
	log.Printf(
		"Establishing HBONE tunnel to %s with identity %q for caller on port %s (destination: %s, nodeServiceID: %q, mTLS=%v)\n",
		targetHost,
		identity,
		localConn.RemoteAddr().String(),
		realDest,
		nodeServiceID,
		clientTLS != nil,
	)

	tunnel, err := s.hboneClient.OpenTunnelWithOptions(ctx, hbone.TunnelOptions{
		ConnectTimeout: connectTimeout,
		TargetHost:     targetHost,
		RealDest:       realDest,
		NodeServiceID:  nodeServiceID,
		SourceNodeID:   sourceNodeID,
		Identity:       identity,
		TLSConfig:      clientTLS,
	})
	if err != nil {
		log.Printf("Tunnel error: %v\n", err)
		if errors.Is(err, domain.ErrForbidden) {
			respondForbiddenOutbound(ctx, httpBridge, localConn, model.ConnectionMeta{
				Direction:      model.DirectionOutbound,
				SourceNodeID:   sourceNodeID,
				CallerIdentity: identity,
				CallerVerified: clientTLS != nil && identity != "",
				SourceAddr:     localConn.RemoteAddr().String(),
				DestAddr:       realDest,
				NodeServiceID:  nodeServiceID,
			})
		}
		return
	}
	if err := bridgeOutboundTunnel(ctx, httpBridge, tunnel, localConn, model.ConnectionMeta{
		Direction:      model.DirectionOutbound,
		SourceNodeID:   sourceNodeID,
		CallerIdentity: identity,
		CallerVerified: clientTLS != nil && identity != "",
		SourceAddr:     localConn.RemoteAddr().String(),
		DestAddr:       realDest,
		NodeServiceID:  nodeServiceID,
	}); err != nil {
		log.Printf("Tunnel bridge error: %v\n", err)
	}
}

func (s *ClientSideService) tunnelWithRetries(
	ctx context.Context,
	localConn net.Conn,
	router *Router,
	destIP uint32,
	destPort uint16,
	fallbackHost string,
	sourceNodeID string,
	identity string,
	clientTLS *tls.Config,
	defaultRetry model.RetryConfig,
	httpBridge inbound.HTTPStreamBridge,
	telemetry outbound.TelemetryProvider,
) error {
	var metrics outbound.MetricRecorder
	var tracer outbound.TraceRecorder
	if telemetry != nil {
		metrics = telemetry.Metrics()
		tracer = telemetry.Tracer()
	}

	connStart := time.Now()
	srcSvc, srcNS := model.ParseCallerService(identity)

	var activeTracked bool
	var activeSvc, activeNS string
	defer func() {
		if activeTracked && metrics != nil {
			metrics.AddUpDownCounter(context.Background(), outbound.MetricConnectionsActive, -1,
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: activeSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: activeNS},
			)
		}
	}()

	recordConnOutcome := func(destSvc, destNS, result string) {
		if metrics == nil {
			return
		}
		metrics.AddCounter(context.Background(), outbound.MetricConnectionsTotal, 1,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
			model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "egress"},
			model.MetricAttribute{Key: outbound.MetricAttrResult, Value: result},
		)
		metrics.RecordHistogram(context.Background(), outbound.MetricConnectionsDurationMs,
			float64(time.Since(connStart).Nanoseconds())/1e6,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
		)
	}

	var excludedBuf [8]model.EndpointKey
	excluded := excludedBuf[:0]
	var lastErr error
	lastDestSvc := "unknown"
	lastDestNS := "unknown"
	attempt := 0

	for {
		resolved, retryCfg, err := router.ResolveRouteIPv4(destIP, destPort, fallbackHost, excluded)
		if err != nil {
			if attempt == 0 {
				log.Printf("No route available for %s (caller port %s): %v\n",
					formatIPv4Port(destIP, destPort), localConn.RemoteAddr().String(), err)
				recordConnOutcome("unknown", "unknown", "no_route")
				return err
			}
			if metrics != nil {
				metrics.AddCounter(ctx, outbound.MetricRetriesExhausted, 1,
					model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: lastDestSvc},
				)
			}
			recordConnOutcome(lastDestSvc, lastDestNS, "error")
			wrapped := fmt.Errorf("%w after %d attempt(s) (tried=%v): %w",
				domain.ErrRetriesExhausted, attempt, excluded, lastErr)
			log.Printf("Routing retries exhausted for %s: %v\n",
				formatIPv4Port(destIP, destPort), wrapped)
			return wrapped
		}

		destSvc := formatServiceAttr(resolved.Namespace, resolved.ServiceName)
		destNS := resolved.Namespace
		if destNS == "" {
			destNS = "unknown"
		}
		lastDestSvc = destSvc
		lastDestNS = destNS

		if !activeTracked && metrics != nil {
			activeTracked = true
			activeSvc = destSvc
			activeNS = destNS
			metrics.AddUpDownCounter(ctx, outbound.MetricConnectionsActive, 1,
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: activeSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: activeNS},
			)
		}

		connectTimeout := retryCfg.ConnectTimeout
		if connectTimeout <= 0 {
			connectTimeout = defaultRetry.ConnectTimeout
			if connectTimeout <= 0 {
				connectTimeout = model.DefaultConnectTimeout
			}
		}

		release := router.AcquireEndpoint(resolved.EndpointKey)

		spanCtx := ctx
		var span outbound.SpanHandle = outbound.NoopSpanHandle{}
		if tracer != nil {
			protoLabel := strings.ToLower(strings.TrimSpace(resolved.Protocol))
			if protoLabel == "" {
				protoLabel = "tcp"
			}
			destName := resolved.ServiceName
			if destName == "" {
				destName = destSvc
			}
			spanCtx, span = tracer.StartSpan(ctx, outbound.SpanNameEgress, model.SpanKindClient,
				model.MetricAttribute{Key: outbound.AttrDirection, Value: "egress"},
				model.MetricAttribute{Key: outbound.AttrNode, Value: sourceNodeID},
				model.MetricAttribute{Key: outbound.AttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.AttrSourceNamespace, Value: srcNS},
				model.MetricAttribute{Key: outbound.AttrDestinationService, Value: destName},
				model.MetricAttribute{Key: outbound.AttrDestinationNamespace, Value: destNS},
				model.MetricAttribute{Key: outbound.AttrDestinationEndpoint, Value: resolved.RealDest},
				model.MetricAttribute{Key: outbound.AttrProtocol, Value: protoLabel},
				model.MetricAttribute{Key: outbound.AttrRetryAttempt, Value: strconv.Itoa(attempt)},
			)
		}

		log.Printf(
			"Establishing HBONE tunnel to %s with identity %q for caller on port %s (destination: %s, nodeServiceID: %q, attempt=%d, mTLS=%v)\n",
			resolved.TargetHost,
			identity,
			localConn.RemoteAddr().String(),
			resolved.RealDest,
			resolved.ServiceID,
			attempt+1,
			clientTLS != nil,
		)

		tunnel, err := s.hboneClient.OpenTunnelWithOptions(spanCtx, hbone.TunnelOptions{
			ConnectTimeout: connectTimeout,
			TargetHost:     resolved.TargetHost,
			RealDest:       resolved.RealDest,
			NodeServiceID:  resolved.ServiceID,
			SourceNodeID:   sourceNodeID,
			DestService:    destSvc,
			DestNodeID:     resolved.NodeID,
			Identity:       identity,
			TLSConfig:      clientTLS,
		})
		if err == nil {
			defer release()
			if attempt > 0 && metrics != nil {
				metrics.AddCounter(spanCtx, outbound.MetricRetriesSuccess, 1,
					model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
				)
			}
			meta := model.ConnectionMeta{
				Direction:       model.DirectionOutbound,
				ConfiguredProto: model.NormalizeProtocol(resolved.Protocol),
				RawProtocol:     resolved.Protocol,
				SourceNodeID:    sourceNodeID,
				DestNodeID:      resolved.NodeID,
				CallerIdentity:  identity,
				CallerVerified:  clientTLS != nil && identity != "",
				SourceAddr:      localConn.RemoteAddr().String(),
				DestAddr:        resolved.RealDest,
				Namespace:       resolved.Namespace,
				ServiceName:     resolved.ServiceName,
				NodeServiceID:   resolved.ServiceID,
			}

			var bridgeConn net.Conn = localConn
			var l4Counter *countingNetConn
			if httpBridge == nil && metrics != nil {
				l4Counter = &countingNetConn{Conn: localConn}
				bridgeConn = l4Counter
				metrics.AddUpDownCounter(spanCtx, outbound.MetricRequestsActive, 1,
					model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
					model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
				)
			}
			l4Start := time.Now()
			bridgeErr := bridgeOutboundTunnel(spanCtx, httpBridge, tunnel, bridgeConn, meta)
			if l4Counter != nil && metrics != nil {
				metrics.AddUpDownCounter(context.Background(), outbound.MetricRequestsActive, -1,
					model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
					model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
				)
				respCode := "ok"
				if bridgeErr != nil {
					respCode = "error"
				}
				durMs := float64(time.Since(l4Start).Nanoseconds()) / 1e6
				if metrics.CombinedRequestMetricEnabled() {
					metrics.AddCounter(context.Background(), outbound.MetricRequestsTotal, 1,
						model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
						model.MetricAttribute{Key: outbound.MetricAttrSourceNamespace, Value: srcNS},
						model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
						model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
						model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "tcp"},
						model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: respCode},
					)
				}
				metrics.AddCounter(context.Background(), outbound.MetricRequestsEgressTotal, 1,
					model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
					model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
					model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "tcp"},
					model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: respCode},
				)
				metrics.RecordHistogram(context.Background(), outbound.MetricRequestsDurationMs, durMs,
					model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
					model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
					model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "tcp"},
				)
				if sent := l4Counter.bytesRead.Load(); sent > 0 {
					metrics.AddCounter(context.Background(), outbound.MetricRequestsBytesSent, sent,
						model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
						model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
					)
				}
				if recvd := l4Counter.bytesWritten.Load(); recvd > 0 {
					metrics.AddCounter(context.Background(), outbound.MetricRequestsBytesReceived, recvd,
						model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
						model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
					)
				}
			}

			if bridgeErr != nil {
				log.Printf("Tunnel bridge error: %v\n", bridgeErr)
				span.SetError(bridgeErr, bridgeErr.Error())
				span.End()
				recordConnOutcome(destSvc, destNS, "error")
				return bridgeErr
			}
			span.End()
			recordConnOutcome(destSvc, destNS, "success")
			return nil
		}

		release()
		lastErr = err

		var statusErr *domain.TunnelStatusError
		if errors.As(err, &statusErr) {
			span.SetAttributes(model.MetricAttribute{Key: outbound.AttrHTTPStatusCode, Value: strconv.Itoa(statusErr.StatusCode)})
		}
		span.SetError(err, err.Error())
		span.End()

		if !isRetryableRouteError(ctx, err, retryCfg) {
			log.Printf("Non-retryable HBONE tunnel error to %s (destination %s, nodeServiceID %q): %v\n",
				resolved.TargetHost, resolved.RealDest, resolved.ServiceID, err)
			outcome := "error"
			if errors.Is(err, domain.ErrForbidden) {
				outcome = "forbidden"
				respondForbiddenOutbound(ctx, httpBridge, localConn, model.ConnectionMeta{
					Direction:       model.DirectionOutbound,
					ConfiguredProto: model.NormalizeProtocol(resolved.Protocol),
					RawProtocol:     resolved.Protocol,
					SourceNodeID:    sourceNodeID,
					DestNodeID:      resolved.NodeID,
					CallerIdentity:  identity,
					CallerVerified:  clientTLS != nil && identity != "",
					SourceAddr:      localConn.RemoteAddr().String(),
					DestAddr:        resolved.RealDest,
					Namespace:       resolved.Namespace,
					ServiceName:     resolved.ServiceName,
					NodeServiceID:   resolved.ServiceID,
				})
			}
			recordConnOutcome(destSvc, destNS, outcome)
			return err
		}

		// Peer 502 (and configured connect failures) indicates a wrong/stale routing choice
		// for this connection. Never mark the endpoint unhealthy; exclude only for this
		// connection and retry another candidate.
		log.Printf("HBONE routing attempt %d failed for %s/%s endpoint %+v (%s): %v; selecting another endpoint\n",
			attempt+1, resolved.Namespace, resolved.ServiceName, resolved.EndpointKey, resolved.TargetHost, err)
		excluded = append(excluded, resolved.EndpointKey)

		if attempt >= retryCfg.MaxRetries {
			if metrics != nil {
				metrics.AddCounter(ctx, outbound.MetricRetriesExhausted, 1,
					model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
				)
			}
			recordConnOutcome(destSvc, destNS, "error")
			wrapped := fmt.Errorf("%w for %s/%s after %d attempt(s) (tried=%v): %w",
				domain.ErrRetriesExhausted, resolved.Namespace, resolved.ServiceName, attempt+1, excluded, err)
			log.Printf("Routing retries exhausted: %v\n", wrapped)
			return wrapped
		}

		if metrics != nil {
			metrics.AddCounter(ctx, outbound.MetricRetriesTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
				model.MetricAttribute{Key: outbound.MetricAttrRetryReason, Value: classifyRetryReason(err)},
			)
		}

		attempt++
		if retryCfg.BackoffBase > 0 && router.HasAvailableEndpointIPv4(destIP, excluded) {
			delay := computeRetryBackoff(retryCfg.BackoffBase, retryCfg.BackoffMax, attempt)
			if !sleepWithContext(ctx, delay) {
				recordConnOutcome(destSvc, destNS, "error")
				return ctx.Err()
			}
		}
	}
}

func bridgeOutboundTunnel(
	ctx context.Context,
	httpBridge inbound.HTTPStreamBridge,
	tunnel *hbone.Tunnel,
	localConn net.Conn,
	meta model.ConnectionMeta,
) error {
	if httpBridge != nil {
		defer tunnel.Close()
		return httpBridge.Bridge(ctx, localConn, tunnel.Conn(), meta)
	}
	return tunnel.Bridge(localConn)
}

func respondForbiddenOutbound(
	ctx context.Context,
	httpBridge inbound.HTTPStreamBridge,
	localConn net.Conn,
	meta model.ConnectionMeta,
) {
	if httpBridge == nil || localConn == nil {
		return
	}
	if responder, ok := httpBridge.(inbound.HTTPForbiddenResponder); ok {
		_ = responder.RespondForbidden(ctx, localConn, meta)
	}
}

func isRetryableRouteError(ctx context.Context, err error, cfg model.RetryConfig) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	var statusErr *domain.TunnelStatusError
	if errors.As(err, &statusErr) {
		if statusErr.StatusCode == http.StatusBadGateway {
			return true
		}
		if cfg.RetryOn5xx && statusErr.StatusCode >= 500 && statusErr.StatusCode <= 599 {
			return true
		}
		return false
	}
	if cfg.RetryOnConnectFail && errors.Is(err, domain.ErrTunnelFailed) {
		return true
	}
	return false
}

func computeRetryBackoff(base, maxDur time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	if maxDur < base {
		maxDur = base
	}
	delay := base
	for i := 1; i < attempt; i++ {
		if delay >= maxDur {
			delay = maxDur
			break
		}
		if delay > maxDur/2 {
			delay = maxDur
			break
		}
		delay *= 2
	}
	if delay <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(delay) + 1))
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func classifyRetryReason(err error) string {
	var statusErr *domain.TunnelStatusError
	if errors.As(err, &statusErr) {
		if statusErr.StatusCode == http.StatusBadGateway {
			return "502_bad_gateway"
		}
		if statusErr.StatusCode >= 500 && statusErr.StatusCode <= 599 {
			return "5xx"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "connection_failure"
}

type countingNetConn struct {
	net.Conn
	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
}

func (c *countingNetConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.bytesRead.Add(int64(n))
	}
	return n, err
}

func (c *countingNetConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.bytesWritten.Add(int64(n))
	}
	return n, err
}

func (c *countingNetConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
