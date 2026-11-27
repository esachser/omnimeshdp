package hbone

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/sockmark"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

// Server implements an HTTP/2 HBONE (CONNECT) tunnel server.
type Server struct {
	addr         string
	httpServer   *http.Server
	listener     net.Listener
	tlsConfig    *tls.Config
	svcMu        sync.RWMutex
	services     map[string]model.NodeServiceInfo // keyed by NodeServiceInfo.Key()
	servicesByID map[string]model.NodeServiceInfo // serviceID -> NodeServiceInfo
	cfgMu        sync.RWMutex
	nodeID       string
	httpBridge   inbound.HTTPStreamBridge
	authorizer   inbound.Authorizer
	telemetry    outbound.TelemetryProvider

	pendingTLS    sync.Map // net.Conn -> time.Time
	activeTunnels sync.Map // net.Conn -> string (peer_node)
}

// NewServer creates a new HBONE server listening on the specified address.
// If tlsConfig is provided, the server enforces HTTP/2 over TLS with mTLS.
func NewServer(addr string, tlsConfig ...*tls.Config) *Server {
	s := &Server{
		addr:         addr,
		services:     make(map[string]model.NodeServiceInfo),
		servicesByID: make(map[string]model.NodeServiceInfo),
	}
	if len(tlsConfig) > 0 && tlsConfig[0] != nil {
		s.tlsConfig = tlsConfig[0].Clone()
	}

	s.httpServer = &http.Server{
		Addr:        addr,
		Handler:     s,
		IdleTimeout: 120 * time.Second,
		HTTP2:       &http.HTTP2Config{},
		Protocols:   serverProtocols(s.tlsConfig != nil),
		TLSConfig:   s.tlsConfig,
		ConnState:   s.onConnState,
	}

	return s
}

// SetTelemetry configures the TelemetryProvider used for inbound HBONE metrics, mTLS metrics, and tracing.
func (s *Server) SetTelemetry(tp outbound.TelemetryProvider) {
	if s == nil {
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.telemetry = tp
}

func (s *Server) telemetryRecorders() (outbound.MetricRecorder, outbound.TraceRecorder) {
	if s == nil {
		return nil, nil
	}
	s.cfgMu.RLock()
	tp := s.telemetry
	s.cfgMu.RUnlock()
	if tp == nil {
		return nil, nil
	}
	return tp.Metrics(), tp.Tracer()
}

func (s *Server) onConnState(conn net.Conn, state http.ConnState) {
	metrics, _ := s.telemetryRecorders()
	switch state {
	case http.StateNew:
		if metrics != nil {
			peerHost := hostOnly(conn.RemoteAddr().String())
			if peerHost == "" {
				peerHost = "unknown"
			}
			s.activeTunnels.Store(conn, peerHost)
			metrics.AddUpDownCounter(context.Background(), outbound.MetricHBONETunnelsActive, 1,
				model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: peerHost},
				model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
			)
		}
	case http.StateClosed, http.StateHijacked:
		pendingKey := conn
		if tc, ok := conn.(*tls.Conn); ok {
			pendingKey = tc.NetConn()
		}
		if startRaw, ok := s.pendingTLS.LoadAndDelete(pendingKey); ok && metrics != nil {
			if start, ok := startRaw.(time.Time); ok {
				durMs := float64(time.Since(start).Nanoseconds()) / 1e6
				metrics.AddCounter(context.Background(), outbound.MetricMTLSHandshakesTotal, 1,
					model.MetricAttribute{Key: outbound.MetricAttrPeerService, Value: "unknown"},
					model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
					model.MetricAttribute{Key: outbound.MetricAttrResult, Value: "failure"},
				)
				metrics.RecordHistogram(context.Background(), outbound.MetricMTLSHandshakesDurationMs, durMs,
					model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
				)
			}
		}
		if peerRaw, ok := s.activeTunnels.LoadAndDelete(conn); ok && metrics != nil {
			peerHost, _ := peerRaw.(string)
			metrics.AddUpDownCounter(context.Background(), outbound.MetricHBONETunnelsActive, -1,
				model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: peerHost},
				model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
			)
		}
	}
}

func serverProtocols(useTLS bool) *http.Protocols {
	protos := new(http.Protocols)
	if useTLS {
		protos.SetHTTP2(true)
	} else {
		protos.SetUnencryptedHTTP2(true)
	}
	return protos
}

// SetServices replaces the locally registered services used to resolve x-omnimesh-service-id.
func (s *Server) SetServices(services []model.NodeServiceInfo) {
	s.svcMu.Lock()
	defer s.svcMu.Unlock()

	s.services = make(map[string]model.NodeServiceInfo, len(services))
	for _, svc := range services {
		s.services[svc.Key()] = svc
	}
	s.rebuildServiceIndexLocked()
}

// UpdateServices incrementally adds/updates and removes locally registered services.
func (s *Server) UpdateServices(added, removed []model.NodeServiceInfo) {
	s.svcMu.Lock()
	defer s.svcMu.Unlock()

	if s.services == nil {
		s.services = make(map[string]model.NodeServiceInfo)
	}
	for _, rem := range removed {
		delete(s.services, rem.Key())
	}
	for _, add := range added {
		s.services[add.Key()] = add
	}
	s.rebuildServiceIndexLocked()
}

func (s *Server) rebuildServiceIndexLocked() {
	idx := make(map[string]model.NodeServiceInfo, len(s.services)*2)
	for _, svc := range s.services {
		addr := svc.Address()
		if addr == "" {
			continue
		}
		if svc.ID != "" {
			idx[svc.ID] = svc
		}
		idx[svc.Key()] = svc
		if svc.Name != "" {
			if _, exists := idx[svc.Name]; !exists {
				idx[svc.Name] = svc
			}
		}
	}
	s.servicesByID = idx
}

// ResolveService looks up the locally registered NodeServiceInfo for a given service ID.
func (s *Server) ResolveService(serviceID string) (model.NodeServiceInfo, bool) {
	if serviceID == "" {
		return model.NodeServiceInfo{}, false
	}
	s.svcMu.RLock()
	defer s.svcMu.RUnlock()
	svc, ok := s.servicesByID[serviceID]
	return svc, ok
}

// ResolveServiceAddr looks up the local "host:port" address for a given service ID.
func (s *Server) ResolveServiceAddr(serviceID string) (string, bool) {
	svc, ok := s.ResolveService(serviceID)
	if !ok {
		return "", false
	}
	addr := svc.Address()
	return addr, addr != ""
}

// SetNodeID configures the local node ID attached to inbound HTTP ConnectionMeta.
func (s *Server) SetNodeID(nodeID string) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.nodeID = nodeID
}

// SetHTTPBridge configures an L7 HTTPStreamBridge for inbound HTTP/1.1 and HTTP/2 inspection.
func (s *Server) SetHTTPBridge(bridge inbound.HTTPStreamBridge) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.httpBridge = bridge
}

// SetAuthorizer configures an inbound Authorizer evaluated at L4 connection establishment.
func (s *Server) SetAuthorizer(authorizer inbound.Authorizer) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.authorizer = authorizer
}

// SetTLSConfig updates the server's mTLS configuration.
func (s *Server) SetTLSConfig(tlsConfig *tls.Config) {
	if tlsConfig != nil {
		s.tlsConfig = tlsConfig.Clone()
	} else {
		s.tlsConfig = nil
	}
	if s.httpServer != nil {
		s.httpServer.TLSConfig = s.tlsConfig
		s.httpServer.Protocols = serverProtocols(s.tlsConfig != nil)
	}
}

// Start binds to the listener and serves HTTP/2 HBONE connections.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve serves HTTP/2 HBONE connections on the provided pre-opened listener.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.listener = ln

	if s.tlsConfig != nil {
		if !slices.Contains(s.tlsConfig.NextProtos, "h2") {
			s.tlsConfig.NextProtos = append([]string{"h2"}, s.tlsConfig.NextProtos...)
		}
		instrumentedTLS := s.wrapTLSConfigForMetrics(s.tlsConfig)
		s.httpServer.TLSConfig = instrumentedTLS
		s.httpServer.Protocols = serverProtocols(true)
		ln = tls.NewListener(ln, instrumentedTLS)
	}

	log.Printf("Proxy HBONE server running on %s (tls=%v)...\n", ln.Addr().String(), s.tlsConfig != nil)

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) wrapTLSConfigForMetrics(base *tls.Config) *tls.Config {
	cloned := base.Clone()
	origGetConfig := cloned.GetConfigForClient
	origVerify := cloned.VerifyConnection

	recordVerify := func(conn net.Conn, start time.Time, hasStart bool, cs tls.ConnectionState) error {
		var err error
		if origVerify != nil {
			err = origVerify(cs)
		}
		if conn != nil {
			if prev, ok := s.pendingTLS.LoadAndDelete(conn); ok && !hasStart {
				if t, ok := prev.(time.Time); ok {
					start = t
					hasStart = true
				}
			}
		}
		if metrics, _ := s.telemetryRecorders(); metrics != nil {
			var durMs float64
			if hasStart {
				durMs = float64(time.Since(start).Nanoseconds()) / 1e6
			}
			result := "success"
			if err != nil {
				result = "failure"
			}
			peerSvc := extractPeerServiceFromState(cs)
			metrics.AddCounter(context.Background(), outbound.MetricMTLSHandshakesTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrPeerService, Value: peerSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
				model.MetricAttribute{Key: outbound.MetricAttrResult, Value: result},
			)
			metrics.RecordHistogram(context.Background(), outbound.MetricMTLSHandshakesDurationMs, durMs,
				model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
			)
		}
		return err
	}

	cloned.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		start := time.Now()
		var conn net.Conn
		if hello != nil {
			conn = hello.Conn
			if conn != nil {
				s.pendingTLS.Store(conn, start)
			}
		}

		targetCfg := cloned
		if origGetConfig != nil {
			customCfg, err := origGetConfig(hello)
			if err != nil {
				return nil, err
			}
			if customCfg != nil {
				targetCfg = customCfg
			}
		}

		perConn := targetCfg.Clone()
		perConn.GetConfigForClient = nil
		customVerify := targetCfg.VerifyConnection
		perConn.VerifyConnection = func(cs tls.ConnectionState) error {
			if customVerify != nil && origGetConfig != nil {
				var err error
				err = customVerify(cs)
				if conn != nil {
					s.pendingTLS.Delete(conn)
				}
				if metrics, _ := s.telemetryRecorders(); metrics != nil {
					result := "success"
					if err != nil {
						result = "failure"
					}
					peerSvc := extractPeerServiceFromState(cs)
					metrics.AddCounter(context.Background(), outbound.MetricMTLSHandshakesTotal, 1,
						model.MetricAttribute{Key: outbound.MetricAttrPeerService, Value: peerSvc},
						model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
						model.MetricAttribute{Key: outbound.MetricAttrResult, Value: result},
					)
					metrics.RecordHistogram(context.Background(), outbound.MetricMTLSHandshakesDurationMs,
						float64(time.Since(start).Nanoseconds())/1e6,
						model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
					)
				}
				return err
			}
			return recordVerify(conn, start, true, cs)
		}
		return perConn, nil
	}

	cloned.VerifyConnection = func(cs tls.ConnectionState) error {
		return recordVerify(nil, time.Time{}, false, cs)
	}

	return cloned
}

// ServeHTTP handles incoming HTTP/2 requests, expecting CONNECT with x-omnimesh-service-id or x-omnimesh-real-dest.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	metrics, tracer := s.telemetryRecorders()
	connStart := time.Now()

	if r.Method != http.MethodConnect {
		if metrics != nil {
			metrics.AddCounter(r.Context(), outbound.MetricHBONEStreamsTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: "unknown"},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: "unknown"},
				model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
				model.MetricAttribute{Key: outbound.MetricAttrResult, Value: "error"},
			)
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	nodeServiceID := r.Header.Get(HeaderNodeServiceID)
	realDest := r.Header.Get(HeaderRealDest)
	sourceNodeID := r.Header.Get(HeaderSourceNode)

	destAddr := realDest
	var resolvedSvc model.NodeServiceInfo
	if nodeServiceID != "" {
		if svc, ok := s.ResolveService(nodeServiceID); ok {
			if resolvedAddr := svc.Address(); resolvedAddr != "" {
				destAddr = resolvedAddr
				resolvedSvc = svc
			}
		}
	}

	if destAddr == "" {
		if metrics != nil {
			metrics.AddCounter(r.Context(), outbound.MetricHBONEStreamsTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: defaultStr(sourceNodeID, "unknown")},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: defaultStr(nodeServiceID, "unknown")},
				model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
				model.MetricAttribute{Key: outbound.MetricAttrResult, Value: "error"},
			)
		}
		http.Error(w, "Missing x-omnimesh-real-dest or resolvable x-omnimesh-node-service-id header", http.StatusBadRequest)
		return
	}

	var callerIdentity string
	callerVerified := false
	if r.TLS != nil {
		for _, peerCert := range r.TLS.PeerCertificates {
			for _, uri := range peerCert.URIs {
				if uri.Scheme == "spiffe" {
					callerIdentity = uri.String()
					callerVerified = callerIdentity != ""
					break
				}
			}
			if callerIdentity != "" {
				break
			}
		}
		if callerIdentity == "" && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.PeerCertificates[0].URIs) > 0 {
			callerIdentity = r.TLS.PeerCertificates[0].URIs[0].String()
			callerVerified = callerIdentity != ""
		}
	} else {
		callerIdentity = r.Header.Get(HeaderCallerIdentity)
		if callerIdentity == "" {
			callerIdentity = r.Header.Get(HeaderSourceIdentity)
		}
	}
	if callerIdentity != "" {
		log.Printf("Proxy HBONE server accepted connection for %s (nodeServiceID=%q, realDest=%q) from caller %s\n",
			destAddr, nodeServiceID, realDest, callerIdentity)
	}

	s.cfgMu.RLock()
	httpBridge := s.httpBridge
	nodeID := s.nodeID
	authorizer := s.authorizer
	s.cfgMu.RUnlock()

	destMeshIP, destPort := parseHostPort(realDest)
	if destPort == 0 && resolvedSvc.Port > 0 {
		destPort = resolvedSvc.Port
	}
	if destPort == 0 {
		_, destPort = parseHostPort(destAddr)
	}

	inboundL7Available := false
	if l7Checker, ok := httpBridge.(interface{ InboundL7Enabled() bool }); ok {
		inboundL7Available = l7Checker.InboundL7Enabled()
	} else if httpBridge != nil {
		inboundL7Available = true
	}

	peerNode := sourceNodeID
	if peerNode == "" {
		peerNode = defaultStr(hostOnly(r.RemoteAddr), "unknown")
	}
	srcSvc, srcNS := model.ParseCallerService(callerIdentity)
	resolvedNS := resolvedSvc.Namespace
	resolvedName := resolvedSvc.Name
	resolvedProto := resolvedSvc.Protocol

	destSvcLabel := formatServiceLabel(resolvedNS, resolvedName, nodeServiceID, destAddr)
	destNSLabel := defaultStr(resolvedNS, "unknown")

	reqCtx := r.Context()
	if tracer != nil {
		reqCtx = tracer.ExtractContext(reqCtx, outbound.HTTPHeaderCarrier(r.Header))
	}

	var span outbound.SpanHandle = outbound.NoopSpanHandle{}
	if tracer != nil {
		spanAttrs := []model.MetricAttribute{
			{Key: outbound.AttrDirection, Value: "ingress"},
			{Key: outbound.AttrNode, Value: nodeID},
			{Key: outbound.AttrSourceService, Value: srcSvc},
			{Key: outbound.AttrSourceNamespace, Value: srcNS},
			{Key: outbound.AttrDestinationService, Value: defaultStr(resolvedName, destSvcLabel)},
			{Key: outbound.AttrDestinationNamespace, Value: destNSLabel},
			{Key: outbound.AttrDestinationEndpoint, Value: destAddr},
			{Key: outbound.AttrProtocol, Value: defaultStr(strings.ToLower(strings.TrimSpace(resolvedProto)), "tcp")},
		}
		reqCtx, span = tracer.StartSpan(reqCtx, outbound.SpanNameIngress, model.SpanKindServer, spanAttrs...)
	}

	if metrics != nil {
		metrics.AddUpDownCounter(reqCtx, outbound.MetricHBONEStreamsActive, 1,
			model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: peerNode},
			model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
		)
		defer metrics.AddUpDownCounter(context.Background(), outbound.MetricHBONEStreamsActive, -1,
			model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: peerNode},
			model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
		)
		metrics.AddUpDownCounter(reqCtx, outbound.MetricConnectionsActive, 1,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNSLabel},
		)
		defer metrics.AddUpDownCounter(context.Background(), outbound.MetricConnectionsActive, -1,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNSLabel},
		)
	}

	recordOutcome := func(result string) {
		if metrics == nil {
			return
		}
		metrics.AddCounter(context.Background(), outbound.MetricHBONEStreamsTotal, 1,
			model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: peerNode},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
			model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
			model.MetricAttribute{Key: outbound.MetricAttrResult, Value: result},
		)
		metrics.AddCounter(context.Background(), outbound.MetricConnectionsTotal, 1,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNSLabel},
			model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
			model.MetricAttribute{Key: outbound.MetricAttrResult, Value: result},
		)
		metrics.RecordHistogram(context.Background(), outbound.MetricConnectionsDurationMs,
			float64(time.Since(connStart).Nanoseconds())/1e6,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
		)
	}

	authzRequiresL7 := false
	if authorizer != nil {
		decision := authorizer.AuthorizeConnection(reqCtx, model.AuthzRequest{
			Layer:              model.AuthzLayerL4,
			CallerIdentity:     callerIdentity,
			CallerVerified:     callerVerified,
			SourceNodeID:       sourceNodeID,
			SourceAddr:         r.RemoteAddr,
			DestNamespace:      resolvedSvc.Namespace,
			DestServiceName:    resolvedSvc.Name,
			DestNodeServiceID:  nodeServiceID,
			DestMeshIP:         destMeshIP,
			DestPort:           destPort,
			DestProtocol:       resolvedSvc.Protocol,
			DestLabels:         resolvedSvc.Labels,
			InboundL7Available: inboundL7Available,
		})
		if !decision.Allowed {
			recordOutcome("forbidden")
			span.SetAttributes(model.MetricAttribute{Key: outbound.AttrHTTPStatusCode, Value: "403"})
			span.SetError(nil, "forbidden by authorization policy")
			span.End()
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		authzRequiresL7 = decision.RequiresL7
		if resolvedNS == "" {
			resolvedNS = decision.ResolvedDestNamespace
		}
		if resolvedName == "" {
			resolvedName = decision.ResolvedDestServiceName
		}
		if resolvedProto == "" {
			resolvedProto = decision.ResolvedProtocol
		}
		if resolvedName != "" {
			destSvcLabel = formatServiceLabel(resolvedNS, resolvedName, nodeServiceID, destAddr)
			destNSLabel = defaultStr(resolvedNS, "unknown")
			span.SetAttributes(
				model.MetricAttribute{Key: outbound.AttrDestinationService, Value: resolvedName},
				model.MetricAttribute{Key: outbound.AttrDestinationNamespace, Value: destNSLabel},
			)
		}
	}

	// Dial target real destination. The socket is marked so Linux redirect rules
	// don't send it back into the proxy (no-op on other platforms).
	dialer := net.Dialer{Timeout: 5 * time.Second, Control: sockmark.Control(sockmark.ProxyMark)}
	targetConn, err := dialer.Dial("tcp", destAddr)
	if err != nil {
		log.Printf("Failed to connect to destination at %s (nodeServiceID=%q): %v\n", destAddr, nodeServiceID, err)
		recordOutcome("bad_gateway")
		span.SetAttributes(model.MetricAttribute{Key: outbound.AttrHTTPStatusCode, Value: "502"})
		span.SetError(err, "failed to dial local service")
		span.End()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	w.WriteHeader(http.StatusOK)
	flusher, hasFlusher := w.(http.Flusher)
	if hasFlusher {
		flusher.Flush()
	}

	var trackedBody io.ReadCloser = r.Body
	var trackedWriter io.Writer = w
	if metrics != nil {
		trackedBody = &trackedReadCloser{
			rc: r.Body,
			onRead: func(n int) {
				metrics.AddCounter(context.Background(), outbound.MetricHBONEBytesReceived, int64(n),
					model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: peerNode},
					model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
				)
			},
		}
		trackedWriter = &countingWriter{
			w: w,
			onWrite: func(n int) {
				metrics.AddCounter(context.Background(), outbound.MetricHBONEBytesSent, int64(n),
					model.MetricAttribute{Key: outbound.MetricAttrPeerNode, Value: peerNode},
					model.MetricAttribute{Key: outbound.MetricAttrDirection, Value: "ingress"},
				)
			},
		}
	}

	if httpBridge != nil {
		var localAddr net.Addr
		if s.listener != nil {
			localAddr = s.listener.Addr()
		}
		hboneConn := newHBONEStreamConn(trackedBody, trackedWriter, flusher, r.RemoteAddr, localAddr)
		defer hboneConn.Close()

		svcID := resolvedSvc.ID
		if svcID == "" {
			svcID = nodeServiceID
		}
		meta := model.ConnectionMeta{
			Direction:       model.DirectionInbound,
			ConfiguredProto: model.NormalizeProtocol(resolvedProto),
			RawProtocol:     resolvedProto,
			SourceNodeID:    sourceNodeID,
			DestNodeID:      nodeID,
			CallerIdentity:  callerIdentity,
			CallerVerified:  callerVerified,
			SourceAddr:      r.RemoteAddr,
			DestAddr:        destAddr,
			DestPort:        destPort,
			Namespace:       resolvedNS,
			ServiceName:     resolvedName,
			NodeServiceID:   svcID,
			ServiceLabels:   resolvedSvc.Labels,
			AuthzRequiresL7: authzRequiresL7,
		}
		bridgeErr := httpBridge.Bridge(reqCtx, hboneConn, targetConn, meta)
		if bridgeErr != nil {
			log.Printf("Inbound HTTP bridge error for %s: %v\n", destAddr, bridgeErr)
			recordOutcome("error")
			span.SetError(bridgeErr, bridgeErr.Error())
		} else {
			recordOutcome("success")
		}
		span.End()
		return
	}

	// Raw L4 fallback when HTTP bridge is not configured
	if metrics != nil {
		metrics.AddUpDownCounter(reqCtx, outbound.MetricRequestsActive, 1,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNSLabel},
		)
	}

	var bytesIn, bytesOut int64
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream from client to target
	go func() {
		defer wg.Done()
		bytesIn, _ = io.Copy(targetConn, trackedBody)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	// Stream from target to client
	go func() {
		defer wg.Done()
		fw := &flushWriter{w: trackedWriter, f: flusher}
		bytesOut, _ = io.Copy(fw, targetConn)
	}()

	wg.Wait()

	if metrics != nil {
		metrics.AddUpDownCounter(context.Background(), outbound.MetricRequestsActive, -1,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNSLabel},
		)
		durMs := float64(time.Since(connStart).Nanoseconds()) / 1e6
		if metrics.CombinedRequestMetricEnabled() {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrSourceNamespace, Value: srcNS},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNSLabel},
				model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "tcp"},
				model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: "ok"},
			)
		}
		metrics.AddCounter(context.Background(), outbound.MetricRequestsIngressTotal, 1,
			model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
			model.MetricAttribute{Key: outbound.MetricAttrSourceNamespace, Value: srcNS},
			model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "tcp"},
			model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: "ok"},
		)
		metrics.RecordHistogram(context.Background(), outbound.MetricRequestsDurationMs, durMs,
			model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
			model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "tcp"},
		)
		if bytesIn > 0 {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsBytesSent, bytesIn,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
			)
		}
		if bytesOut > 0 {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsBytesReceived, bytesOut,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvcLabel},
			)
		}
	}
	recordOutcome("success")
	span.End()
}

type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return
}

// hboneStreamConn adapts an inbound HTTP/2 HBONE CONNECT stream (r.Body + ResponseWriter)
// into a thread-safe net.Conn for the shared L7 HTTPStreamBridge.
type hboneStreamConn struct {
	reader     *deadlineReader
	w          io.Writer
	flusher    http.Flusher
	remoteAddr net.Addr
	localAddr  net.Addr

	writeMu sync.Mutex
	closed  bool
}

func newHBONEStreamConn(body io.ReadCloser, w io.Writer, flusher http.Flusher, remoteAddr string, localAddr net.Addr) *hboneStreamConn {
	var rAddr net.Addr = hboneAddr{addr: remoteAddr}
	if parsed, err := net.ResolveTCPAddr("tcp", remoteAddr); err == nil {
		rAddr = parsed
	}
	if localAddr == nil {
		localAddr = hboneAddr{addr: "hbone-server"}
	}
	return &hboneStreamConn{
		reader:     newDeadlineReader(body),
		w:          w,
		flusher:    flusher,
		remoteAddr: rAddr,
		localAddr:  localAddr,
	}
}

func (c *hboneStreamConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *hboneStreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	n, err := c.w.Write(p)
	if c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}

func (c *hboneStreamConn) Close() error {
	c.writeMu.Lock()
	alreadyClosed := c.closed
	c.closed = true
	c.writeMu.Unlock()
	if alreadyClosed {
		return nil
	}
	return c.reader.Close()
}

func (c *hboneStreamConn) LocalAddr() net.Addr               { return c.localAddr }
func (c *hboneStreamConn) RemoteAddr() net.Addr              { return c.remoteAddr }
func (c *hboneStreamConn) SetDeadline(t time.Time) error     { return c.reader.SetReadDeadline(t) }
func (c *hboneStreamConn) SetReadDeadline(t time.Time) error { return c.reader.SetReadDeadline(t) }
func (c *hboneStreamConn) SetWriteDeadline(time.Time) error  { return nil }

func parseHostPort(addr string) (string, int) {
	if addr == "" {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return host, 0
	}
	return host, port
}

type trackedReadCloser struct {
	rc     io.ReadCloser
	onRead func(int)
}

func (t *trackedReadCloser) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 && t.onRead != nil {
		t.onRead(n)
	}
	return n, err
}

func (t *trackedReadCloser) Close() error {
	return t.rc.Close()
}

func hostOnly(addr string) string {
	host, _ := parseHostPort(addr)
	return host
}

func defaultStr(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
}

func formatServiceLabel(ns, name, svcID, addr string) string {
	if ns != "" && name != "" {
		return ns + "/" + name
	}
	if name != "" {
		return name
	}
	if svcID != "" {
		return svcID
	}
	if addr != "" {
		return addr
	}
	return "unknown"
}
