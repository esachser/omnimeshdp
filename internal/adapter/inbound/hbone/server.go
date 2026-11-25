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
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/sockmark"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
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
	}

	return s
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
		s.httpServer.TLSConfig = s.tlsConfig
		s.httpServer.Protocols = serverProtocols(true)
		ln = tls.NewListener(ln, s.tlsConfig)
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

// ServeHTTP handles incoming HTTP/2 requests, expecting CONNECT with x-omnimesh-service-id or x-omnimesh-real-dest.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
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

	authzRequiresL7 := false
	resolvedNS := resolvedSvc.Namespace
	resolvedName := resolvedSvc.Name
	resolvedProto := resolvedSvc.Protocol
	if authorizer != nil {
		decision := authorizer.AuthorizeConnection(r.Context(), model.AuthzRequest{
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
	}

	// Dial target real destination. The socket is marked so Linux redirect rules
	// don't send it back into the proxy (no-op on other platforms).
	dialer := net.Dialer{Timeout: 5 * time.Second, Control: sockmark.Control(sockmark.ProxyMark)}
	targetConn, err := dialer.Dial("tcp", destAddr)
	if err != nil {
		log.Printf("Failed to connect to destination at %s (nodeServiceID=%q): %v\n", destAddr, nodeServiceID, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	w.WriteHeader(http.StatusOK)
	flusher, hasFlusher := w.(http.Flusher)
	if hasFlusher {
		flusher.Flush()
	}

	if httpBridge != nil {
		var localAddr net.Addr
		if s.listener != nil {
			localAddr = s.listener.Addr()
		}
		hboneConn := newHBONEStreamConn(r.Body, w, flusher, r.RemoteAddr, localAddr)
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
		if err := httpBridge.Bridge(r.Context(), hboneConn, targetConn, meta); err != nil {
			log.Printf("Inbound HTTP bridge error for %s: %v\n", destAddr, err)
		}
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Stream from client to target
	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, r.Body)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	// Stream from target to client
	go func() {
		defer wg.Done()
		fw := &flushWriter{w: w, f: flusher}
		_, _ = io.Copy(fw, targetConn)
	}()

	wg.Wait()
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
	w          http.ResponseWriter
	flusher    http.Flusher
	remoteAddr net.Addr
	localAddr  net.Addr

	writeMu sync.Mutex
	closed  bool
}

func newHBONEStreamConn(body io.ReadCloser, w http.ResponseWriter, flusher http.Flusher, remoteAddr string, localAddr net.Addr) *hboneStreamConn {
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
