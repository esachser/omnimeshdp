package hbone

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/sockmark"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Server implements an HTTP/2 HBONE (CONNECT) tunnel server.
type Server struct {
	addr         string
	httpServer   *http.Server
	listener     net.Listener
	tlsConfig    *tls.Config
	svcMu        sync.RWMutex
	services     map[string]model.NodeServiceInfo // keyed by NodeServiceInfo.Key()
	servicesByID map[string]string                // serviceID -> "host:port"
}

// NewServer creates a new HBONE server listening on the specified address.
// If tlsConfig is provided, the server enforces HTTP/2 over TLS with mTLS.
func NewServer(addr string, tlsConfig ...*tls.Config) *Server {
	s := &Server{
		addr:         addr,
		services:     make(map[string]model.NodeServiceInfo),
		servicesByID: make(map[string]string),
	}
	if len(tlsConfig) > 0 && tlsConfig[0] != nil {
		s.tlsConfig = tlsConfig[0].Clone()
	}

	h2Server := &http2.Server{
		IdleTimeout: 120 * time.Second,
	}

	handler := h2c.NewHandler(s, h2Server)
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	return s
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
	idx := make(map[string]string, len(s.services)*2)
	for _, svc := range s.services {
		addr := svc.Address()
		if addr == "" {
			continue
		}
		if svc.ID != "" {
			idx[svc.ID] = addr
		}
		idx[svc.Key()] = addr
		if svc.Name != "" {
			if _, exists := idx[svc.Name]; !exists {
				idx[svc.Name] = addr
			}
		}
	}
	s.servicesByID = idx
}

// ResolveServiceAddr looks up the local "host:port" address for a given service ID.
func (s *Server) ResolveServiceAddr(serviceID string) (string, bool) {
	if serviceID == "" {
		return "", false
	}
	s.svcMu.RLock()
	defer s.svcMu.RUnlock()
	addr, ok := s.servicesByID[serviceID]
	return addr, ok
}

// SetTLSConfig updates the server's mTLS configuration.
func (s *Server) SetTLSConfig(tlsConfig *tls.Config) {
	if tlsConfig != nil {
		s.tlsConfig = tlsConfig.Clone()
	} else {
		s.tlsConfig = nil
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
		hasH2 := false
		for _, p := range s.tlsConfig.NextProtos {
			if p == "h2" {
				hasH2 = true
				break
			}
		}
		if !hasH2 {
			s.tlsConfig.NextProtos = append([]string{"h2"}, s.tlsConfig.NextProtos...)
		}
		s.httpServer.TLSConfig = s.tlsConfig

		h2Server := &http2.Server{
			IdleTimeout: 120 * time.Second,
		}
		if err := http2.ConfigureServer(s.httpServer, h2Server); err != nil {
			return err
		}
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

	destAddr := realDest
	if nodeServiceID != "" {
		if resolvedAddr, ok := s.ResolveServiceAddr(nodeServiceID); ok && resolvedAddr != "" {
			destAddr = resolvedAddr
		}
	}

	if destAddr == "" {
		http.Error(w, "Missing x-omnimesh-real-dest or resolvable x-omnimesh-node-service-id header", http.StatusBadRequest)
		return
	}

	var callerIdentity string
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		peerCert := r.TLS.PeerCertificates[0]
		if len(peerCert.URIs) > 0 {
			callerIdentity = peerCert.URIs[0].String()
		}
	}
	if callerIdentity == "" {
		callerIdentity = r.Header.Get(HeaderCallerIdentity)
		if callerIdentity == "" {
			callerIdentity = r.Header.Get(HeaderSourceIdentity)
		}
	}
	if callerIdentity != "" {
		log.Printf("Proxy HBONE server accepted connection for %s (nodeServiceID=%q, realDest=%q) from caller %s\n",
			destAddr, nodeServiceID, realDest, callerIdentity)
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
