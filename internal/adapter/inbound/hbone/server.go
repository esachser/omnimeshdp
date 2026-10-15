package hbone

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Server implements an HTTP/2 HBONE (CONNECT) tunnel server.
type Server struct {
	addr       string
	httpServer *http.Server
	listener   net.Listener
}

// NewServer creates a new HBONE server listening on the specified address.
func NewServer(addr string) *Server {
	s := &Server{
		addr: addr,
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

// Start binds to the listener and serves HTTP/2 HBONE connections.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = ln

	log.Printf("Proxy HBONE server running on %s...\n", s.addr)

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

// ServeHTTP handles incoming HTTP/2 requests, expecting CONNECT with x-omnimesh-real-dest.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	realDest := r.Header.Get("x-omnimesh-real-dest")
	if realDest == "" {
		http.Error(w, "Missing x-omnimesh-real-dest header", http.StatusBadRequest)
		return
	}

	// Dial target real destination
	targetConn, err := net.DialTimeout("tcp", realDest, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to real destination at %s: %v\n", realDest, err)
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
