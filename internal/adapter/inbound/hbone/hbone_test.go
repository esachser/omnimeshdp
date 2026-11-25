package hbone_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func TestHBONETunnelEcho(t *testing.T) {
	// 1. Start a dummy backend TCP echo server
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo listener: %v", err)
	}
	defer echoListener.Close()

	echoAddr := echoListener.Addr().String()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start HBONE server
	hbListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port for HBONE server: %v", err)
	}
	hbAddr := hbListener.Addr().String()
	_ = hbListener.Close()

	server := hbone.NewServer(hbAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.Start(ctx); err != nil {
			serverErrCh <- err
		}
	}()

	// Allow server time to bind
	time.Sleep(100 * time.Millisecond)

	// 3. Create HBONE client
	client := hbone.NewClient()

	// 4. Create a local pipe simulating an intercepted connection
	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()
	defer proxySide.Close()

	tunnelErrCh := make(chan error, 1)
	go func() {
		err := client.Tunnel(
			ctx,
			proxySide,
			hbAddr,
			echoAddr,
			"test-identity",
		)
		tunnelErrCh <- err
	}()

	// 5. Write data through clientSide and verify echo response
	testPayload := []byte("Hello HBONE Mesh Over HTTP/2!")

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := clientSide.Write(testPayload)
		writeErrCh <- err
	}()

	select {
	case err := <-writeErrCh:
		if err != nil {
			t.Fatalf("failed to write to tunnel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout writing to tunnel")
	}

	buf := make([]byte, len(testPayload))
	_ = clientSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(clientSide, buf)
	if err != nil {
		t.Fatalf("failed to read echoed data from tunnel: %v", err)
	}

	if string(buf[:n]) != string(testPayload) {
		t.Fatalf("echo mismatch: got %q, expected %q", string(buf[:n]), string(testPayload))
	}

	fmt.Println("HBONE HTTP/2 CONNECT tunnel successfully verified!")
}

func createTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509bundle.Bundle) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: "Omnimesh Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	td := spiffeid.RequireTrustDomainFromString("omnimesh.local")
	bundle := x509bundle.New(td)
	bundle.AddX509Authority(caCert)

	return caCert, caKey, bundle
}

func createTestSPIFFEWorkloadSVID(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeIDStr string) *x509svid.SVID {
	t.Helper()

	spiffeURI, err := url.Parse(spiffeIDStr)
	if err != nil {
		t.Fatalf("invalid spiffe id: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "Omnimesh SVID",
		},
		URIs:                  []*url.URL{spiffeURI},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	svid, err := x509svid.ParseRaw(der, keyDER)
	if err != nil {
		t.Fatalf("failed to parse SVID: %v", err)
	}

	return svid
}

func TestHBONETunnelEcho_MTLS(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("omnimesh.local")
	caCert, caKey, bundle := createTestCA(t)

	serverSVID := createTestSPIFFEWorkloadSVID(t, caCert, caKey, "spiffe://omnimesh.local/ns/omnimesh-system/sa/omnimeshdp-server")
	clientSVID := createTestSPIFFEWorkloadSVID(t, caCert, caKey, "spiffe://omnimesh.local/ns/production/sa/order-service")

	serverTLS := tlsconfig.MTLSServerConfig(serverSVID, bundle, tlsconfig.AuthorizeMemberOf(td))
	clientTLS := tlsconfig.MTLSClientConfig(clientSVID, bundle, tlsconfig.AuthorizeMemberOf(td))

	// 1. Start a dummy backend TCP echo server
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo listener: %v", err)
	}
	defer echoListener.Close()
	echoAddr := echoListener.Addr().String()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start HBONE server with server mTLS config
	hbListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port for HBONE server: %v", err)
	}
	hbAddr := hbListener.Addr().String()
	_ = hbListener.Close()

	server := hbone.NewServer(hbAddr, serverTLS)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.Start(ctx); err != nil {
			serverErrCh <- err
		}
	}()

	// Allow server time to bind
	time.Sleep(100 * time.Millisecond)

	// 3. Create HBONE client
	client := hbone.NewClient()

	// 4. Create local pipe simulating intercepted connection from calling process
	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()
	defer proxySide.Close()

	tunnelErrCh := make(chan error, 1)
	go func() {
		err := client.Tunnel(
			ctx,
			proxySide,
			hbAddr,
			echoAddr,
			clientSVID.ID.String(),
			clientTLS,
		)
		tunnelErrCh <- err
	}()

	// 5. Send payload through tunnel over mTLS and verify echoed response
	testPayload := []byte("Inter-Agent mTLS Encrypted Tunnel with SVID Impersonation!")

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := clientSide.Write(testPayload)
		writeErrCh <- err
	}()

	select {
	case err := <-writeErrCh:
		if err != nil {
			t.Fatalf("failed to write to tunnel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout writing to tunnel")
	}

	buf := make([]byte, len(testPayload))
	_ = clientSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(clientSide, buf)
	if err != nil {
		t.Fatalf("failed to read echoed data from mTLS tunnel: %v", err)
	}

	if string(buf[:n]) != string(testPayload) {
		t.Fatalf("echo mismatch: got %q, expected %q", string(buf[:n]), string(testPayload))
	}
}

func TestHBONETunnel_ResolvesServiceByID(t *testing.T) {
	// 1. Start a local backend TCP echo server on a real random port
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo listener: %v", err)
	}
	defer echoListener.Close()

	tcpAddr := echoListener.Addr().(*net.TCPAddr)

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start HBONE server configured with the local service's host and port
	hbListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port for HBONE server: %v", err)
	}
	hbAddr := hbListener.Addr().String()
	_ = hbListener.Close()

	server := hbone.NewServer(hbAddr)
	server.SetServices([]model.NodeServiceInfo{
		{
			Namespace: "production",
			Name:      "payment-service",
			ID:        "sample-1",
			Host:      "127.0.0.1",
			Port:      tcpAddr.Port,
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// 3. Create HBONE client and tunnel using virtual mesh IP as realDest + "sample-1" as serviceID
	client := hbone.NewClient()
	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()
	defer proxySide.Close()

	go func() {
		_ = client.TunnelToService(
			ctx,
			proxySide,
			hbAddr,
			"10.240.0.99:80", // unroutable virtual mesh IP
			"sample-1",       // service ID resolved by destination HBONE server
			"test-identity",
		)
	}()

	testPayload := []byte("Routed to local service via x-omnimesh-service-id!")
	writeErrCh := make(chan error, 1)
	go func() {
		_, err := clientSide.Write(testPayload)
		writeErrCh <- err
	}()

	select {
	case err := <-writeErrCh:
		if err != nil {
			t.Fatalf("failed to write to tunnel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout writing to tunnel")
	}

	buf := make([]byte, len(testPayload))
	_ = clientSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(clientSide, buf)
	if err != nil {
		t.Fatalf("failed to read echoed data from tunnel: %v", err)
	}
	if string(buf[:n]) != string(testPayload) {
		t.Fatalf("echo mismatch: got %q, expected %q", string(buf[:n]), string(testPayload))
	}
}

func TestHBONEOpenTunnel_StatusErrorsAndTimeoutLifetime(t *testing.T) {
	// 1. Real HBONE server pointing to a closed local port returns 502 Bad Gateway
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve closed port: %v", err)
	}
	closedAddr := closedLn.Addr().String()
	_ = closedLn.Close()

	hbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	hbAddr := hbLn.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := hbone.NewServer(hbAddr)
	go func() {
		_ = server.Serve(ctx, hbLn)
	}()

	client := hbone.NewClient()

	_, err = client.OpenTunnelWithTimeout(ctx, 2*time.Second, hbAddr, closedAddr, "", "test-id")
	if err == nil {
		t.Fatal("expected 502 error, got nil")
	}
	if !errors.Is(err, domain.ErrBadGateway) {
		t.Fatalf("expected errors.Is(err, ErrBadGateway), got: %v", err)
	}
	if !errors.Is(err, domain.ErrTunnelFailed) {
		t.Fatalf("expected errors.Is(err, ErrTunnelFailed), got: %v", err)
	}
	var statusErr *domain.TunnelStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected TunnelStatusError{502}, got: %v", err)
	}

	// 2. Non-502 status (403 Forbidden) does not match ErrBadGateway
	forbiddenLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer forbiddenLn.Close()
	h2Protos := new(http.Protocols)
	h2Protos.SetUnencryptedHTTP2(true)
	forbiddenHTTP := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}),
		HTTP2:     &http.HTTP2Config{},
		Protocols: h2Protos,
	}
	go func() { _ = forbiddenHTTP.Serve(forbiddenLn) }()
	defer forbiddenHTTP.Close()

	_, err = client.OpenTunnelWithTimeout(ctx, 2*time.Second, forbiddenLn.Addr().String(), closedAddr, "", "test-id")
	if err == nil {
		t.Fatal("expected 403 error, got nil")
	}
	if errors.Is(err, domain.ErrBadGateway) {
		t.Fatalf("403 Forbidden must not match ErrBadGateway: %v", err)
	}
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusForbidden {
		t.Fatalf("expected TunnelStatusError{403}, got: %v", err)
	}

	// 3. Handshake timeout does NOT kill a tunnel that succeeds before connectTimeout
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	tunnel, err := client.OpenTunnelWithTimeout(ctx, 80*time.Millisecond, hbAddr, echoLn.Addr().String(), "", "test-id")
	if err != nil {
		t.Fatalf("expected tunnel to open before 80ms connectTimeout, got: %v", err)
	}
	// Wait longer than connectTimeout before bridging to ensure the stream was NOT canceled!
	time.Sleep(150 * time.Millisecond)

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()
	defer proxySide.Close()

	go func() { _ = tunnel.Bridge(proxySide) }()

	msg := []byte("still alive past connectTimeout!")
	if _, err := clientSide.Write(msg); err != nil {
		t.Fatalf("write failed past connectTimeout: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatalf("read failed past connectTimeout: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), string(msg))
	}

	// 4. Slow/stalled peer times out cleanly within connectTimeout with context.DeadlineExceeded
	stalledLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for stalled server: %v", err)
	}
	defer stalledLn.Close()
	stalledRelease := make(chan struct{})
	defer close(stalledRelease)
	stalledHTTP := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-stalledRelease
		}),
		HTTP2:     &http.HTTP2Config{},
		Protocols: h2Protos,
	}
	go func() { _ = stalledHTTP.Serve(stalledLn) }()
	defer stalledHTTP.Close()

	start := time.Now()
	_, err = client.OpenTunnelWithTimeout(ctx, 60*time.Millisecond, stalledLn.Addr().String(), closedAddr, "", "test-id")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded on stalled peer, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected timeout around 60ms, took %v", elapsed)
	}
}

func TestHBONEServer_EnforcesHTTP2ProtocolAndSetTLSConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h1Protos := new(http.Protocols)
	h1Protos.SetHTTP1(true)

	t.Run("cleartext server rejects HTTP/1.1 requests", func(t *testing.T) {
		hbLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		server := hbone.NewServer(hbLn.Addr().String())
		go func() { _ = server.Serve(ctx, hbLn) }()

		h1Client := &http.Client{
			Timeout:   2 * time.Second,
			Transport: &http.Transport{Protocols: h1Protos},
		}
		defer h1Client.CloseIdleConnections()

		resp, err := h1Client.Get("http://" + hbLn.Addr().String() + "/")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("expected HTTP/1.1 request to be rejected, got status %d", resp.StatusCode)
		}
	})

	t.Run("SetTLSConfig switches server to mTLS HTTP/2 only", func(t *testing.T) {
		echoLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to start echo listener: %v", err)
		}
		defer echoLn.Close()
		go func() {
			for {
				c, err := echoLn.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					_, _ = io.Copy(conn, conn)
				}(c)
			}
		}()

		td := spiffeid.RequireTrustDomainFromString("omnimesh.local")
		caCert, caKey, bundle := createTestCA(t)
		serverSVID := createTestSPIFFEWorkloadSVID(t, caCert, caKey, "spiffe://omnimesh.local/ns/omnimesh-system/sa/srv")
		clientSVID := createTestSPIFFEWorkloadSVID(t, caCert, caKey, "spiffe://omnimesh.local/ns/prod/sa/cli")
		serverTLS := tlsconfig.MTLSServerConfig(serverSVID, bundle, tlsconfig.AuthorizeMemberOf(td))
		clientTLS := tlsconfig.MTLSClientConfig(clientSVID, bundle, tlsconfig.AuthorizeMemberOf(td))

		hbLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		hbAddr := hbLn.Addr().String()

		server := hbone.NewServer(hbAddr)
		server.SetTLSConfig(serverTLS)
		go func() { _ = server.Serve(ctx, hbLn) }()

		h1TLSClient := &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				Protocols:       h1Protos,
				TLSClientConfig: clientTLS.Clone(),
			},
		}
		defer h1TLSClient.CloseIdleConnections()

		if resp, err := h1TLSClient.Get("https://" + hbAddr + "/"); err == nil {
			_ = resp.Body.Close()
			t.Fatalf("expected TLS HTTP/1.1 request to be rejected, got status %d", resp.StatusCode)
		}

		client := hbone.NewClient()
		tunnel, err := client.OpenTunnelWithTimeout(ctx, 2*time.Second, hbAddr, echoLn.Addr().String(), "", clientSVID.ID.String(), clientTLS)
		if err != nil {
			t.Fatalf("expected mTLS HBONE tunnel after SetTLSConfig, got: %v", err)
		}
		defer tunnel.Close()

		clientSide, proxySide := net.Pipe()
		defer clientSide.Close()
		defer proxySide.Close()
		go func() { _ = tunnel.Bridge(proxySide) }()

		msg := []byte("mTLS via SetTLSConfig")
		if _, err := clientSide.Write(msg); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		buf := make([]byte, len(msg))
		_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(clientSide, buf); err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("echo mismatch: got %q, want %q", string(buf), string(msg))
		}
	})
}

type recordingHBONEAuthorizer struct {
	allowCaller string
	calls       atomic.Int32
	mu          sync.Mutex
	lastReq     model.AuthzRequest
}

func (a *recordingHBONEAuthorizer) AuthorizeConnection(_ context.Context, req model.AuthzRequest) model.AuthzDecision {
	a.calls.Add(1)
	a.mu.Lock()
	a.lastReq = req
	a.mu.Unlock()
	if req.CallerVerified && req.CallerIdentity == a.allowCaller {
		return model.AuthzDecision{Allowed: true, Reason: model.AuthzReasonExplicitAllow}
	}
	return model.AuthzDecision{Allowed: false, Reason: model.AuthzReasonExplicitDeny}
}

func (a *recordingHBONEAuthorizer) lastRequest() model.AuthzRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastReq
}

func (a *recordingHBONEAuthorizer) AuthorizeHTTP(_ context.Context, req model.AuthzRequest) model.AuthzDecision {
	return model.AuthzDecision{Allowed: req.CallerVerified && req.CallerIdentity == a.allowCaller}
}

func TestHBONEServer_AuthorizerDeniesBeforeDialAndPreventsHeaderSpoofing(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("omnimesh.local")
	caCert, caKey, bundle := createTestCA(t)

	serverSVID := createTestSPIFFEWorkloadSVID(t, caCert, caKey, "spiffe://omnimesh.local/ns/omnimesh-system/sa/node-b")
	authorizedSVID := createTestSPIFFEWorkloadSVID(t, caCert, caKey, "spiffe://omnimesh.local/ns/prod/sa/orders")
	attackerSVID := createTestSPIFFEWorkloadSVID(t, caCert, caKey, "spiffe://omnimesh.local/ns/prod/sa/attacker")

	serverTLS := tlsconfig.MTLSServerConfig(serverSVID, bundle, tlsconfig.AuthorizeMemberOf(td))
	authorizedTLS := tlsconfig.MTLSClientConfig(authorizedSVID, bundle, tlsconfig.AuthorizeMemberOf(td))
	attackerTLS := tlsconfig.MTLSClientConfig(attackerSVID, bundle, tlsconfig.AuthorizeMemberOf(td))

	var backendAccepts atomic.Int32
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backendLn.Close()
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			backendAccepts.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	backendPort := backendLn.Addr().(*net.TCPAddr).Port

	hbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen hbone: %v", err)
	}
	hbAddr := hbLn.Addr().String()

	authzStub := &recordingHBONEAuthorizer{allowCaller: authorizedSVID.ID.String()}
	srv := hbone.NewServer(hbAddr, serverTLS)
	srv.SetServices([]model.NodeServiceInfo{
		{Namespace: "prod", Name: "payments", ID: "payments-1", Host: "127.0.0.1", Port: backendPort},
	})
	srv.SetAuthorizer(authzStub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, hbLn) }()

	client := hbone.NewClient()

	// 1. Attacker presents attackerSVID over mTLS while spoofing x-omnimesh-caller-identity
	//    of authorizedSVID in the HTTP/2 CONNECT header. Must be denied AND never dial backend.
	_, err = client.OpenTunnelWithOptions(ctx, hbone.TunnelOptions{
		ConnectTimeout: 2 * time.Second,
		TargetHost:     hbAddr,
		RealDest:       "10.0.0.5:8080",
		NodeServiceID:  "payments-1",
		Identity:       authorizedSVID.ID.String(), // Spoofed header value!
		TLSConfig:      attackerTLS,                // Real mTLS cert is attackerSVID!
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for spoofed attacker, got %v", err)
	}
	lastReq := authzStub.lastRequest()
	if lastReq.CallerIdentity != attackerSVID.ID.String() || !lastReq.CallerVerified {
		t.Fatalf("expected mTLS identity %q (verified=true), got %q (verified=%v)",
			attackerSVID.ID.String(), lastReq.CallerIdentity, lastReq.CallerVerified)
	}
	if backendAccepts.Load() != 0 {
		t.Fatalf("expected target backend never to be dialed on authz deny, got %d accepts", backendAccepts.Load())
	}

	// 2. Authorized SVID succeeds and dials backend.
	tun, err := client.OpenTunnelWithOptions(ctx, hbone.TunnelOptions{
		ConnectTimeout: 2 * time.Second,
		TargetHost:     hbAddr,
		RealDest:       "10.0.0.5:8080",
		NodeServiceID:  "payments-1",
		Identity:       authorizedSVID.ID.String(),
		TLSConfig:      authorizedTLS,
	})
	if err != nil {
		t.Fatalf("expected authorized tunnel to succeed, got %v", err)
	}
	_ = tun.Close()
	if backendAccepts.Load() != 1 {
		t.Fatalf("expected 1 backend accept for authorized connection, got %d", backendAccepts.Load())
	}
}
