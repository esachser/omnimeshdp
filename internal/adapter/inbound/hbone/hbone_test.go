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
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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
	h2Srv := &http2.Server{}
	forbiddenHTTP := &http.Server{
		Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}), h2Srv),
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
		Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-stalledRelease
		}), &http2.Server{}),
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
