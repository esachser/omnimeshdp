package hbone_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
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
