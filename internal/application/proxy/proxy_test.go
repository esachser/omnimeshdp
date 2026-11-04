package proxy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/application/proxy"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type mockProcessor struct {
	pktInfo *model.OriginalPacketInfo
	err     error
}

func (m *mockProcessor) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (m *mockProcessor) Close() error {
	return nil
}

func (m *mockProcessor) GetOriginalPacketInfo(localAddr net.Addr, socketHandle uintptr) (*model.OriginalPacketInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.pktInfo, nil
}

func (m *mockProcessor) GetIdentityByPID(pid uint64) (string, bool) {
	return "fallback-sid", true
}

type mockSVIDProvider struct {
	mu           sync.Mutex
	queriedPIDs  []uint64
	tlsConfig    *tls.Config
	spiffeID     string
	errByPID     map[uint64]error
}

func (m *mockSVIDProvider) GetClientTLSConfigByPID(ctx context.Context, pid uint64) (*tls.Config, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queriedPIDs = append(m.queriedPIDs, pid)

	if err, ok := m.errByPID[pid]; ok {
		return nil, "", err
	}
	return m.tlsConfig, m.spiffeID, nil
}

func setupTestMTLS(t *testing.T, clientSPIFFEID, serverSPIFFEID string) (*tls.Config, *tls.Config) {
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

	genSVID := func(spiffeIDStr string) *x509svid.SVID {
		u, err := url.Parse(spiffeIDStr)
		if err != nil {
			t.Fatalf("invalid url: %v", err)
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject: pkix.Name{
				CommonName: "Workload SVID",
			},
			URIs:                  []*url.URL{u},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(1 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create cert: %v", err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal key: %v", err)
		}
		svid, err := x509svid.ParseRaw(der, keyDER)
		if err != nil {
			t.Fatalf("parse raw: %v", err)
		}
		return svid
	}

	cKey := genSVID(clientSPIFFEID)
	sKey := genSVID(serverSPIFFEID)

	clientTLS := tlsconfig.MTLSClientConfig(cKey, bundle, tlsconfig.AuthorizeMemberOf(td))
	serverTLS := tlsconfig.MTLSServerConfig(sKey, bundle, tlsconfig.AuthorizeMemberOf(td))

	return clientTLS, serverTLS
}

func TestClientSideService_ImpersonatesCallingProcessByPID(t *testing.T) {
	const callerPID = uint64(54321)
	const callerSVID = "spiffe://omnimesh.local/ns/production/sa/payment-service"
	const serverSVID = "spiffe://omnimesh.local/ns/omnimesh-system/sa/target-node"

	clientTLS, serverTLS := setupTestMTLS(t, callerSVID, serverSVID)

	// 1. Echo backend
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for echo backend: %v", err)
	}
	defer echoListener.Close()
	echoAddr := echoListener.Addr().String()
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	var echoPort uint16
	_, _ = fmt.Sscanf(echoPortStr, "%d", &echoPort)

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

	// 2. ServerSideService (receiving agent)
	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for server proxy: %v", err)
	}
	serverAddr := serverListener.Addr().String()

	serverService := proxy.NewServerSideService(serverAddr, serverTLS)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = serverService.Serve(ctx, serverListener)
	}()

	// 3. ClientSideService (calling agent)
	clientListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for client proxy: %v", err)
	}
	clientAddr := clientListener.Addr().String()

	// Mock processor that returns the caller PID and echo destination
	mockProc := &mockProcessor{
		pktInfo: &model.OriginalPacketInfo{
			PID:  callerPID,
			IP:   0x7f000001, // 127.0.0.1
			Port: echoPort,
		},
	}

	svidProv := &mockSVIDProvider{
		tlsConfig: clientTLS,
		spiffeID:  callerSVID,
		errByPID:  make(map[uint64]error),
	}

	clientService := proxy.NewClientSideService(clientAddr, serverAddr, mockProc)
	clientService.SetWorkloadSVIDProvider(svidProv)

	go func() {
		_ = clientService.Serve(ctx, clientListener)
	}()

	time.Sleep(100 * time.Millisecond)

	// 4. Dial client service simulating intercepted connection from process
	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatalf("failed to dial client proxy: %v", err)
	}
	defer conn.Close()

	testMsg := "Test data from calling process impersonating payment-service"
	if _, err := conn.Write([]byte(testMsg)); err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}

	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read echoed response: %v", err)
	}

	if string(buf[:n]) != testMsg {
		t.Fatalf("expected echoed %q, got %q", testMsg, string(buf[:n]))
	}

	// 5. Verify that WorkloadSVIDProvider was called with callerPID
	svidProv.mu.Lock()
	defer svidProv.mu.Unlock()
	if len(svidProv.queriedPIDs) == 0 {
		t.Fatal("expected WorkloadSVIDProvider to be queried, but was not")
	}
	if svidProv.queriedPIDs[0] != callerPID {
		t.Errorf("expected queried PID %d, got %d", callerPID, svidProv.queriedPIDs[0])
	}
}

func TestClientSideService_RejectsWhenSVIDFails(t *testing.T) {
	const callerPID = uint64(99999)

	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer serverListener.Close()

	clientListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	clientAddr := clientListener.Addr().String()

	mockProc := &mockProcessor{
		pktInfo: &model.OriginalPacketInfo{
			PID:  callerPID,
			IP:   0x7f000001,
			Port: 8080,
		},
	}

	svidProv := &mockSVIDProvider{
		errByPID: map[uint64]error{
			callerPID: errors.New("workload not registered in SPIRE"),
		},
	}

	clientService := proxy.NewClientSideService(clientAddr, serverListener.Addr().String(), mockProc)
	clientService.SetWorkloadSVIDProvider(svidProv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = clientService.Serve(ctx, clientListener)
	}()

	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatalf("failed to dial client proxy: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("unauthorized data"))
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(buf)

	// Since SVID failed, the connection should be closed immediately (EOF or read error with 0 bytes)
	if n > 0 {
		t.Fatalf("expected connection to be closed without echo, got %d bytes: %q", n, string(buf[:n]))
	}
	if err == nil {
		t.Fatal("expected EOF or read error, got nil")
	}

	svidProv.mu.Lock()
	defer svidProv.mu.Unlock()
	if len(svidProv.queriedPIDs) == 0 || svidProv.queriedPIDs[0] != callerPID {
		t.Errorf("expected SVID provider query for PID %d", callerPID)
	}
}
