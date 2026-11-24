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
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
	"github.com/esachser/omnimeshdp/internal/application/proxy"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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

func startEchoServer(t *testing.T) (string, int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	tcpAddr := ln.Addr().(*net.TCPAddr)
	return ln.Addr().String(), tcpAddr.Port, func() { _ = ln.Close() }
}

func reserveClosedPort(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr, tcpAddr.Port
}

func startCountedHTTP2Server(t *testing.T, ctx context.Context, handler http.Handler) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	var hits atomic.Int32
	srv := &http.Server{
		Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			handler.ServeHTTP(w, r)
		}), &http2.Server{}),
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = ln.Close()
	}()
	return ln.Addr().String(), &hits
}

func startTestClientProxy(t *testing.T, ctx context.Context, destIP uint32, destPort uint16, router *proxy.Router) string {
	t.Helper()
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen client proxy: %v", err)
	}
	mockProc := &mockProcessor{
		pktInfo: &model.OriginalPacketInfo{
			PID:  1234,
			IP:   destIP,
			Port: destPort,
		},
	}
	cs := proxy.NewClientSideService(clientLn.Addr().String(), "", mockProc)
	cs.SetRouter(router)
	go func() {
		_ = cs.Serve(ctx, clientLn)
	}()
	// Wait briefly for Accept loop to enter
	time.Sleep(30 * time.Millisecond)
	return clientLn.Addr().String()
}

func TestClientSideService_RetriesOnPeer502AndKeepsEndpointEligible(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Closed backend port causes real hbone.Server A to return HTTP 502 Bad Gateway.
	_, closedPort := reserveClosedPort(t)
	_, echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	srvALn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	addrA := srvALn.Addr().String()
	hboneA := hbone.NewServer(addrA)
	hboneA.SetServices([]model.NodeServiceInfo{
		{Namespace: "prod", Name: "echo", ID: "svc-a", Host: "127.0.0.1", Port: closedPort},
	})
	go func() { _ = hboneA.Serve(ctx, srvALn) }()

	srvBLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	addrB := srvBLn.Addr().String()
	hboneB := hbone.NewServer(addrB)
	hboneB.SetServices([]model.NodeServiceInfo{
		{Namespace: "prod", Name: "echo", ID: "svc-b", Host: "127.0.0.1", Port: echoPort},
	})
	go func() { _ = hboneB.Serve(ctx, srvBLn) }()

	const meshIPStr = "10.200.1.10"
	const meshIP = uint32(10<<24 | 200<<16 | 1<<8 | 10)
	const svcPort = uint16(8080)

	router := proxy.NewRouter()
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "echo", MeshAddr: meshIPStr, Port: int32(svcPort)},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "echo",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "node-a", RouteName: "svc-a", Addr: addrA},
					{NodeId: "node-b", RouteName: "svc-b", Addr: addrB},
				},
			},
		},
		TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
			{
				Name:                   "rr",
				Namespace:              "prod",
				TargetServiceNamespace: "prod",
				TargetServiceName:      "echo",
				LoadBalancer: &omnimeshv1.LoadBalancerPolicyInfo{
					Algorithm: omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED_ROUND_ROBIN,
				},
			},
		},
	})

	proxyAddr := startTestClientProxy(t, ctx, meshIP, svcPort, router)

	// 1st connection: RR picks node-a (502) -> transparent retry to node-b (200) -> echo succeeds!
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	payload := []byte("hello over 502 failover")
	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		t.Fatalf("read echo after 502 failover: %v", err)
	}
	conn.Close()
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), string(payload))
	}

	// Verify node-a was NOT marked unhealthy by updating hboneA to a live echo backend
	// and verifying subsequent connections still route to node-a!
	hboneA.SetServices([]model.NodeServiceInfo{
		{Namespace: "prod", Name: "echo", ID: "svc-a", Host: "127.0.0.1", Port: echoPort},
	})
	// Also test with a fresh wrapped counter on A? Even simpler: resolve directly from router
	// with node-b excluded -> must return node-a (proving router kept node-a healthy!).
	resolvedA, _, err := router.ResolveRouteWithExclusions(meshIPStr, svcPort, "", []model.EndpointKey{
		{NodeID: "node-b", RouteName: "svc-b", Addr: addrB},
	})
	if err != nil || resolvedA.NodeID != "node-a" {
		t.Fatalf("expected node-a to remain eligible (not marked unhealthy after 502), got r=%v err=%v", resolvedA, err)
	}

	// Send 2 more real connections through proxy while both A and B are healthy.
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if _, err := c.Write(payload); err != nil {
			c.Close()
			t.Fatalf("write %d: %v", i, err)
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			c.Close()
			t.Fatalf("read %d: %v", i, err)
		}
		c.Close()
	}
}

func TestClientSideService_StopsAfterMaxRetriesAndDistinctEndpoints(t *testing.T) {
	badGatewayHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	})

	t.Run("stops at MaxRetries=1 with 3 endpoints", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		addr1, hits1 := startCountedHTTP2Server(t, ctx, badGatewayHandler)
		addr2, hits2 := startCountedHTTP2Server(t, ctx, badGatewayHandler)
		addr3, hits3 := startCountedHTTP2Server(t, ctx, badGatewayHandler)

		const meshIPStr = "10.200.2.1"
		const meshIP = uint32(10<<24 | 200<<16 | 2<<8 | 1)

		router := proxy.NewRouter()
		router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
			Services: []*omnimeshv1.ServiceInfo{
				{Namespace: "prod", Name: "fail", MeshAddr: meshIPStr, Port: 80},
			},
			Routes: []*omnimeshv1.RouteInfo{
				{
					Namespace:   "prod",
					ServiceName: "fail",
					TargetNodes: []*omnimeshv1.NodeEndpointInfo{
						{NodeId: "n1", RouteName: "r1", Addr: addr1},
						{NodeId: "n2", RouteName: "r2", Addr: addr2},
						{NodeId: "n3", RouteName: "r3", Addr: addr3},
					},
				},
			},
			TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
				{
					Name:                   "retry-1",
					Namespace:              "prod",
					TargetServiceNamespace: "prod",
					TargetServiceName:      "fail",
					Retry:                  &omnimeshv1.RetryPolicyInfo{MaxRetries: 1},
				},
			},
		})

		proxyAddr := startTestClientProxy(t, ctx, meshIP, 80, router)
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 16)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, readErr := conn.Read(buf)
		if n > 0 || readErr == nil {
			t.Fatalf("expected closed connection with 0 bytes, got n=%d err=%v", n, readErr)
		}

		total := hits1.Load() + hits2.Load() + hits3.Load()
		if total != 2 {
			t.Fatalf("expected 2 total attempts (1 initial + 1 retry), got %d", total)
		}
		if hits1.Load() > 1 || hits2.Load() > 1 || hits3.Load() > 1 {
			t.Fatalf("no endpoint should be tried twice: hits=(%d,%d,%d)", hits1.Load(), hits2.Load(), hits3.Load())
		}
	})

	t.Run("caps retries at distinct endpoints (2 endpoints with MaxRetries=3)", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		addr1, hits1 := startCountedHTTP2Server(t, ctx, badGatewayHandler)
		addr2, hits2 := startCountedHTTP2Server(t, ctx, badGatewayHandler)

		const meshIPStr = "10.200.2.2"
		const meshIP = uint32(10<<24 | 200<<16 | 2<<8 | 2)

		router := proxy.NewRouter()
		router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
			Services: []*omnimeshv1.ServiceInfo{
				{Namespace: "prod", Name: "fail2", MeshAddr: meshIPStr, Port: 80},
			},
			Routes: []*omnimeshv1.RouteInfo{
				{
					Namespace:   "prod",
					ServiceName: "fail2",
					TargetNodes: []*omnimeshv1.NodeEndpointInfo{
						{NodeId: "n1", RouteName: "r1", Addr: addr1},
						{NodeId: "n2", RouteName: "r2", Addr: addr2},
					},
				},
			},
		})

		proxyAddr := startTestClientProxy(t, ctx, meshIP, 80, router)
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 16)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, readErr := conn.Read(buf)
		if n > 0 || readErr == nil {
			t.Fatalf("expected closed connection, got n=%d err=%v", n, readErr)
		}

		if hits1.Load() != 1 || hits2.Load() != 1 {
			t.Fatalf("expected each endpoint hit exactly once, got hits=(%d,%d)", hits1.Load(), hits2.Load())
		}
	})

	t.Run("1 endpoint returning 502 makes 0 redundant retries", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		addr1, hits1 := startCountedHTTP2Server(t, ctx, badGatewayHandler)

		const meshIPStr = "10.200.2.3"
		const meshIP = uint32(10<<24 | 200<<16 | 2<<8 | 3)

		router := proxy.NewRouter()
		router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
			Services: []*omnimeshv1.ServiceInfo{
				{Namespace: "prod", Name: "fail1", MeshAddr: meshIPStr, Port: 80},
			},
			Routes: []*omnimeshv1.RouteInfo{
				{
					Namespace:   "prod",
					ServiceName: "fail1",
					TargetNodes: []*omnimeshv1.NodeEndpointInfo{
						{NodeId: "n1", RouteName: "r1", Addr: addr1},
					},
				},
			},
		})

		proxyAddr := startTestClientProxy(t, ctx, meshIP, 80, router)
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 16)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf)

		if hits1.Load() != 1 {
			t.Fatalf("expected exactly 1 attempt for single endpoint, got %d", hits1.Load())
		}
	})
}

func TestClientSideService_NonRetryableErrorsAndConnectFailurePolicy(t *testing.T) {
	t.Run("403 Forbidden is not retried", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		addr403, hits403 := startCountedHTTP2Server(t, ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}))
		addr200, hits200 := startCountedHTTP2Server(t, ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		const meshIPStr = "10.200.3.1"
		const meshIP = uint32(10<<24 | 200<<16 | 3<<8 | 1)

		router := proxy.NewRouter()
		router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
			Services: []*omnimeshv1.ServiceInfo{
				{Namespace: "prod", Name: "auth", MeshAddr: meshIPStr, Port: 80},
			},
			Routes: []*omnimeshv1.RouteInfo{
				{
					Namespace:   "prod",
					ServiceName: "auth",
					TargetNodes: []*omnimeshv1.NodeEndpointInfo{
						{NodeId: "n1", RouteName: "r1", Addr: addr403},
						{NodeId: "n2", RouteName: "r2", Addr: addr200},
					},
				},
			},
			TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
				{
					Name:                   "rr",
					Namespace:              "prod",
					TargetServiceNamespace: "prod",
					TargetServiceName:      "auth",
					LoadBalancer: &omnimeshv1.LoadBalancerPolicyInfo{
						Algorithm: omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED_ROUND_ROBIN,
					},
				},
			},
		})

		proxyAddr := startTestClientProxy(t, ctx, meshIP, 80, router)
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 16)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, readErr := conn.Read(buf)
		if n > 0 || readErr == nil {
			t.Fatalf("expected closed conn, got n=%d err=%v", n, readErr)
		}
		if hits403.Load() != 1 || hits200.Load() != 0 {
			t.Fatalf("expected 403 to stop immediately without retrying 2nd endpoint, got hits403=%d hits200=%d", hits403.Load(), hits200.Load())
		}
	})

	t.Run("mid-stream close after 200 OK is not retried", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		addrDrop, hitsDrop := startCountedHTTP2Server(t, ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			// Return immediately after 200 OK -> ends stream cleanly/abruptly without echoing
		}))
		addr200, hits200 := startCountedHTTP2Server(t, ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			_, _ = io.Copy(w, r.Body)
		}))

		const meshIPStr = "10.200.3.2"
		const meshIP = uint32(10<<24 | 200<<16 | 3<<8 | 2)

		router := proxy.NewRouter()
		router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
			Services: []*omnimeshv1.ServiceInfo{
				{Namespace: "prod", Name: "drop", MeshAddr: meshIPStr, Port: 80},
			},
			Routes: []*omnimeshv1.RouteInfo{
				{
					Namespace:   "prod",
					ServiceName: "drop",
					TargetNodes: []*omnimeshv1.NodeEndpointInfo{
						{NodeId: "n1", RouteName: "r1", Addr: addrDrop},
						{NodeId: "n2", RouteName: "r2", Addr: addr200},
					},
				},
			},
			TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
				{
					Name:                   "rr",
					Namespace:              "prod",
					TargetServiceNamespace: "prod",
					TargetServiceName:      "drop",
					LoadBalancer: &omnimeshv1.LoadBalancerPolicyInfo{
						Algorithm: omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED_ROUND_ROBIN,
					},
				},
			},
		})

		proxyAddr := startTestClientProxy(t, ctx, meshIP, 80, router)
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		_, _ = conn.Write([]byte("ping"))
		buf := make([]byte, 16)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(buf)
		if n != 0 || hitsDrop.Load() != 1 || hits200.Load() != 0 {
			t.Fatalf("expected no retry after 200 OK, got n=%d hitsDrop=%d hits200=%d", n, hitsDrop.Load(), hits200.Load())
		}
	})

	t.Run("connect-failure retried when policy includes connect-failure", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		closedAgentAddr, _ := reserveClosedPort(t)
		_, echoPort, stopEcho := startEchoServer(t)
		defer stopEcho()

		srvBLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen B: %v", err)
		}
		addrB := srvBLn.Addr().String()
		hboneB := hbone.NewServer(addrB)
		hboneB.SetServices([]model.NodeServiceInfo{
			{Namespace: "prod", Name: "cf", ID: "svc-b", Host: "127.0.0.1", Port: echoPort},
		})
		go func() { _ = hboneB.Serve(ctx, srvBLn) }()

		const meshIPStr = "10.200.3.3"
		const meshIP = uint32(10<<24 | 200<<16 | 3<<8 | 3)

		router := proxy.NewRouter()
		router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
			Services: []*omnimeshv1.ServiceInfo{
				{Namespace: "prod", Name: "cf", MeshAddr: meshIPStr, Port: 80},
			},
			Routes: []*omnimeshv1.RouteInfo{
				{
					Namespace:   "prod",
					ServiceName: "cf",
					TargetNodes: []*omnimeshv1.NodeEndpointInfo{
						{NodeId: "n1", RouteName: "svc-dead", Addr: closedAgentAddr},
						{NodeId: "n2", RouteName: "svc-b", Addr: addrB},
					},
				},
			},
			TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
				{
					Name:                   "cf-policy",
					Namespace:              "prod",
					TargetServiceNamespace: "prod",
					TargetServiceName:      "cf",
					LoadBalancer: &omnimeshv1.LoadBalancerPolicyInfo{
						Algorithm: omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED_ROUND_ROBIN,
					},
					Retry: &omnimeshv1.RetryPolicyInfo{
						MaxRetries: 2,
						RetryOn:    []string{"connect-failure"},
					},
				},
			},
		})

		proxyAddr := startTestClientProxy(t, ctx, meshIP, 80, router)
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		msg := []byte("recovered from connect-failure")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, len(msg))
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("expected failover echo on connect-failure, got: %v", err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("echo mismatch: got %q, want %q", string(buf), string(msg))
		}
	})
}

func TestClientSideService_Concurrent502Failover(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, closedPort := reserveClosedPort(t)
	_, echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	srvALn, _ := net.Listen("tcp", "127.0.0.1:0")
	hboneA := hbone.NewServer(srvALn.Addr().String())
	hboneA.SetServices([]model.NodeServiceInfo{{Namespace: "prod", Name: "conc", ID: "ep-a", Host: "127.0.0.1", Port: closedPort}})
	go func() { _ = hboneA.Serve(ctx, srvALn) }()

	srvBLn, _ := net.Listen("tcp", "127.0.0.1:0")
	hboneB := hbone.NewServer(srvBLn.Addr().String())
	hboneB.SetServices([]model.NodeServiceInfo{{Namespace: "prod", Name: "conc", ID: "ep-b", Host: "127.0.0.1", Port: echoPort}})
	go func() { _ = hboneB.Serve(ctx, srvBLn) }()

	srvCLn, _ := net.Listen("tcp", "127.0.0.1:0")
	hboneC := hbone.NewServer(srvCLn.Addr().String())
	hboneC.SetServices([]model.NodeServiceInfo{{Namespace: "prod", Name: "conc", ID: "ep-c", Host: "127.0.0.1", Port: echoPort}})
	go func() { _ = hboneC.Serve(ctx, srvCLn) }()

	const meshIPStr = "10.200.4.1"
	const meshIP = uint32(10<<24 | 200<<16 | 4<<8 | 1)

	router := proxy.NewRouter()
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "conc", MeshAddr: meshIPStr, Port: 8080},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "conc",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "na", RouteName: "ep-a", Addr: srvALn.Addr().String()},
					{NodeId: "nb", RouteName: "ep-b", Addr: srvBLn.Addr().String()},
					{NodeId: "nc", RouteName: "ep-c", Addr: srvCLn.Addr().String()},
				},
			},
		},
	})

	proxyAddr := startTestClientProxy(t, ctx, meshIP, 8080, router)

	const workers = 20
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", proxyAddr)
			if err != nil {
				t.Errorf("worker %d dial: %v", id, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("concurrent-payload-%02d", id)
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Errorf("worker %d write: %v", id, err)
				return
			}
			buf := make([]byte, len(msg))
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Errorf("worker %d read: %v", id, err)
				return
			}
			if string(buf) != msg {
				t.Errorf("worker %d mismatch: got %q, want %q", id, string(buf), msg)
			}
		}(i)
	}
	wg.Wait()
}
