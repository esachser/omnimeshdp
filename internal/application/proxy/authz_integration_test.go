package proxy_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
	"github.com/esachser/omnimeshdp/internal/application/authz"
	"github.com/esachser/omnimeshdp/internal/application/httpproxy"
	"github.com/esachser/omnimeshdp/internal/application/proxy"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type authzHarness struct {
	ctx           context.Context
	cancel        context.CancelFunc
	clientService *proxy.ClientSideService
	serverService *proxy.ServerSideService
	router        *proxy.Router
	authzEngine   *authz.Engine
	httpBridge    *httpproxy.Bridge
	clientAddr    string
	serverAddr    string
	server2Addr   string
}

func startAuthzMTLSHarness(
	t *testing.T,
	authzCfg model.AuthorizationConfig,
	callerSPIFFEID string,
	svcProto string,
	backendPort int,
	secondBackendPort int,
) *authzHarness {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	clientTLS, serverTLS := setupTestMTLS(t, callerSPIFFEID, "spiffe://omnimesh.local/ns/omnimesh-system/sa/node-b")

	engine, err := authz.NewEngine(authzCfg, authz.WithTrustDomain("omnimesh.local"))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	httpCfg := model.DefaultHTTPConfig()
	httpCfg.SniffTimeout = "60ms"
	bridge, err := httpproxy.NewBridge(httpCfg, false)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	if authzCfg.EnforceL7 && authzCfg.NormalizedMode() != model.AuthzModeDisabled {
		bridge.SetAuthorizer(engine)
	}

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen server1: %v", err)
	}
	serverAddr := serverLn.Addr().String()

	serverSvc := proxy.NewServerSideService(serverAddr, serverTLS)
	serverSvc.SetNodeID("node-b")
	serverSvc.SetHTTPBridge(bridge)
	serverSvc.SetAuthorizer(engine)
	serverSvc.SetServices([]model.NodeServiceInfo{
		{
			Namespace: "prod",
			Name:      "api",
			ID:        "api-v1",
			Host:      "127.0.0.1",
			Port:      backendPort,
			Protocol:  svcProto,
			Labels:    map[string]string{"version": "v1"},
		},
	})
	go func() { _ = serverSvc.Serve(ctx, serverLn) }()

	const meshIPStr = "10.215.0.10"
	const meshIP = uint32(10<<24 | 215<<16 | 0<<8 | 10)

	targetNodes := []*omnimeshv1.NodeEndpointInfo{
		{NodeId: "node-b", RouteName: "api-v1", Addr: serverAddr},
	}

	var server2Addr string
	if secondBackendPort > 0 {
		server2Ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen server2: %v", err)
		}
		server2Addr = server2Ln.Addr().String()
		server2Svc := proxy.NewServerSideService(server2Addr, serverTLS)
		server2Svc.SetNodeID("node-c")
		server2Svc.SetHTTPBridge(bridge)
		server2Svc.SetAuthorizer(engine)
		server2Svc.SetServices([]model.NodeServiceInfo{
			{
				Namespace: "prod",
				Name:      "api",
				ID:        "api-v2",
				Host:      "127.0.0.1",
				Port:      secondBackendPort,
				Protocol:  svcProto,
				Labels:    map[string]string{"version": "v1"},
			},
		})
		go func() { _ = server2Svc.Serve(ctx, server2Ln) }()
		targetNodes = append(targetNodes, &omnimeshv1.NodeEndpointInfo{
			NodeId: "node-c", RouteName: "api-v2", Addr: server2Addr,
		})
	}

	snap := &omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "api", MeshAddr: meshIPStr, Port: 8080, Protocol: svcProto},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{Namespace: "prod", ServiceName: "api", TargetNodes: targetNodes},
		},
	}

	router := proxy.NewRouterWithNode("node-a", "default")
	router.ApplySnapshot(snap)
	engine.ApplySnapshot(snap)

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	clientAddr := clientLn.Addr().String()

	clientSvc := proxy.NewClientSideService(clientAddr, "", &mockProcessor{
		pktInfo: &model.OriginalPacketInfo{PID: 4242, IP: meshIP, Port: 8080},
	})
	clientSvc.SetRouter(router)
	clientSvc.SetNodeID("node-a")
	clientSvc.SetHTTPBridge(bridge)
	clientSvc.SetWorkloadSVIDProvider(&mockSVIDProvider{
		tlsConfig: clientTLS,
		spiffeID:  callerSPIFFEID,
		errByPID:  make(map[uint64]error),
	})
	go func() { _ = clientSvc.Serve(ctx, clientLn) }()

	time.Sleep(40 * time.Millisecond)

	return &authzHarness{
		ctx:           ctx,
		cancel:        cancel,
		clientService: clientSvc,
		serverService: serverSvc,
		router:        router,
		authzEngine:   engine,
		httpBridge:    bridge,
		clientAddr:    clientAddr,
		serverAddr:    serverAddr,
		server2Addr:   server2Addr,
	}
}

func TestE2E_Authz_TCPDefaultDenyFailFastAndDynamicUpdates(t *testing.T) {
	var accepts1, accepts2 atomic.Int32
	startEcho := func(counter *atomic.Int32) (net.Listener, int) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen echo: %v", err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				counter.Add(1)
				go func(conn net.Conn) {
					defer conn.Close()
					_, _ = io.Copy(conn, conn)
				}(c)
			}
		}()
		return ln, ln.Addr().(*net.TCPAddr).Port
	}

	ln1, port1 := startEcho(&accepts1)
	defer ln1.Close()
	ln2, port2 := startEcho(&accepts2)
	defer ln2.Close()

	caller := "spiffe://omnimesh.local/ns/prod/sa/worker"
	h := startAuthzMTLSHarness(t, model.DefaultAuthorizationConfig(), caller, "tcp", port1, port2)

	// 1. Default deny: connection fails fast with 0 backend accepts across both endpoints.
	conn, err := net.Dial("tcp", h.clientAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_, _ = conn.Write([]byte("hello"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	if n, err := conn.Read(buf); n > 0 || err == nil {
		_ = conn.Close()
		t.Fatalf("expected closed connection under default deny, got n=%d err=%v", n, err)
	}
	_ = conn.Close()

	if accepts1.Load()+accepts2.Load() != 0 {
		t.Fatalf("expected 0 backend accepts when L4 denied, got %d+%d", accepts1.Load(), accepts2.Load())
	}
	if st := h.authzEngine.Stats(); st.DeniedTotal != 1 {
		t.Fatalf("expected exactly 1 L4 denial (0 retries on 403), got %d denials", st.DeniedTotal)
	}

	// 2. Push ALLOW policy via ScopeUpdate -> traffic succeeds.
	h.authzEngine.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_ADD,
		AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
			{
				Name:        "allow-worker",
				Namespace:   "prod",
				Action:      "ALLOW",
				Source:      &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "worker"},
				Destination: &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "api"},
			},
		},
	})

	conn2, err := net.Dial("tcp", h.clientAddr)
	if err != nil {
		t.Fatalf("dial proxy after allow: %v", err)
	}
	defer conn2.Close()
	_, _ = conn2.Write([]byte("ping"))
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadFull(conn2, buf[:4])
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("expected echoed ping after ALLOW update, got %q err=%v", string(buf[:n]), err)
	}

	// 3. Push DENY policy via ScopeUpdate -> traffic denied again.
	h.authzEngine.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_ADD,
		AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
			{
				Name:        "deny-worker",
				Namespace:   "prod",
				Action:      "DENY",
				Source:      &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "worker"},
				Destination: &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "api"},
			},
		},
	})

	conn3, err := net.Dial("tcp", h.clientAddr)
	if err != nil {
		t.Fatalf("dial proxy after deny: %v", err)
	}
	defer conn3.Close()
	_, _ = conn3.Write([]byte("blocked"))
	_ = conn3.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn3.Read(buf); n > 0 || err == nil {
		t.Fatalf("expected closed connection after DENY update, got n=%d err=%v", n, err)
	}
}

func TestE2E_Authz_HTTP1_L4Deny_L7Rules_KeepAliveRevocation_AndL4BypassGuard(t *testing.T) {
	var hits atomic.Int32
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backendLn.Close()
	backendSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("charged"))
		}),
	}
	go func() { _ = backendSrv.Serve(backendLn) }()
	defer backendSrv.Close()
	port := backendLn.Addr().(*net.TCPAddr).Port

	caller := "spiffe://omnimesh.local/ns/prod/sa/orders"

	// Part A: L4 default-deny returns HTTP/1.1 403 Forbidden via RespondForbidden.
	t.Run("L4 denied HTTP/1.1 caller receives 403 Forbidden", func(t *testing.T) {
		hits.Store(0)
		h := startAuthzMTLSHarness(t, model.DefaultAuthorizationConfig(), caller, "http", port, 0)
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", h.clientAddr)
				},
			},
		}
		defer client.CloseIdleConnections()

		resp, err := client.Get("http://api.prod.mesh/api/v1/charge")
		if err != nil {
			t.Fatalf("HTTP GET err: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || hits.Load() != 0 {
			t.Fatalf("expected 403 and 0 backend hits, got status=%d hits=%d", resp.StatusCode, hits.Load())
		}
	})

	// Part B: L7 rule enforcement, path traversal blocking, mid-connection keep-alive revocation, and L4 bypass prevention.
	t.Run("L7 HTTP/1.1 rules, mid-connection revocation, and L4 bypass block", func(t *testing.T) {
		hits.Store(0)
		cfg := model.AuthorizationConfig{
			Mode:      "strict",
			EnforceL7: true,
			LocalPolicies: []model.LocalAuthzPolicy{
				{
					Name:        "orders-charge-post",
					Namespace:   "prod",
					Action:      "allow",
					Source:      model.AuthzSelector{Namespace: "prod", Name: "orders"},
					Destination: model.AuthzSelector{Namespace: "prod", Name: "api"},
					Rules: []model.AuthzRule{
						{
							HTTP: &model.HTTPAuthzRule{
								Methods:      []string{"POST"},
								PathPrefixes: []string{"/api/v1/charge"},
							},
						},
					},
				},
			},
		}
		h := startAuthzMTLSHarness(t, cfg, caller, "http", port, 0)

		rawConn, err := net.Dial("tcp", h.clientAddr)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer rawConn.Close()
		br := bufio.NewReader(rawConn)

		// Req 1: POST /api/v1/charge -> 200 OK
		req1, _ := http.NewRequest("POST", "http://api.prod.mesh/api/v1/charge", nil)
		if err := req1.Write(rawConn); err != nil {
			t.Fatalf("write req1: %v", err)
		}
		resp1, err := http.ReadResponse(br, req1)
		if err != nil {
			t.Fatalf("read resp1: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp1.Body)
		_ = resp1.Body.Close()
		if resp1.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 on allowed POST, got %d", resp1.StatusCode)
		}

		// Req 2 on same keep-alive conn: DELETE /api/v1/charge -> 403 Forbidden (closes keep-alive)
		rawConn2, err := net.Dial("tcp", h.clientAddr)
		if err != nil {
			t.Fatalf("dial proxy 2: %v", err)
		}
		defer rawConn2.Close()
		br2 := bufio.NewReader(rawConn2)

		req2, _ := http.NewRequest("DELETE", "http://api.prod.mesh/api/v1/charge", nil)
		if err := req2.Write(rawConn2); err != nil {
			t.Fatalf("write req2: %v", err)
		}
		resp2, err := http.ReadResponse(br2, req2)
		if err != nil {
			t.Fatalf("read resp2: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp2.Body)
		_ = resp2.Body.Close()
		if resp2.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 on DELETE, got %d", resp2.StatusCode)
		}

		// Req 3: Path traversal /api/v1/charge/../admin -> 403 Forbidden
		rawConn3, err := net.Dial("tcp", h.clientAddr)
		if err != nil {
			t.Fatalf("dial proxy 3: %v", err)
		}
		defer rawConn3.Close()
		br3 := bufio.NewReader(rawConn3)

		req3, _ := http.NewRequest("POST", "http://api.prod.mesh/api/v1/charge/../admin", nil)
		if err := req3.Write(rawConn3); err != nil {
			t.Fatalf("write req3: %v", err)
		}
		resp3, err := http.ReadResponse(br3, req3)
		if err != nil {
			t.Fatalf("read resp3: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp3.Body)
		_ = resp3.Body.Close()
		if resp3.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 on path traversal, got %d", resp3.StatusCode)
		}

		// Mid-connection revocation on the still-open first keep-alive connection (rawConn):
		// push an emergency DENY policy, then send another valid POST on rawConn -> immediate 403!
		h.authzEngine.ApplyUpdate(&omnimeshv1.ScopeUpdate{
			Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_ADD,
			AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
				{
					Name:        "emergency-deny",
					Namespace:   "prod",
					Action:      "DENY",
					Source:      &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "orders"},
					Destination: &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "api"},
				},
			},
		})

		req4, _ := http.NewRequest("POST", "http://api.prod.mesh/api/v1/charge", nil)
		if err := req4.Write(rawConn); err != nil {
			t.Fatalf("write req4 on keep-alive: %v", err)
		}
		resp4, err := http.ReadResponse(br, req4)
		if err != nil {
			t.Fatalf("read resp4 on keep-alive: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp4.Body)
		_ = resp4.Body.Close()
		if resp4.StatusCode != http.StatusForbidden {
			t.Fatalf("expected immediate 403 on existing keep-alive connection after DENY update, got %d", resp4.StatusCode)
		}

		if hits.Load() != 1 {
			t.Fatalf("expected only 1 request to reach backend, got %d", hits.Load())
		}

		// L4 bypass attempt: send raw non-HTTP binary bytes after removing emergency DENY.
		h.authzEngine.ApplyUpdate(&omnimeshv1.ScopeUpdate{
			Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
			AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
				{Name: "emergency-deny", Namespace: "prod"},
			},
		})

		rawBypass, err := net.Dial("tcp", h.clientAddr)
		if err != nil {
			t.Fatalf("dial bypass: %v", err)
		}
		defer rawBypass.Close()
		_, _ = rawBypass.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05})
		_ = rawBypass.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		if n, err := rawBypass.Read(buf); n > 0 || err == nil {
			t.Fatalf("expected L4 bypass attempt to be closed without reaching backend, got n=%d err=%v", n, err)
		}
		if hits.Load() != 1 {
			t.Fatalf("expected backend hits to remain 1 after L4 bypass attempt, got %d", hits.Load())
		}
	})
}

func TestE2E_Authz_GRPC_L4AndL7PermissionDenied(t *testing.T) {
	var rpcHits atomic.Int32
	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen grpc: %v", err)
	}
	defer grpcLn.Close()

	gs := grpc.NewServer()
	gs.RegisterService(&grpc.ServiceDesc{
		ServiceName: "payment.v1.PaymentService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Charge",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					var req wrapperspb.StringValue
					if err := dec(&req); err != nil {
						return nil, err
					}
					rpcHits.Add(1)
					return &wrapperspb.StringValue{Value: "charged:" + req.Value}, nil
				},
			},
			{
				MethodName: "Refund",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					var req wrapperspb.StringValue
					if err := dec(&req); err != nil {
						return nil, err
					}
					rpcHits.Add(1)
					return &wrapperspb.StringValue{Value: "refunded:" + req.Value}, nil
				},
			},
		},
	}, struct{}{})
	go func() { _ = gs.Serve(grpcLn) }()
	defer gs.Stop()

	port := grpcLn.Addr().(*net.TCPAddr).Port
	caller := "spiffe://omnimesh.local/ns/prod/sa/orders"

	t.Run("L4 denial translates to gRPC PermissionDenied", func(t *testing.T) {
		rpcHits.Store(0)
		h := startAuthzMTLSHarness(t, model.DefaultAuthorizationConfig(), caller, "grpc", port, 0)

		conn, err := grpc.NewClient(
			"passthrough:///api.prod.mesh:8080",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", h.clientAddr)
			}),
		)
		if err != nil {
			t.Fatalf("grpc.NewClient: %v", err)
		}
		defer conn.Close()

		callCtx, callCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer callCancel()

		var reply wrapperspb.StringValue
		err = conn.Invoke(callCtx, "/payment.v1.PaymentService/Charge", &wrapperspb.StringValue{Value: "10"}, &reply)
		if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
			t.Fatalf("expected gRPC PermissionDenied on L4 denial, got err=%v", err)
		}
		if rpcHits.Load() != 0 {
			t.Fatalf("expected 0 backend RPC hits, got %d", rpcHits.Load())
		}
	})

	t.Run("L7 gRPC method rule allows Charge and denies Refund with PermissionDenied", func(t *testing.T) {
		rpcHits.Store(0)
		cfg := model.AuthorizationConfig{
			Mode:      "strict",
			EnforceL7: true,
			LocalPolicies: []model.LocalAuthzPolicy{
				{
					Name:        "grpc-charge-only",
					Namespace:   "prod",
					Action:      "allow",
					Source:      model.AuthzSelector{Namespace: "prod", Name: "orders"},
					Destination: model.AuthzSelector{Namespace: "prod", Name: "api"},
					Rules: []model.AuthzRule{
						{
							GRPC: &model.GRPCAuthzRule{
								Services: []string{"payment.v1.PaymentService"},
								Methods:  []string{"Charge"},
							},
						},
					},
				},
			},
		}
		h := startAuthzMTLSHarness(t, cfg, caller, "grpc", port, 0)

		conn, err := grpc.NewClient(
			"passthrough:///api.prod.mesh:8080",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", h.clientAddr)
			}),
		)
		if err != nil {
			t.Fatalf("grpc.NewClient: %v", err)
		}
		defer conn.Close()

		callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer callCancel()

		var reply wrapperspb.StringValue
		if err := conn.Invoke(callCtx, "/payment.v1.PaymentService/Charge", &wrapperspb.StringValue{Value: "42"}, &reply); err != nil {
			t.Fatalf("expected Charge RPC to succeed, got %v", err)
		}
		if reply.Value != "charged:42" {
			t.Fatalf("unexpected Charge reply: %q", reply.Value)
		}

		err = conn.Invoke(callCtx, "/payment.v1.PaymentService/Refund", &wrapperspb.StringValue{Value: "42"}, &reply)
		if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
			t.Fatalf("expected gRPC PermissionDenied on Refund, got err=%v", err)
		}
		if rpcHits.Load() != 1 {
			t.Fatalf("expected only 1 RPC to hit backend, got %d", rpcHits.Load())
		}
	})
}

func TestE2E_Authz_HBONEServerDirectNilAuthorizerBackwardsCompat(t *testing.T) {
	// Ensure hbone.NewServer without SetAuthorizer preserves backwards compatibility for legacy callers.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
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

	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen srv: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := hbone.NewServer(srvLn.Addr().String())
	go func() { _ = srv.Serve(ctx, srvLn) }()

	tun, err := hbone.NewClient().OpenTunnel(ctx, srvLn.Addr().String(), echoLn.Addr().String(), "", "unauth-test")
	if err != nil {
		t.Fatalf("expected nil-authorizer HBONE server to stay backwards compatible, got %v", err)
	}
	_ = tun.Close()
}
