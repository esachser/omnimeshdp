package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
	"github.com/esachser/omnimeshdp/internal/application/httpproxy"
	"github.com/esachser/omnimeshdp/internal/application/proxy"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type capturedHTTPRequest struct {
	Method  string              `json:"method"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Proto   string              `json:"proto"`
	Headers map[string][]string `json:"headers"`
}

type meshHarness struct {
	ctx           context.Context
	cancel        context.CancelFunc
	clientService *proxy.ClientSideService
	serverService *proxy.ServerSideService
	router        *proxy.Router
	clientAddr    string
	serverAddr    string
}

func startMTLSMeshHarness(
	t *testing.T,
	httpCfg model.HTTPConfig,
	spireDisabled bool,
	callerSPIFFEID string,
	svcProto string,
	backendPort int,
	customInterceptors ...outbound.HeaderInterceptor,
) *meshHarness {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	var clientTLS, serverTLS *tls.Config
	if !spireDisabled {
		clientTLS, serverTLS = setupTestMTLS(t, callerSPIFFEID, "spiffe://omnimesh.local/ns/omnimesh-system/sa/node-b")
	}

	bridge, err := httpproxy.NewBridge(httpCfg, spireDisabled, customInterceptors...)
	if err != nil {
		cancel()
		t.Fatalf("failed to create HTTP bridge: %v", err)
	}

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen server proxy: %v", err)
	}
	serverAddr := serverLn.Addr().String()

	serverSvc := proxy.NewServerSideService(serverAddr, serverTLS)
	serverSvc.SetNodeID("node-b")
	serverSvc.SetHTTPBridge(bridge)
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

	const meshIPStr = "10.210.0.10"
	const meshIP = uint32(10<<24 | 210<<16 | 0<<8 | 10)

	router := proxy.NewRouterWithNode("node-a", "default")
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{
				Namespace: "prod",
				Name:      "api",
				MeshAddr:  meshIPStr,
				Port:      8080,
				Protocol:  svcProto,
			},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "api",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{
						NodeId:    "node-b",
						RouteName: "api-v1",
						Addr:      serverAddr,
					},
				},
			},
		},
	})

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen client proxy: %v", err)
	}
	clientAddr := clientLn.Addr().String()

	mockProc := &mockProcessor{
		pktInfo: &model.OriginalPacketInfo{
			PID:  777,
			IP:   meshIP,
			Port: 8080,
		},
	}

	clientSvc := proxy.NewClientSideService(clientAddr, "", mockProc)
	clientSvc.SetRouter(router)
	clientSvc.SetNodeID("node-a")
	clientSvc.SetHTTPBridge(bridge)
	if !spireDisabled {
		clientSvc.SetWorkloadSVIDProvider(&mockSVIDProvider{
			tlsConfig: clientTLS,
			spiffeID:  callerSPIFFEID,
			errByPID:  make(map[uint64]error),
		})
	}
	go func() { _ = clientSvc.Serve(ctx, clientLn) }()

	time.Sleep(40 * time.Millisecond)

	h := &meshHarness{
		ctx:           ctx,
		cancel:        cancel,
		clientService: clientSvc,
		serverService: serverSvc,
		router:        router,
		clientAddr:    clientAddr,
		serverAddr:    serverAddr,
	}
	t.Cleanup(cancel)
	return h
}

func TestE2E_HTTP1_KeepAliveHeadersAndAntiSpoofing(t *testing.T) {
	const callerSPIFFE = "spiffe://omnimesh.local/ns/prod/sa/frontend"

	var mu sync.Mutex
	var captured []capturedHTTPRequest

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backendLn.Close()

	backendSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdrs := make(map[string][]string, len(r.Header))
			for k, v := range r.Header {
				hdrs[k] = append([]string(nil), v...)
			}
			mu.Lock()
			captured = append(captured, capturedHTTPRequest{
				Method:  r.Method,
				Host:    r.Host,
				Path:    r.URL.RequestURI(),
				Proto:   r.Proto,
				Headers: hdrs,
			})
			mu.Unlock()

			w.Header().Set("X-Backend-Handled", "true")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"ok": "1"})
		}),
	}
	go func() { _ = backendSrv.Serve(backendLn) }()
	defer backendSrv.Close()

	cfg := model.DefaultHTTPConfig()
	cfg.Tracing.EchoResponseHeaders = true
	cfg.Rules = []model.HeaderRule{
		{
			Name:      "inject-custom-req",
			Phase:     "request",
			Direction: "inbound",
			Action:    "set",
			Header:    "x-mesh-hop",
			Value:     "${source_node}->${dest_node}:${service.label.version}:${trace_id}",
		},
		{
			Name:      "inject-custom-resp",
			Phase:     "response",
			Direction: "inbound",
			Action:    "set_if_absent",
			Header:    "x-served-by",
			Value:     "${dest_node}/${node_service_id}",
		},
	}

	h := startMTLSMeshHarness(t, cfg, false, callerSPIFFE, "", backendLn.Addr().(*net.TCPAddr).Port)

	// Open a single persistent TCP connection to test HTTP/1.1 keep-alive + multiple Host headers.
	rawConn, err := net.Dial("tcp", h.clientAddr)
	if err != nil {
		t.Fatalf("dial client proxy: %v", err)
	}
	defer rawConn.Close()
	br := bufio.NewReader(rawConn)

	// Request 1: includes spoofed x-omnimesh-* headers that must be stripped and replaced.
	req1, _ := http.NewRequest("GET", "http://service-a.mesh/items?x=1", nil)
	req1.Header.Set("X-Omnimesh-Caller-Identity", "spiffe://evil.local/admin")
	req1.Header.Set("X-Omnimesh-Fake-Header", "smuggled")
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
		t.Fatalf("expected 200 on req1, got %d", resp1.StatusCode)
	}
	if resp1.Header.Get("X-Served-By") != "node-b/api-v1" {
		t.Fatalf("expected response rule X-Served-By 'node-b/api-v1', got %q", resp1.Header.Get("X-Served-By"))
	}
	if resp1.Header.Get("X-Request-Id") == "" || resp1.Header.Get("X-Trace-Id") == "" {
		t.Fatalf("expected echoed X-Request-Id and X-Trace-Id on response, got req=%q trace=%q",
			resp1.Header.Get("X-Request-Id"), resp1.Header.Get("X-Trace-Id"))
	}

	// Request 2 on the SAME persistent connection with a different Host and pre-existing traceparent.
	const explicitTP = "00-11111111111111111111111111111111-2222222222222222-01"
	req2, _ := http.NewRequest("POST", "http://service-b.mesh/orders", strings.NewReader("payload"))
	req2.Header.Set("Traceparent", explicitTP)
	req2.Header.Set("X-Request-Id", "caller-req-99")
	if err := req2.Write(rawConn); err != nil {
		t.Fatalf("write req2: %v", err)
	}
	resp2, err := http.ReadResponse(br, req2)
	if err != nil {
		t.Fatalf("read resp2: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on req2, got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("X-Request-Id") != "caller-req-99" {
		t.Fatalf("expected echoed caller-req-99, got %q", resp2.Header.Get("X-Request-Id"))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 2 {
		t.Fatalf("expected 2 backend requests, got %d", len(captured))
	}

	c1 := captured[0]
	h1 := http.Header(c1.Headers)
	if c1.Proto != "HTTP/1.1" || c1.Host != "service-a.mesh" {
		t.Fatalf("expected HTTP/1.1 with Host service-a.mesh, got proto=%s host=%s", c1.Proto, c1.Host)
	}
	if h1.Get("X-Omnimesh-Caller-Identity") != callerSPIFFE {
		t.Fatalf("expected verified mTLS identity %q, got %q", callerSPIFFE, h1.Get("X-Omnimesh-Caller-Identity"))
	}
	if h1.Get("X-Omnimesh-Fake-Header") != "" {
		t.Fatalf("expected spoofed header stripped, got %q", h1.Get("X-Omnimesh-Fake-Header"))
	}
	if h1.Get("X-Omnimesh-Source-Node") != "node-a" || h1.Get("X-Omnimesh-Dest-Node") != "node-b" {
		t.Fatalf("unexpected node headers: src=%q dst=%q", h1.Get("X-Omnimesh-Source-Node"), h1.Get("X-Omnimesh-Dest-Node"))
	}
	if h1.Get("X-Omnimesh-Dest-Service") != "prod/api" || h1.Get("X-Omnimesh-Node-Service-Id") != "api-v1" {
		t.Fatalf("unexpected service headers: svc=%q id=%q", h1.Get("X-Omnimesh-Dest-Service"), h1.Get("X-Omnimesh-Node-Service-Id"))
	}
	if h1.Get("Traceparent") == "" || h1.Get("X-Request-Id") == "" {
		t.Fatalf("expected generated traceparent and x-request-id on backend")
	}
	if !strings.HasPrefix(h1.Get("X-Mesh-Hop"), "node-a->node-b:v1:") {
		t.Fatalf("unexpected rule header x-mesh-hop: %q", h1.Get("X-Mesh-Hop"))
	}

	c2 := captured[1]
	h2 := http.Header(c2.Headers)
	if c2.Host != "service-b.mesh" || h2.Get("Traceparent") != explicitTP || h2.Get("X-Request-Id") != "caller-req-99" {
		t.Fatalf("req2 correlation/host mismatch: host=%s tp=%s rid=%s", c2.Host, h2.Get("Traceparent"), h2.Get("X-Request-Id"))
	}
}

func TestE2E_HTTP1_StreamingSSEAnd101Upgrade(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backendLn.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, event := range []string{"data: one\n\n", "data: two\n\n"} {
			_, _ = io.WriteString(w, event)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(25 * time.Millisecond)
		}
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Traceparent") == "" || r.Header.Get("X-Omnimesh-Dest-Service") != "prod/api" {
			http.Error(w, "missing injected mesh headers on upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = brw.Flush()
		_, _ = io.Copy(conn, conn)
	})

	backendSrv := &http.Server{Handler: mux}
	go func() { _ = backendSrv.Serve(backendLn) }()
	defer backendSrv.Close()

	h := startMTLSMeshHarness(t, model.DefaultHTTPConfig(), false, "spiffe://omnimesh.local/ns/prod/sa/ws-client", "http1", backendLn.Addr().(*net.TCPAddr).Port)

	t.Run("SSE streaming flushes immediately without waiting for EOF", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", h.clientAddr)
				},
			},
		}
		defer client.CloseIdleConnections()

		resp, err := client.Get("http://api.prod.mesh/sse")
		if err != nil {
			t.Fatalf("GET /sse: %v", err)
		}
		defer resp.Body.Close()

		br := bufio.NewReader(resp.Body)
		firstLine, err := br.ReadString('\n')
		if err != nil || firstLine != "data: one\n" {
			t.Fatalf("expected immediate first SSE chunk, got %q err=%v", firstLine, err)
		}
	})

	t.Run("101 Switching Protocols upgrades to raw bidirectional stream", func(t *testing.T) {
		conn, err := net.Dial("tcp", h.clientAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		reqStr := "GET /ws HTTP/1.1\r\nHost: api.prod.mesh\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
		if _, err := io.WriteString(conn, reqStr); err != nil {
			t.Fatalf("write upgrade req: %v", err)
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read 101 resp: %v", err)
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("expected 101 Switching Protocols, got %d", resp.StatusCode)
		}

		msg := []byte("ws-frame-hello-mesh")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write ws frame: %v", err)
		}
		buf := make([]byte, len(msg))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(br, buf); err != nil {
			t.Fatalf("read ws frame: %v", err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("ws frame mismatch: got %q, want %q", string(buf), string(msg))
		}
	})
}

func TestE2E_HTTP2_GRPCStreamingTrailersAndCancellation(t *testing.T) {
	const callerSPIFFE = "spiffe://omnimesh.local/ns/prod/sa/grpc-caller"

	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen grpc: %v", err)
	}
	defer grpcLn.Close()

	var cancelObserved atomic.Bool
	var seenHeadersMu sync.Mutex
	var lastMD metadata.MD

	gs := grpc.NewServer()
	gs.RegisterService(&grpc.ServiceDesc{
		ServiceName: "test.MeshEcho",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Unary",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					var req wrapperspb.StringValue
					if err := dec(&req); err != nil {
						return nil, err
					}
					if md, ok := metadata.FromIncomingContext(ctx); ok {
						seenHeadersMu.Lock()
						lastMD = md.Copy()
						seenHeadersMu.Unlock()
					}
					_ = grpc.SetTrailer(ctx, metadata.Pairs("x-grpc-trailer", "trailer-ok"))
					return &wrapperspb.StringValue{Value: "echo:" + req.Value}, nil
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Bidi",
				ServerStreams: true,
				ClientStreams: true,
				Handler: func(srv any, stream grpc.ServerStream) error {
					for {
						var msg wrapperspb.StringValue
						err := stream.RecvMsg(&msg)
						if errors.Is(err, io.EOF) {
							stream.SetTrailer(metadata.Pairs("x-stream-trailer", "done"))
							return nil
						}
						if err != nil {
							if stream.Context().Err() != nil {
								cancelObserved.Store(true)
							}
							return err
						}
						if msg.Value == "wait-cancel" {
							<-stream.Context().Done()
							cancelObserved.Store(true)
							return status.Error(codes.Canceled, "client canceled")
						}
						if err := stream.SendMsg(&wrapperspb.StringValue{Value: "stream:" + msg.Value}); err != nil {
							return err
						}
					}
				},
			},
		},
	}, struct{}{})

	go func() { _ = gs.Serve(grpcLn) }()
	defer gs.Stop()

	cfg := model.DefaultHTTPConfig()
	cfg.Rules = []model.HeaderRule{
		{
			Name:      "grpc-custom",
			Phase:     "request",
			Direction: "inbound",
			Action:    "set",
			Header:    "x-grpc-injected",
			Value:     "${caller_identity}|${trace_id}",
		},
	}

	h := startMTLSMeshHarness(t, cfg, false, callerSPIFFE, "grpc", grpcLn.Addr().(*net.TCPAddr).Port)

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

	// 1. Unary gRPC + metadata inspection + trailing header verification
	var trailerMD metadata.MD
	var reply wrapperspb.StringValue
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()

	if err := conn.Invoke(callCtx, "/test.MeshEcho/Unary", &wrapperspb.StringValue{Value: "ping"}, &reply, grpc.Trailer(&trailerMD)); err != nil {
		t.Fatalf("unary gRPC invoke failed: %v", err)
	}
	if reply.Value != "echo:ping" {
		t.Fatalf("unexpected unary reply: %q", reply.Value)
	}
	if vals := trailerMD.Get("x-grpc-trailer"); len(vals) != 1 || vals[0] != "trailer-ok" {
		t.Fatalf("expected gRPC trailer x-grpc-trailer='trailer-ok', got %v", trailerMD)
	}

	seenHeadersMu.Lock()
	if got := lastMD.Get("x-omnimesh-caller-identity"); len(got) != 1 || got[0] != callerSPIFFE {
		seenHeadersMu.Unlock()
		t.Fatalf("expected verified identity %q in gRPC metadata, got %v", callerSPIFFE, got)
	}
	if len(lastMD.Get("traceparent")) == 0 || len(lastMD.Get("x-request-id")) == 0 {
		seenHeadersMu.Unlock()
		t.Fatalf("expected traceparent and x-request-id in gRPC metadata: %v", lastMD)
	}
	if got := lastMD.Get("x-grpc-injected"); len(got) != 1 || !strings.HasPrefix(got[0], callerSPIFFE+"|") {
		seenHeadersMu.Unlock()
		t.Fatalf("expected custom rule header in gRPC metadata, got %v", got)
	}
	seenHeadersMu.Unlock()

	// 2. Concurrent multiplexed bidirectional streaming + trailers
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			st, err := conn.NewStream(callCtx, &grpc.StreamDesc{StreamName: "Bidi", ServerStreams: true, ClientStreams: true}, "/test.MeshEcho/Bidi")
			if err != nil {
				t.Errorf("stream %d open: %v", idx, err)
				return
			}
			msg := fmt.Sprintf("m-%d", idx)
			if err := st.SendMsg(&wrapperspb.StringValue{Value: msg}); err != nil {
				t.Errorf("stream %d send: %v", idx, err)
				return
			}
			if err := st.CloseSend(); err != nil {
				t.Errorf("stream %d closeSend: %v", idx, err)
				return
			}
			var out wrapperspb.StringValue
			if err := st.RecvMsg(&out); err != nil || out.Value != "stream:"+msg {
				t.Errorf("stream %d recv: out=%q err=%v", idx, out.Value, err)
				return
			}
			if err := st.RecvMsg(&out); !errors.Is(err, io.EOF) {
				t.Errorf("stream %d expected EOF, got %v", idx, err)
				return
			}
			if tr := st.Trailer().Get("x-stream-trailer"); len(tr) != 1 || tr[0] != "done" {
				t.Errorf("stream %d missing stream trailer: %v", idx, st.Trailer())
			}
		}(i)
	}
	wg.Wait()

	// 3. Client stream cancellation propagates RST_STREAM end-to-end
	cancelStreamCtx, cancelStream := context.WithCancel(context.Background())
	st, err := conn.NewStream(cancelStreamCtx, &grpc.StreamDesc{StreamName: "Bidi", ServerStreams: true, ClientStreams: true}, "/test.MeshEcho/Bidi")
	if err != nil {
		t.Fatalf("open cancel stream: %v", err)
	}
	if err := st.SendMsg(&wrapperspb.StringValue{Value: "wait-cancel"}); err != nil {
		t.Fatalf("send wait-cancel: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	cancelStream()

	deadline := time.Now().Add(2 * time.Second)
	for !cancelObserved.Load() && time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond)
	}
	if !cancelObserved.Load() {
		t.Fatalf("expected server stream to observe client cancellation via RST_STREAM")
	}
}

type h2CustomInterceptor struct{}

func (i *h2CustomInterceptor) Name() string { return "tenant-guard" }
func (i *h2CustomInterceptor) OnRequest(_ context.Context, _ *model.ConnectionMeta, req *model.HTTPRequestContext) error {
	if req.Headers.Get("X-Block") == "1" {
		return &domain.HTTPRejectError{StatusCode: http.StatusForbidden, Message: "blocked-by-hook"}
	}
	return nil
}
func (i *h2CustomInterceptor) OnResponse(_ context.Context, _ *model.ConnectionMeta, _ *model.HTTPRequestContext, resp *model.HTTPResponseContext) error {
	resp.Headers.Set("X-Hook-Resp", "ok")
	return nil
}

func TestE2E_HTTP2_CustomInterceptorRejection(t *testing.T) {
	var hits atomic.Int32
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backendLn.Close()

	protos := new(http.Protocols)
	protos.SetUnencryptedHTTP2(true)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
		HTTP2:     &http.HTTP2Config{},
		Protocols: protos,
	}
	go func() { _ = srv.Serve(backendLn) }()
	defer srv.Close()

	h := startMTLSMeshHarness(t, model.DefaultHTTPConfig(), true, "", "h2c", backendLn.Addr().(*net.TCPAddr).Port, &h2CustomInterceptor{})

	h2Client := &http.Client{
		Transport: &http.Transport{
			Protocols:         protos,
			HTTP2:             &http.HTTP2Config{},
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", h.clientAddr)
			},
		},
	}
	defer h2Client.CloseIdleConnections()

	reqBlocked, _ := http.NewRequest("GET", "http://api.prod.mesh/blocked", nil)
	reqBlocked.Header.Set("X-Block", "1")
	respBlocked, err := h2Client.Do(reqBlocked)
	if err != nil {
		t.Fatalf("h2 blocked req err: %v", err)
	}
	_ = respBlocked.Body.Close()
	if respBlocked.StatusCode != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("expected 403 and 0 backend hits, got status=%d hits=%d", respBlocked.StatusCode, hits.Load())
	}

	respAllowed, err := h2Client.Get("http://api.prod.mesh/ok")
	if err != nil {
		t.Fatalf("h2 allowed req err: %v", err)
	}
	_ = respAllowed.Body.Close()
	if respAllowed.StatusCode != http.StatusOK || respAllowed.Header.Get("X-Hook-Resp") != "ok" || hits.Load() != 1 {
		t.Fatalf("expected 200 with X-Hook-Resp=ok, got status=%d hdr=%q hits=%d",
			respAllowed.StatusCode, respAllowed.Header.Get("X-Hook-Resp"), hits.Load())
	}
}

func TestE2E_L4Fallback_TLSAndServerSpeaksFirstAndToggleMatrix(t *testing.T) {
	t.Run("application-level TLS passes transparently through HBONE", func(t *testing.T) {
		tlsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("tls-end-to-end-ok"))
		}))
		defer tlsBackend.Close()

		backendPort := tlsBackend.Listener.Addr().(*net.TCPAddr).Port
		h := startMTLSMeshHarness(t, model.DefaultHTTPConfig(), false, "spiffe://omnimesh.local/ns/prod/sa/tls-app", "", backendPort)

		appClient := tlsBackend.Client()
		appTr := appClient.Transport.(*http.Transport).Clone()
		appTr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", h.clientAddr)
		}
		appClient.Transport = appTr

		resp, err := appClient.Get("https://127.0.0.1/secure")
		if err != nil {
			t.Fatalf("app TLS GET failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "tls-end-to-end-ok" {
			t.Fatalf("unexpected TLS response: status=%d body=%q", resp.StatusCode, string(body))
		}
	})

	t.Run("server-speaks-first TCP banner passes transparently under auto and tcp", func(t *testing.T) {
		bannerLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen banner: %v", err)
		}
		defer bannerLn.Close()

		go func() {
			for {
				c, err := bannerLn.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					_, _ = io.WriteString(conn, "220 READY\n")
					_, _ = io.Copy(conn, conn)
				}(c)
			}
		}()

		cfg := model.DefaultHTTPConfig()
		cfg.SniffTimeout = "40ms"
		h := startMTLSMeshHarness(t, cfg, true, "", "", bannerLn.Addr().(*net.TCPAddr).Port)

		conn, err := net.Dial("tcp", h.clientAddr)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		banner, err := br.ReadString('\n')
		if err != nil || banner != "220 READY\n" {
			t.Fatalf("expected server-speaks-first banner, got %q err=%v", banner, err)
		}
		_, _ = io.WriteString(conn, "PING\n")
		echo, err := br.ReadString('\n')
		if err != nil || echo != "PING\n" {
			t.Fatalf("expected echo PING, got %q err=%v", echo, err)
		}
	})

	t.Run("toggle matrix outbound-only, inbound-only, and disabled", func(t *testing.T) {
		backendLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer backendLn.Close()

		var lastHeaders http.Header
		var mu sync.Mutex
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				lastHeaders = r.Header.Clone()
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
			}),
		}
		go func() { _ = srv.Serve(backendLn) }()
		defer srv.Close()
		port := backendLn.Addr().(*net.TCPAddr).Port

		cases := []struct {
			name            string
			outboundEnabled bool
			inboundEnabled  bool
			globalEnabled   bool
			wantTrace       bool
			wantDestNode    bool
		}{
			{"outbound_only", true, false, true, true, true},
			{"inbound_only", false, true, true, true, true},
			{"globally_disabled", true, true, false, false, false},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cfg := model.DefaultHTTPConfig()
				cfg.Enabled = tc.globalEnabled
				cfg.Outbound.Enabled = tc.outboundEnabled
				cfg.Inbound.Enabled = tc.inboundEnabled

				h := startMTLSMeshHarness(t, cfg, false, "spiffe://omnimesh.local/ns/prod/sa/t", "http1", port)
				client := &http.Client{
					Transport: &http.Transport{
						DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
							return (&net.Dialer{}).DialContext(ctx, "tcp", h.clientAddr)
						},
					},
				}
				defer client.CloseIdleConnections()

				resp, err := client.Get("http://api.prod.mesh/check")
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				_ = resp.Body.Close()

				mu.Lock()
				got := lastHeaders
				mu.Unlock()
				if hasTP := got.Get("Traceparent") != ""; hasTP != tc.wantTrace {
					t.Fatalf("Traceparent presence=%v, want %v", hasTP, tc.wantTrace)
				}
				if hasDest := got.Get("X-Omnimesh-Dest-Node") != ""; hasDest != tc.wantDestNode {
					t.Fatalf("X-Omnimesh-Dest-Node presence=%v, want %v", hasDest, tc.wantDestNode)
				}
			})
		}
	})
}

func TestE2E_HTTP1_502FailoverRetriesWithHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, closedPort := reserveClosedPort(t)

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backendLn.Close()
	backendPort := backendLn.Addr().(*net.TCPAddr).Port

	var seenTrace string
	var mu sync.Mutex
	backendSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seenTrace = r.Header.Get("Traceparent")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("recovered-http1"))
		}),
	}
	go func() { _ = backendSrv.Serve(backendLn) }()
	defer backendSrv.Close()

	bridge, err := httpproxy.NewBridge(model.DefaultHTTPConfig(), true)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}

	srvALn, _ := net.Listen("tcp", "127.0.0.1:0")
	hboneA := hbone.NewServer(srvALn.Addr().String())
	hboneA.SetNodeID("node-dead")
	hboneA.SetHTTPBridge(bridge)
	hboneA.SetServices([]model.NodeServiceInfo{
		{Namespace: "prod", Name: "web", ID: "web-a", Host: "127.0.0.1", Port: closedPort, Protocol: "http1"},
	})
	go func() { _ = hboneA.Serve(ctx, srvALn) }()

	srvBLn, _ := net.Listen("tcp", "127.0.0.1:0")
	hboneB := hbone.NewServer(srvBLn.Addr().String())
	hboneB.SetNodeID("node-live")
	hboneB.SetHTTPBridge(bridge)
	hboneB.SetServices([]model.NodeServiceInfo{
		{Namespace: "prod", Name: "web", ID: "web-b", Host: "127.0.0.1", Port: backendPort, Protocol: "http1"},
	})
	go func() { _ = hboneB.Serve(ctx, srvBLn) }()

	const meshIPStr = "10.220.0.5"
	const meshIP = uint32(10<<24 | 220<<16 | 0<<8 | 5)

	router := proxy.NewRouterWithNode("node-caller", "default")
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "web", MeshAddr: meshIPStr, Port: 8080, Protocol: "http1"},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "web",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "node-dead", RouteName: "web-a", Addr: srvALn.Addr().String()},
					{NodeId: "node-live", RouteName: "web-b", Addr: srvBLn.Addr().String()},
				},
			},
		},
		TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
			{
				Name:                   "rr",
				Namespace:              "prod",
				TargetServiceNamespace: "prod",
				TargetServiceName:      "web",
				LoadBalancer: &omnimeshv1.LoadBalancerPolicyInfo{
					Algorithm: omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED_ROUND_ROBIN,
				},
			},
		},
	})

	clientLn, _ := net.Listen("tcp", "127.0.0.1:0")
	cs := proxy.NewClientSideService(clientLn.Addr().String(), "", &mockProcessor{
		pktInfo: &model.OriginalPacketInfo{PID: 1, IP: meshIP, Port: 8080},
	})
	cs.SetRouter(router)
	cs.SetNodeID("node-caller")
	cs.SetHTTPBridge(bridge)
	go func() { _ = cs.Serve(ctx, clientLn) }()
	time.Sleep(40 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", clientLn.Addr().String())
			},
		},
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get("http://web.prod.mesh/hello")
	if err != nil {
		t.Fatalf("expected transparent 502 failover for HTTP/1.1 request, got error: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK || string(body) != "recovered-http1" {
		t.Fatalf("unexpected response after 502 failover: status=%d body=%q", resp.StatusCode, string(body))
	}
	mu.Lock()
	if seenTrace == "" {
		mu.Unlock()
		t.Fatalf("expected traceparent injected on retried HTTP/1.1 request")
	}
	mu.Unlock()
}
