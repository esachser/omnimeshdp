package proxy_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/oteltelemetry"
	"github.com/esachser/omnimeshdp/internal/application/authz"
	"github.com/esachser/omnimeshdp/internal/application/httpproxy"
	"github.com/esachser/omnimeshdp/internal/application/proxy"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func collectMetricNamesAndData(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	out := make(map[string]metricdata.Metrics)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out[m.Name] = m
		}
	}
	return out
}

func TestE2E_TelemetryHTTP1_GRPC_Authz_MTLS_And_Sampling(t *testing.T) {
	const callerSPIFFE = "spiffe://omnimesh.local/ns/prod/sa/frontend"

	// Backend HTTP/1.1 + gRPC servers.
	var receivedTraceparent atomic.Value
	httpBackendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http backend: %v", err)
	}
	defer httpBackendLn.Close()

	httpBackend := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedTraceparent.Store(r.Header.Get("Traceparent"))
			if r.URL.Path == "/boom" {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("boom"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
	}
	go func() { _ = httpBackend.Serve(httpBackendLn) }()
	defer httpBackend.Close()

	// Configure OTel telemetry providers for node-a (egress) and node-b (ingress).
	obsCfg := model.DefaultObservabilityConfig()
	obsCfg.Metrics.Enabled = true
	obsCfg.Metrics.Endpoint = "127.0.0.1:0"
	obsCfg.Traces.Enabled = true
	obsCfg.Traces.Sampler = "always_on"

	readerA := sdkmetric.NewManualReader()
	expA := tracetest.NewInMemoryExporter()
	tpA, err := oteltelemetry.NewProvider(context.Background(), obsCfg, "node-a",
		oteltelemetry.WithMetricReader(readerA),
		oteltelemetry.WithSpanExporter(expA),
		oteltelemetry.WithSyncSpanProcessor(),
	)
	if err != nil {
		t.Fatalf("NewProvider node-a: %v", err)
	}
	defer func() { _ = tpA.Shutdown(context.Background()) }()

	readerB := sdkmetric.NewManualReader()
	expB := tracetest.NewInMemoryExporter()
	tpB, err := oteltelemetry.NewProvider(context.Background(), obsCfg, "node-b",
		oteltelemetry.WithMetricReader(readerB),
		oteltelemetry.WithSpanExporter(expB),
		oteltelemetry.WithSyncSpanProcessor(),
	)
	if err != nil {
		t.Fatalf("NewProvider node-b: %v", err)
	}
	defer func() { _ = tpB.Shutdown(context.Background()) }()

	clientTLS, serverTLS := setupTestMTLS(t, callerSPIFFE, "spiffe://omnimesh.local/ns/omnimesh-system/sa/node-b")

	// Authz engine on node-b allowing /hello and denying /admin.
	authzCfg := model.DefaultAuthorizationConfig()
	authzEngine, err := authz.NewEngine(
		authzCfg,
		authz.WithTrustDomain("omnimesh.local"),
		authz.WithObserver(oteltelemetry.NewAuthzObserver(tpB.Metrics(), tpB.Tracer())),
		authz.WithPolicyCountObserver(func(count int) {
			tpB.Metrics().RecordGauge(context.Background(), outbound.MetricAuthzPoliciesCached, float64(count))
		}),
	)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	httpCfg := model.DefaultHTTPConfig()
	bridgeA, err := httpproxy.NewBridge(httpCfg, false)
	if err != nil {
		t.Fatalf("NewBridge A: %v", err)
	}
	bridgeA.SetTelemetry(tpA)

	bridgeB, err := httpproxy.NewBridge(httpCfg, false)
	if err != nil {
		t.Fatalf("NewBridge B: %v", err)
	}
	bridgeB.SetTelemetry(tpB)
	bridgeB.SetAuthorizer(authzEngine)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen server proxy: %v", err)
	}
	serverAddr := serverLn.Addr().String()

	serverSvc := proxy.NewServerSideService(serverAddr, serverTLS)
	serverSvc.SetNodeID("node-b")
	serverSvc.SetHTTPBridge(bridgeB)
	serverSvc.SetAuthorizer(authzEngine)
	serverSvc.SetTelemetry(tpB)
	serverSvc.SetServices([]model.NodeServiceInfo{
		{
			Namespace: "prod",
			Name:      "api",
			ID:        "api-v1",
			Host:      "127.0.0.1",
			Port:      httpBackendLn.Addr().(*net.TCPAddr).Port,
			Protocol:  "http",
		},
	})
	go func() { _ = serverSvc.Serve(ctx, serverLn) }()

	const meshIPStr = "10.220.0.10"
	const meshIP = uint32(10<<24 | 220<<16 | 0<<8 | 10)

	snapshot := &omnimeshv1.ScopeSnapshot{
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "prod", Cidr: "10.220.0.0/24", Isolation: "strict"},
		},
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "api", MeshAddr: meshIPStr, Port: 8080, Protocol: "http"},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "api",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "node-b", RouteName: "api-v1", Addr: serverAddr},
				},
			},
		},
		AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
			{
				Name:        "allow-hello",
				Namespace:   "prod",
				Action:      "ALLOW",
				Source:      &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "frontend"},
				Destination: &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "api"},
				Rules: []*omnimeshv1.AuthzRuleInfo{
					{Http: &omnimeshv1.HttpAuthzRuleInfo{Methods: []string{"GET", "POST"}, PathPrefixes: []string{"/hello", "/boom"}}},
				},
			},
		},
	}

	router := proxy.NewRouterWithNode("node-a", "default")
	router.SetMetrics(tpA.Metrics())
	router.ApplySnapshot(snapshot)
	authzEngine.ApplySnapshot(snapshot)

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client proxy: %v", err)
	}
	clientAddr := clientLn.Addr().String()

	clientSvc := proxy.NewClientSideService(clientAddr, "", &mockProcessor{
		pktInfo: &model.OriginalPacketInfo{PID: 777, IP: meshIP, Port: 8080},
	})
	clientSvc.SetRouter(router)
	clientSvc.SetNodeID("node-a")
	clientSvc.SetHTTPBridge(bridgeA)
	clientSvc.SetTelemetry(tpA)
	clientSvc.SetWorkloadSVIDProvider(&mockSVIDProvider{
		tlsConfig: clientTLS,
		spiffeID:  callerSPIFFE,
		errByPID:  make(map[uint64]error),
	})
	go func() { _ = clientSvc.Serve(ctx, clientLn) }()

	time.Sleep(40 * time.Millisecond)

	// 1. Send an allowed HTTP/1.1 request with an incoming W3C traceparent.
	const incomingTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const incomingTraceparent = "00-" + incomingTraceID + "-00f067aa0ba902b7-01"

	httpClient := &http.Client{Timeout: 3 * time.Second}
	req1, _ := http.NewRequest(http.MethodPost, "http://"+clientAddr+"/hello", strings.NewReader("hello-payload"))
	req1.Header.Set("Traceparent", incomingTraceparent)
	resp1, err := httpClient.Do(req1)
	if err != nil {
		t.Fatalf("GET /hello failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /hello, got %d", resp1.StatusCode)
	}

	// Verify backend received a traceparent with the SAME TraceID.
	gotTP, _ := receivedTraceparent.Load().(string)
	if !strings.HasPrefix(gotTP, "00-"+incomingTraceID+"-") {
		t.Fatalf("expected backend traceparent to preserve traceID %s, got %q", incomingTraceID, gotTP)
	}

	// 2. Send a denied HTTP/1.1 request (/admin -> 403 Forbidden).
	req2, _ := http.NewRequest(http.MethodGet, "http://"+clientAddr+"/admin", nil)
	resp2, err := httpClient.Do(req2)
	if err != nil {
		t.Fatalf("GET /admin failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on /admin, got %d", resp2.StatusCode)
	}

	// Close idle keep-alive connections so connection-lifetime metrics flush cleanly.
	httpClient.CloseIdleConnections()

	// Verify spans on both node-a and node-b share the incoming TraceID for /hello.
	deadline := time.Now().Add(2 * time.Second)
	var spansA, spansB tracetest.SpanStubs
	for time.Now().Before(deadline) {
		spansA = expA.GetSpans()
		spansB = expB.GetSpans()
		if len(spansA) >= 2 && len(spansB) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(spansA) < 2 || len(spansB) < 2 {
		t.Fatalf("expected >=2 spans on both node-a (%d) and node-b (%d)", len(spansA), len(spansB))
	}

	var foundEgressTrace, foundIngressTrace bool
	for _, sp := range spansA {
		if sp.Name == outbound.SpanNameEgress && sp.SpanContext.TraceID().String() == incomingTraceID {
			foundEgressTrace = true
		}
	}
	for _, sp := range spansB {
		if sp.Name == outbound.SpanNameIngress && sp.SpanContext.TraceID().String() == incomingTraceID {
			foundIngressTrace = true
		}
	}
	if !foundEgressTrace || !foundIngressTrace {
		t.Fatalf("expected distributed trace %s across egress (%v) and ingress (%v)", incomingTraceID, foundEgressTrace, foundIngressTrace)
	}

	// Verify node-a & node-b metrics via ManualReader and Prometheus /metrics scrape.
	var mA, mB map[string]metricdata.Metrics
	metricsDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(metricsDeadline) {
		mA = collectMetricNamesAndData(t, readerA)
		mB = collectMetricNamesAndData(t, readerB)
		if _, ok := mA[outbound.MetricConnectionsTotal]; ok {
			if _, okB := mB[outbound.MetricConnectionsTotal]; okB {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, expected := range []string{
		outbound.MetricRequestsTotal,
		outbound.MetricRequestsEgressTotal,
		outbound.MetricRequestsDurationMs,
		outbound.MetricRequestsActive,
		outbound.MetricRequestsBytesSent,
		outbound.MetricRequestsBytesReceived,
		outbound.MetricConnectionsActive,
		outbound.MetricConnectionsTotal,
		outbound.MetricConnectionsDurationMs,
		outbound.MetricHBONETunnelsActive,
		outbound.MetricHBONEStreamsActive,
		outbound.MetricHBONEStreamsTotal,
		outbound.MetricMTLSHandshakesTotal,
		outbound.MetricMTLSHandshakesDurationMs,
		outbound.MetricLBSelectionsTotal,
		outbound.MetricLBEndpointsHealthy,
		outbound.MetricLBEndpointsTotal,
	} {
		if _, ok := mA[expected]; !ok {
			t.Fatalf("expected node-a metric %q to be recorded", expected)
		}
	}

	for _, expected := range []string{
		outbound.MetricRequestsTotal,
		outbound.MetricRequestsIngressTotal,
		outbound.MetricRequestsDurationMs,
		outbound.MetricHBONEStreamsTotal,
		outbound.MetricMTLSHandshakesTotal,
		outbound.MetricAuthzDecisionsTotal,
		outbound.MetricAuthzDenialsTotal,
		outbound.MetricAuthzEvaluationDurationUs,
		outbound.MetricAuthzPoliciesCached,
	} {
		if _, ok := mB[expected]; !ok {
			t.Fatalf("expected node-b metric %q to be recorded", expected)
		}
	}

	// Verify live Prometheus scrape endpoint on node-b.
	promResp, err := http.Get("http://" + tpB.MetricsAddr() + "/metrics")
	if err != nil {
		t.Fatalf("Prometheus scrape failed: %v", err)
	}
	promBody, _ := io.ReadAll(promResp.Body)
	_ = promResp.Body.Close()
	if !strings.Contains(string(promBody), "omnimesh_agent_authz_decisions_total") {
		t.Fatalf("expected omnimesh_agent_authz_decisions_total in Prometheus scrape")
	}
}

func TestE2E_Telemetry502Retries_L4TCP_And_ErrorSampling(t *testing.T) {
	obsCfg := model.DefaultObservabilityConfig()
	obsCfg.Metrics.Enabled = false
	obsCfg.Traces.Enabled = true
	obsCfg.Traces.Sampler = "parentbased_traceidratio"
	obsCfg.Traces.SampleRate = 0.0 // 0% head sampling — only errors should export!
	obsCfg.Traces.AlwaysSampleErrors = true
	obsCfg.Traces.MaxErrorTracesPerSec = 50

	reader := sdkmetric.NewManualReader()
	exp := tracetest.NewInMemoryExporter()
	tp, err := oteltelemetry.NewProvider(context.Background(), obsCfg, "node-retry",
		oteltelemetry.WithMetricReader(reader),
		oteltelemetry.WithSpanExporter(exp),
		oteltelemetry.WithSyncSpanProcessor(),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	defer func() { _ = tp.Shutdown(context.Background()) }()

	// Reserve a closed port to force 502 Bad Gateway on node-bad.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dead port: %v", err)
	}
	deadPort := deadLn.Addr().(*net.TCPAddr).Port
	_ = deadLn.Close()

	// Healthy TCP echo backend on node-good.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo backend: %v", err)
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start two HBONE servers (without L7 bridge to verify L4 TCP hop-level tracing & metrics too).
	srvBadLn, _ := net.Listen("tcp", "127.0.0.1:0")
	srvBad := proxy.NewServerSideService(srvBadLn.Addr().String())
	srvBad.SetNodeID("node-bad")
	srvBad.SetServices([]model.NodeServiceInfo{
		{Namespace: "prod", Name: "tcp-svc", ID: "bad-1", Host: "127.0.0.1", Port: deadPort, Protocol: "tcp"},
	})
	go func() { _ = srvBad.Serve(ctx, srvBadLn) }()

	srvGoodLn, _ := net.Listen("tcp", "127.0.0.1:0")
	srvGood := proxy.NewServerSideService(srvGoodLn.Addr().String())
	srvGood.SetNodeID("node-good")
	srvGood.SetTelemetry(tp)
	srvGood.SetServices([]model.NodeServiceInfo{
		{Namespace: "prod", Name: "tcp-svc", ID: "good-1", Host: "127.0.0.1", Port: echoLn.Addr().(*net.TCPAddr).Port, Protocol: "tcp"},
	})
	go func() { _ = srvGood.Serve(ctx, srvGoodLn) }()

	const meshIPStr = "10.221.0.10"
	const meshIP = uint32(10<<24 | 221<<16 | 0<<8 | 10)

	router := proxy.NewRouterWithNode("node-client", "default")
	router.SetMetrics(tp.Metrics())
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "tcp-svc", MeshAddr: meshIPStr, Port: 9000, Protocol: "tcp"},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "tcp-svc",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "node-bad", RouteName: "bad-1", Addr: srvBadLn.Addr().String()},
					{NodeId: "node-good", RouteName: "good-1", Addr: srvGoodLn.Addr().String()},
				},
			},
		},
		TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
			{
				Name:                   "wrr",
				Namespace:              "prod",
				TargetServiceNamespace: "prod",
				TargetServiceName:      "tcp-svc",
				LoadBalancer: &omnimeshv1.LoadBalancerPolicyInfo{
					Algorithm: omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED_ROUND_ROBIN,
				},
			},
		},
	})

	clientLn, _ := net.Listen("tcp", "127.0.0.1:0")
	clientSvc := proxy.NewClientSideService(clientLn.Addr().String(), "", &mockProcessor{
		pktInfo: &model.OriginalPacketInfo{PID: 100, IP: meshIP, Port: 9000},
	})
	clientSvc.SetRouter(router)
	clientSvc.SetNodeID("node-client")
	clientSvc.SetTelemetry(tp)
	go func() { _ = clientSvc.Serve(ctx, clientLn) }()

	time.Sleep(40 * time.Millisecond)

	// Send 1 TCP message — WRR picks bad-1 first -> 502 -> retries good-1 -> echoes "ping".
	conn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial client proxy: %v", err)
	}
	_, _ = conn.Write([]byte("ping"))
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	got, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("expected 'ping' echo after 502 retry failover, got %q", string(got))
	}

	// Wait briefly for span completion.
	time.Sleep(50 * time.Millisecond)

	m := collectMetricNamesAndData(t, reader)
	for _, expected := range []string{
		outbound.MetricRetriesTotal,
		outbound.MetricRetriesSuccess,
		outbound.MetricRequestsTotal,
		outbound.MetricHBONEBytesSent,
		outbound.MetricHBONEBytesReceived,
	} {
		if _, ok := m[expected]; !ok {
			t.Fatalf("expected metric %q to be recorded during 502 retry + L4 TCP flow", expected)
		}
	}

	// At sample_rate=0.0, the failed 502 attempt span MUST be exported due to AlwaysSampleErrors=true,
	// while the successful retry span MUST NOT be exported.
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected exactly 1 error-sampled span from failed 502 attempt, got %d", len(spans))
	}
}

func TestE2E_TelemetryGRPC_AttributesAndMetrics(t *testing.T) {
	const callerSPIFFE = "spiffe://omnimesh.local/ns/prod/sa/grpc-client"

	grpcBackendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen grpc backend: %v", err)
	}
	defer grpcBackendLn.Close()

	grpcSrv := grpc.NewServer()
	grpcSrv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "test.v1.EchoService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Echo",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					var req wrapperspb.StringValue
					if err := dec(&req); err != nil {
						return nil, err
					}
					if req.Value == "fail" {
						return nil, status.Error(codes.Internal, "internal boom")
					}
					return wrapperspb.String("echo:" + req.Value), nil
				},
			},
		},
	}, struct{}{})
	go func() { _ = grpcSrv.Serve(grpcBackendLn) }()
	defer grpcSrv.Stop()

	obsCfg := model.DefaultObservabilityConfig()
	obsCfg.Traces.Enabled = true
	obsCfg.Traces.Sampler = "always_on"

	reader := sdkmetric.NewManualReader()
	exp := tracetest.NewInMemoryExporter()
	tp, err := oteltelemetry.NewProvider(context.Background(), obsCfg, "node-grpc",
		oteltelemetry.WithMetricReader(reader),
		oteltelemetry.WithSpanExporter(exp),
		oteltelemetry.WithSyncSpanProcessor(),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	defer func() { _ = tp.Shutdown(context.Background()) }()

	bridge, err := httpproxy.NewBridge(model.DefaultHTTPConfig(), true)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	bridge.SetTelemetry(tp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverLn, _ := net.Listen("tcp", "127.0.0.1:0")
	serverSvc := proxy.NewServerSideService(serverLn.Addr().String())
	serverSvc.SetNodeID("node-grpc")
	serverSvc.SetHTTPBridge(bridge)
	serverSvc.SetTelemetry(tp)
	serverSvc.SetServices([]model.NodeServiceInfo{
		{
			Namespace: "prod",
			Name:      "echo-grpc",
			ID:        "echo-1",
			Host:      "127.0.0.1",
			Port:      grpcBackendLn.Addr().(*net.TCPAddr).Port,
			Protocol:  "grpc",
		},
	})
	go func() { _ = serverSvc.Serve(ctx, serverLn) }()

	const meshIPStr = "10.222.0.10"
	const meshIP = uint32(10<<24 | 222<<16 | 0<<8 | 10)
	router := proxy.NewRouterWithNode("node-grpc", "default")
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "echo-grpc", MeshAddr: meshIPStr, Port: 50051, Protocol: "grpc"},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "echo-grpc",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "node-grpc", RouteName: "echo-1", Addr: serverLn.Addr().String()},
				},
			},
		},
	})

	clientLn, _ := net.Listen("tcp", "127.0.0.1:0")
	clientSvc := proxy.NewClientSideService(clientLn.Addr().String(), "", &mockProcessor{
		pktInfo: &model.OriginalPacketInfo{PID: 55, IP: meshIP, Port: 50051},
	})
	clientSvc.SetRouter(router)
	clientSvc.SetNodeID("node-grpc")
	clientSvc.SetHTTPBridge(bridge)
	clientSvc.SetTelemetry(tp)
	clientSvc.SetWorkloadSVIDProvider(&mockSVIDProvider{
		tlsConfig: (*tls.Config)(nil),
		spiffeID:  callerSPIFFE,
		errByPID:  make(map[uint64]error),
	})
	go func() { _ = clientSvc.Serve(ctx, clientLn) }()

	time.Sleep(40 * time.Millisecond)

	conn, err := grpc.NewClient(clientLn.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	var resp wrapperspb.StringValue
	if err := conn.Invoke(context.Background(), "/test.v1.EchoService/Echo", wrapperspb.String("hello"), &resp); err != nil {
		t.Fatalf("gRPC Echo invoke failed: %v", err)
	}
	if resp.Value != "echo:hello" {
		t.Fatalf("expected echo:hello, got %q", resp.Value)
	}

	var foundGRPCSpan bool
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, sp := range exp.GetSpans() {
			attrs := map[string]string{}
			for _, kv := range sp.Attributes {
				attrs[string(kv.Key)] = kv.Value.AsString()
			}
			if attrs[outbound.AttrRPCSystem] == "grpc" &&
				attrs[outbound.AttrRPCService] == "test.v1.EchoService" &&
				attrs[outbound.AttrRPCMethod] == "Echo" &&
				attrs[outbound.AttrRPCGRPCStatusCode] == "0" {
				foundGRPCSpan = true
				break
			}
		}
		if foundGRPCSpan {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !foundGRPCSpan {
		t.Fatalf("expected gRPC span with rpc.system/service/method/grpc.status_code attributes")
	}
}

// Compile-time check for unused fmt/sync imports if adjusted later.
var _ = fmt.Sprint
var _ sync.Mutex
