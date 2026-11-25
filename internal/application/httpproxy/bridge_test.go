package httpproxy_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/application/httpproxy"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type recordingObserverInterceptor struct {
	rejectTenant string
	completed    chan *model.HTTPResponseContext
}

func (r *recordingObserverInterceptor) Name() string { return "test-observer" }

func (r *recordingObserverInterceptor) OnRequest(_ context.Context, _ *model.ConnectionMeta, req *model.HTTPRequestContext) error {
	if r.rejectTenant != "" && req.Headers.Get("X-Tenant-Id") == r.rejectTenant {
		return &domain.HTTPRejectError{
			StatusCode: http.StatusForbidden,
			Message:    "tenant blocked",
			Headers:    http.Header{"X-Reject-Reason": []string{"policy"}},
		}
	}
	return nil
}

func (r *recordingObserverInterceptor) OnResponse(_ context.Context, _ *model.ConnectionMeta, _ *model.HTTPRequestContext, resp *model.HTTPResponseContext) error {
	resp.Headers.Set("X-Observed", "yes")
	return nil
}

func (r *recordingObserverInterceptor) OnComplete(_ context.Context, _ *model.ConnectionMeta, _ *model.HTTPRequestContext, resp *model.HTTPResponseContext, _ error) {
	if r.completed != nil {
		select {
		case r.completed <- resp:
		default:
		}
	}
}

type failInterceptor struct{}

func (f *failInterceptor) Name() string { return "always-fail" }
func (f *failInterceptor) OnRequest(context.Context, *model.ConnectionMeta, *model.HTTPRequestContext) error {
	return errors.New("boom")
}
func (f *failInterceptor) OnResponse(context.Context, *model.ConnectionMeta, *model.HTTPRequestContext, *model.HTTPResponseContext) error {
	return nil
}

func TestBridge_RejectsAndFailOpen(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backendLn.Close()

	srv := &http.Server{
		Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("backend-ok"))
		}), &http2.Server{}),
	}
	go func() { _ = srv.Serve(backendLn) }()
	defer srv.Close()

	t.Run("custom interceptor HTTPRejectError stops request before backend", func(t *testing.T) {
		completedCh := make(chan *model.HTTPResponseContext, 2)
		ic := &recordingObserverInterceptor{rejectTenant: "evil", completed: completedCh}
		bridge, err := httpproxy.NewBridge(model.DefaultHTTPConfig(), true, ic)
		if err != nil {
			t.Fatalf("NewBridge: %v", err)
		}

		downstreamClient, downstreamProxy := net.Pipe()
		upstream, err := net.Dial("tcp", backendLn.Addr().String())
		if err != nil {
			t.Fatalf("dial backend: %v", err)
		}
		defer downstreamClient.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			_ = bridge.Bridge(ctx, downstreamProxy, upstream, model.ConnectionMeta{
				Direction:       model.DirectionInbound,
				ConfiguredProto: model.ProtocolHTTP1,
				Namespace:       "default",
				ServiceName:     "svc",
			})
		}()

		req, _ := http.NewRequest("GET", "http://svc.local/hello", nil)
		req.Header.Set("X-Tenant-Id", "evil")
		if err := req.Write(downstreamClient); err != nil {
			t.Fatalf("write request: %v", err)
		}

		resp, err := http.ReadResponse(bufio.NewReader(downstreamClient), req)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Reject-Reason") != "policy" {
			t.Fatalf("expected X-Reject-Reason 'policy', got %q", resp.Header.Get("X-Reject-Reason"))
		}
		if string(body) != "tenant blocked" {
			t.Fatalf("unexpected reject body: %q", string(body))
		}

		select {
		case comp := <-completedCh:
			if comp.StatusCode != http.StatusForbidden {
				t.Fatalf("expected OnComplete status 403, got %d", comp.StatusCode)
			}
		case <-time.After(time.Second):
			t.Fatal("expected OnComplete callback")
		}
	})

	t.Run("fail_open skips non-reject interceptor error", func(t *testing.T) {
		cfg := model.DefaultHTTPConfig()
		cfg.FailOpen = true
		bridge, err := httpproxy.NewBridge(cfg, true, outbound.HeaderInterceptor(&failInterceptor{}))
		if err != nil {
			t.Fatalf("NewBridge: %v", err)
		}

		downstreamClient, downstreamProxy := net.Pipe()
		upstream, err := net.Dial("tcp", backendLn.Addr().String())
		if err != nil {
			t.Fatalf("dial backend: %v", err)
		}
		defer downstreamClient.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			_ = bridge.Bridge(ctx, downstreamProxy, upstream, model.ConnectionMeta{
				Direction:       model.DirectionOutbound,
				ConfiguredProto: model.ProtocolHTTP1,
			})
		}()

		req, _ := http.NewRequest("GET", "http://svc.local/ok", nil)
		if err := req.Write(downstreamClient); err != nil {
			t.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(downstreamClient), req)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK || string(body) != "backend-ok" {
			t.Fatalf("expected fail_open to allow request through, got status=%d body=%q", resp.StatusCode, string(body))
		}
	})
}

func TestBridge_HTTP1OversizedHeaderRejected431(t *testing.T) {
	cfg := model.DefaultHTTPConfig()
	cfg.MaxHeaderBytes = 4096

	bridge, err := httpproxy.NewBridge(cfg, true)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}

	downstreamClient, downstreamProxy := net.Pipe()
	upA, upB := net.Pipe()
	defer downstreamClient.Close()
	defer upA.Close()
	defer upB.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = bridge.Bridge(ctx, downstreamProxy, upA, model.ConnectionMeta{
			Direction:       model.DirectionOutbound,
			ConfiguredProto: model.ProtocolHTTP1,
		})
	}()

	huge := strings.Repeat("a", 8192)
	go func() {
		_, _ = io.WriteString(downstreamClient, "GET / HTTP/1.1\r\nHost: svc\r\nX-Big: "+huge+"\r\n\r\n")
	}()

	_ = downstreamClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(downstreamClient), nil)
	if err != nil {
		t.Fatalf("expected 431 response, got read error: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("expected 431 Request Header Fields Too Large, got %d", resp.StatusCode)
	}
}

func BenchmarkTraceAndRuleInterceptors(b *testing.B) {
	traceIC := httpproxy.NewTraceContextInterceptor(model.DefaultHTTPConfig().Tracing)
	meshIC := httpproxy.NewMeshMetadataInterceptor(model.DefaultHTTPConfig().MeshHeaders, false)
	ruleEngine, err := httpproxy.NewRuleEngineInterceptor([]model.HeaderRule{
		{
			Name:      "inject-trace",
			Phase:     "request",
			Direction: "outbound",
			Action:    "set",
			Header:    "x-mesh-trace",
			Value:     "${trace_id}:${dest_node}",
		},
	})
	if err != nil {
		b.Fatal(err)
	}

	conn := &model.ConnectionMeta{
		Direction:      model.DirectionOutbound,
		DetectedProto:  model.ProtocolHTTP2,
		SourceNodeID:   "node-1",
		DestNodeID:     "node-2",
		CallerIdentity: "spiffe://omnimesh.local/ns/default/sa/web",
		CallerVerified: true,
		Namespace:      "default",
		ServiceName:    "api",
		NodeServiceID:  "api-1",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &model.HTTPRequestContext{
			Method: "GET",
			Headers: http.Header{
				"Traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
			},
		}
		_ = meshIC.OnRequest(context.Background(), conn, req)
		_ = traceIC.OnRequest(context.Background(), conn, req)
		_ = ruleEngine.OnRequest(context.Background(), conn, req)
	}
}

func BenchmarkBridge_HTTP1AndL4(b *testing.B) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer backendLn.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
	}
	go func() { _ = srv.Serve(backendLn) }()
	defer srv.Close()

	runBench := func(b *testing.B, cfg model.HTTPConfig) {
		bridge, err := httpproxy.NewBridge(cfg, true)
		if err != nil {
			b.Fatal(err)
		}

		proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		defer proxyLn.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			for {
				down, err := proxyLn.Accept()
				if err != nil {
					return
				}
				up, err := net.Dial("tcp", backendLn.Addr().String())
				if err != nil {
					_ = down.Close()
					continue
				}
				go func() {
					_ = bridge.Bridge(ctx, down, up, model.ConnectionMeta{
						Direction:       model.DirectionOutbound,
						ConfiguredProto: model.ProtocolHTTP1,
						SourceNodeID:    "node-1",
						DestNodeID:      "node-2",
						Namespace:       "default",
						ServiceName:     "bench",
					})
				}()
			}
		}()

		client := &http.Client{
			Transport: &http.Transport{MaxIdleConnsPerHost: 8},
		}
		defer client.CloseIdleConnections()

		targetURL := "http://" + proxyLn.Addr().String() + "/ping"
		// Warm up keep-alive connection.
		resp, err := client.Get(targetURL)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp, err := client.Get(targetURL)
			if err != nil {
				b.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}

	b.Run("HTTP1_Enabled", func(b *testing.B) {
		runBench(b, model.DefaultHTTPConfig())
	})
	b.Run("L4_Disabled", func(b *testing.B) {
		cfg := model.DefaultHTTPConfig()
		cfg.Enabled = false
		runBench(b, cfg)
	})
}
