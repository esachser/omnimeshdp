package httpproxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func TestMeshMetadataInterceptor_InboundAntiSpoofing(t *testing.T) {
	cfg := model.DefaultHTTPConfig().MeshHeaders
	ic := NewMeshMetadataInterceptor(cfg, false)

	conn := &model.ConnectionMeta{
		Direction:      model.DirectionInbound,
		SourceNodeID:   "node-a",
		DestNodeID:     "node-b",
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/checkout",
		CallerVerified: true,
		Namespace:      "prod",
		ServiceName:    "payment",
		NodeServiceID:  "payment-1",
	}

	req := &model.HTTPRequestContext{
		Headers: http.Header{
			"X-Omnimesh-Caller-Identity": []string{"spiffe://evil.local/admin"},
			"X-Omnimesh-Source-Node":     []string{"forged-node"},
			"X-Omnimesh-Custom-Evil":     []string{"smuggled"},
			"X-App-Header":               []string{"kept"},
		},
	}

	if err := ic.OnRequest(context.Background(), conn, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Headers.Get(MeshHeaderCallerIdentity); got != conn.CallerIdentity {
		t.Fatalf("expected verified identity %q, got %q", conn.CallerIdentity, got)
	}
	if got := req.Headers.Get(MeshHeaderSourceNode); got != "node-a" {
		t.Fatalf("expected source node 'node-a', got %q", got)
	}
	if got := req.Headers.Get(MeshHeaderDestNode); got != "node-b" {
		t.Fatalf("expected dest node 'node-b', got %q", got)
	}
	if got := req.Headers.Get(MeshHeaderDestService); got != "prod/payment" {
		t.Fatalf("expected dest service 'prod/payment', got %q", got)
	}
	if got := req.Headers.Get(MeshHeaderNodeServiceID); got != "payment-1" {
		t.Fatalf("expected node service id 'payment-1', got %q", got)
	}
	if got := req.Headers.Get("X-Omnimesh-Custom-Evil"); got != "" {
		t.Fatalf("expected forged x-omnimesh-* header stripped, got %q", got)
	}
	if got := req.Headers.Get("X-App-Header"); got != "kept" {
		t.Fatalf("expected normal app header preserved, got %q", got)
	}
}

func TestMeshMetadataInterceptor_UnverifiedAndForwardedFor(t *testing.T) {
	cfg := model.DefaultHTTPConfig().MeshHeaders
	cfg.InjectXForwardedFor = true

	t.Run("omits caller identity when unverified and allow_unverified_identity=false", func(t *testing.T) {
		ic := NewMeshMetadataInterceptor(cfg, false)
		conn := &model.ConnectionMeta{
			Direction:      model.DirectionOutbound,
			SourceAddr:     "10.0.0.5:43210",
			CallerIdentity: "uid=1000",
			CallerVerified: false,
		}
		req := &model.HTTPRequestContext{
			Headers: http.Header{
				"X-Omnimesh-Caller-Identity": []string{"spoofed"},
				"X-Forwarded-For":            []string{"203.0.113.10"},
			},
		}
		if err := ic.OnRequest(context.Background(), conn, req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := req.Headers.Get(MeshHeaderCallerIdentity); got != "" {
			t.Fatalf("expected unverified caller identity omitted, got %q", got)
		}
		if got := req.Headers.Get(MeshHeaderForwardedFor); got != "203.0.113.10, 10.0.0.5" {
			t.Fatalf("expected appended X-Forwarded-For, got %q", got)
		}
	})

	t.Run("injects unverified identity when allow_unverified_identity=true", func(t *testing.T) {
		ic := NewMeshMetadataInterceptor(cfg, true)
		conn := &model.ConnectionMeta{
			Direction:      model.DirectionInbound,
			CallerIdentity: "uid=1000",
			CallerVerified: false,
		}
		req := &model.HTTPRequestContext{Headers: make(http.Header)}
		if err := ic.OnRequest(context.Background(), conn, req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := req.Headers.Get(MeshHeaderCallerIdentity); got != "uid=1000" {
			t.Fatalf("expected unverified identity injected, got %q", got)
		}
	})
}
