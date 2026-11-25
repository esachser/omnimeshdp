package httpproxy

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func TestTraceContextInterceptor_ValidTraceparent(t *testing.T) {
	const incomingTP = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	const incomingTS = "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE"

	t.Run("preserve mode keeps traceparent and tracestate verbatim", func(t *testing.T) {
		ic := NewTraceContextInterceptor(model.TracingConfig{
			Enabled:             true,
			GenerateTraceparent: true,
			TraceparentMode:     "preserve",
			GenerateRequestID:   true,
			RequestIDHeader:     "x-request-id",
		})

		req := &model.HTTPRequestContext{
			Headers: http.Header{
				"Traceparent": []string{incomingTP},
				"Tracestate":  []string{incomingTS},
			},
		}
		if err := ic.OnRequest(context.Background(), &model.ConnectionMeta{}, req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := req.Headers.Get("Traceparent"); got != incomingTP {
			t.Fatalf("expected traceparent %q, got %q", incomingTP, got)
		}
		if got := req.Headers.Get("Tracestate"); got != incomingTS {
			t.Fatalf("expected tracestate %q, got %q", incomingTS, got)
		}
		if !req.TraceContext.Valid || !req.TraceContext.Incoming || req.TraceContext.Generated {
			t.Fatalf("unexpected trace context flags: %+v", req.TraceContext)
		}
		if req.TraceContext.TraceIDHex() != "4bf92f3577b34da6a3ce929d0e0e4736" {
			t.Fatalf("unexpected trace id: %s", req.TraceContext.TraceIDHex())
		}
		if req.TraceContext.ParentIDHex() != "00f067aa0ba902b7" {
			t.Fatalf("unexpected parent id: %s", req.TraceContext.ParentIDHex())
		}
		if req.RequestID == "" || req.Headers.Get("X-Request-Id") != req.RequestID {
			t.Fatalf("expected generated x-request-id, got %q", req.RequestID)
		}
	})

	t.Run("new_span mode keeps trace-id and tracestate, rotates parent-id", func(t *testing.T) {
		ic := NewTraceContextInterceptor(model.TracingConfig{
			Enabled:             true,
			GenerateTraceparent: true,
			TraceparentMode:     "new_span",
			GenerateRequestID:   true,
		})

		req := &model.HTTPRequestContext{
			Headers: http.Header{
				"Traceparent":  []string{incomingTP},
				"Tracestate":   []string{incomingTS},
				"X-Request-Id": []string{"req-abc-123"},
			},
		}
		if err := ic.OnRequest(context.Background(), &model.ConnectionMeta{}, req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		gotTP := req.Headers.Get("Traceparent")
		parts := strings.Split(gotTP, "-")
		if len(parts) != 4 {
			t.Fatalf("invalid updated traceparent: %q", gotTP)
		}
		if parts[1] != "4bf92f3577b34da6a3ce929d0e0e4736" {
			t.Fatalf("trace-id changed: got %s", parts[1])
		}
		if parts[2] == "00f067aa0ba902b7" || parts[2] == "0000000000000000" {
			t.Fatalf("expected new non-zero parent-id, got %s", parts[2])
		}
		if parts[3] != "01" {
			t.Fatalf("expected trace flags 01 preserved, got %s", parts[3])
		}
		if req.Headers.Get("Tracestate") != incomingTS {
			t.Fatalf("expected tracestate preserved, got %q", req.Headers.Get("Tracestate"))
		}
		if req.RequestID != "req-abc-123" || req.Headers.Get("X-Request-Id") != "req-abc-123" {
			t.Fatalf("expected existing x-request-id preserved, got %q", req.RequestID)
		}
	})
}

func TestTraceContextInterceptor_MalformedGenerationAndEcho(t *testing.T) {
	ic := NewTraceContextInterceptor(model.TracingConfig{
		Enabled:             true,
		GenerateTraceparent: true,
		TraceparentMode:     "preserve",
		DefaultSampled:      true,
		GenerateRequestID:   true,
		RequestIDHeader:     "x-correlation-id",
		EchoResponseHeaders: true,
	})

	malformed := []string{
		"",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-short-00f067aa0ba902b7-01",
	}

	for _, badTP := range malformed {
		req := &model.HTTPRequestContext{
			Headers: http.Header{
				"Tracestate": []string{"stale=1"},
			},
		}
		if badTP != "" {
			req.Headers.Set("Traceparent", badTP)
		}
		if err := ic.OnRequest(context.Background(), &model.ConnectionMeta{}, req); err != nil {
			t.Fatalf("unexpected error for %q: %v", badTP, err)
		}
		if !req.TraceContext.Valid || !req.TraceContext.Generated || req.TraceContext.Incoming {
			t.Fatalf("expected generated valid trace context for %q, got %+v", badTP, req.TraceContext)
		}
		if gotTS := req.Headers.Get("Tracestate"); gotTS != "" {
			t.Fatalf("expected stale tracestate cleared on new trace generation, got %q", gotTS)
		}
		if !strings.HasPrefix(req.Headers.Get("Traceparent"), "00-") || !strings.HasSuffix(req.Headers.Get("Traceparent"), "-01") {
			t.Fatalf("unexpected generated traceparent %q", req.Headers.Get("Traceparent"))
		}
		if req.Headers.Get("X-Correlation-Id") == "" {
			t.Fatalf("expected custom request id header generated")
		}

		// Echo response headers without clobbering existing upstream headers.
		resp := &model.HTTPResponseContext{
			StatusCode: 200,
			Headers:    http.Header{"X-Trace-Id": []string{"upstream-kept"}},
		}
		if err := ic.OnResponse(context.Background(), &model.ConnectionMeta{}, req, resp); err != nil {
			t.Fatalf("unexpected response error: %v", err)
		}
		if resp.Headers.Get("X-Trace-Id") != "upstream-kept" {
			t.Fatalf("existing X-Trace-Id should not be overwritten, got %q", resp.Headers.Get("X-Trace-Id"))
		}
		if resp.Headers.Get("X-Correlation-Id") != req.RequestID {
			t.Fatalf("expected echoed request id %q, got %q", req.RequestID, resp.Headers.Get("X-Correlation-Id"))
		}
	}
}
