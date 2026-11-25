package httpproxy

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func TestRuleEngineInterceptor_ActionsPredicatesAndTemplates(t *testing.T) {
	rules := []model.HeaderRule{
		{
			Name:      "set-meta",
			Phase:     "request",
			Direction: "outbound",
			Action:    "set",
			Header:    "x-mesh-meta",
			Value:     "${trace_id}/${span_id}/${traceparent}/${request_id}/${caller_identity}/${source_node}->${dest_node}/${namespace}/${service_name}/${node_service_id}/${direction}/${protocol}/${service.label.version}/${req.header.x-tenant}/${unknown_var}",
			Match: model.RuleMatch{
				Namespaces:   []string{"prod"},
				Services:     []string{"prod/orders"},
				Methods:      []string{"POST"},
				PathPrefix:   "/v1/",
				HeaderExists: "x-tenant",
				HeaderEquals: map[string]string{"x-env": "canary"},
			},
		},
		{
			Name:      "add-tag",
			Phase:     "request",
			Direction: "both",
			Action:    "add",
			Header:    "x-tag",
			Value:     "second",
		},
		{
			Name:      "set-if-absent",
			Phase:     "request",
			Direction: "both",
			Action:    "set_if_absent",
			Header:    "x-defaulted",
			Value:     "fallback",
		},
		{
			Name:      "append-via",
			Phase:     "request",
			Direction: "both",
			Action:    "append",
			Header:    "x-mesh-via",
			Value:     "${source_node}",
		},
		{
			Name:      "remove-secret",
			Phase:     "request",
			Direction: "both",
			Action:    "remove",
			Header:    "x-internal-debug",
		},
		{
			Name:      "resp-status",
			Phase:     "response",
			Direction: "inbound",
			Action:    "set",
			Header:    "x-served-status",
			Value:     "${status_code}:${dest_node}",
			Match: model.RuleMatch{
				HeaderExists: "x-backend-ok",
			},
		},
	}

	engine, err := NewRuleEngineInterceptor(rules)
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}

	conn := &model.ConnectionMeta{
		Direction:      model.DirectionOutbound,
		DetectedProto:  model.ProtocolHTTP2,
		SourceNodeID:   "node-1",
		DestNodeID:     "node-2",
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/api",
		Namespace:      "prod",
		ServiceName:    "orders",
		NodeServiceID:  "orders-v2",
		ServiceLabels:  map[string]string{"version": "v2"},
	}
	req := &model.HTTPRequestContext{
		Method: "POST",
		URL:    &url.URL{Path: "/v1/orders"},
		Headers: http.Header{
			"X-Tenant":         []string{"acme\r\nInjected: bad"},
			"X-Env":            []string{"canary"},
			"X-Tag":            []string{"first"},
			"X-Defaulted":      []string{"keep-me"},
			"X-Mesh-Via":       []string{"edge"},
			"X-Internal-Debug": []string{"secret"},
		},
		TraceContext: model.TraceContext{
			Version:    0,
			TraceID:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			ParentID:   [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
			TraceFlags: 1,
			Valid:      true,
		},
		RequestID: "req-42",
	}

	if err := engine.OnRequest(context.Background(), conn, req); err != nil {
		t.Fatalf("OnRequest error: %v", err)
	}

	wantMeta := "0102030405060708090a0b0c0d0e0f10/0102030405060708/00-0102030405060708090a0b0c0d0e0f10-0102030405060708-01/req-42/spiffe://omnimesh.local/ns/prod/sa/api/node-1->node-2/prod/orders/orders-v2/outbound/http2/v2/acmeInjected: bad/"
	if got := req.Headers.Get("X-Mesh-Meta"); got != wantMeta {
		t.Fatalf("x-mesh-meta mismatch:\ngot:  %q\nwant: %q", got, wantMeta)
	}
	if vals := req.Headers.Values("X-Tag"); len(vals) != 2 || vals[0] != "first" || vals[1] != "second" {
		t.Fatalf("unexpected x-tag values: %v", vals)
	}
	if got := req.Headers.Get("X-Defaulted"); got != "keep-me" {
		t.Fatalf("expected x-defaulted untouched, got %q", got)
	}
	if got := req.Headers.Get("X-Mesh-Via"); got != "edge, node-1" {
		t.Fatalf("expected appended x-mesh-via, got %q", got)
	}
	if got := req.Headers.Get("X-Internal-Debug"); got != "" {
		t.Fatalf("expected x-internal-debug removed, got %q", got)
	}

	// Response rule only fires on inbound when x-backend-ok is present
	inboundConn := *conn
	inboundConn.Direction = model.DirectionInbound
	resp := &model.HTTPResponseContext{
		StatusCode: 201,
		Headers:    http.Header{"X-Backend-Ok": []string{"1"}},
	}
	if err := engine.OnResponse(context.Background(), &inboundConn, req, resp); err != nil {
		t.Fatalf("OnResponse error: %v", err)
	}
	if got := resp.Headers.Get("X-Served-Status"); got != "201:node-2" {
		t.Fatalf("expected x-served-status '201:node-2', got %q", got)
	}
}

func TestRuleEngineInterceptor_ValidationRejectsUnsafeRules(t *testing.T) {
	badRules := []model.HeaderRule{
		{Name: "pseudo", Phase: "request", Action: "set", Header: ":path", Value: "/evil"},
		{Name: "host", Phase: "request", Action: "set", Header: "Host", Value: "evil.com"},
		{Name: "cl", Phase: "request", Action: "set", Header: "content-length", Value: "5"},
		{Name: "te", Phase: "request", Action: "set", Header: "Transfer-Encoding", Value: "chunked"},
		{Name: "bad-name", Phase: "request", Action: "set", Header: "bad header", Value: "x"},
		{Name: "crlf", Phase: "request", Action: "set", Header: "x-ok", Value: "a\nb"},
	}

	for _, r := range badRules {
		if _, err := NewRuleEngineInterceptor([]model.HeaderRule{r}); err == nil {
			t.Errorf("expected rule %q to fail validation", r.Name)
		}
	}
}
