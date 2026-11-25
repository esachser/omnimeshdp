package httpproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

type stubAuthorizer struct {
	allowL4 bool
	allowL7 bool
}

func (s *stubAuthorizer) AuthorizeConnection(_ context.Context, _ model.AuthzRequest) model.AuthzDecision {
	return model.AuthzDecision{Allowed: s.allowL4}
}

func (s *stubAuthorizer) AuthorizeHTTP(_ context.Context, _ model.AuthzRequest) model.AuthzDecision {
	return model.AuthzDecision{Allowed: s.allowL7}
}

func TestAuthzInterceptor_HTTPAndGRPCRejections(t *testing.T) {
	ic := NewAuthzInterceptor(&stubAuthorizer{allowL4: true, allowL7: false})

	conn := &model.ConnectionMeta{
		Direction:      model.DirectionInbound,
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/web",
		CallerVerified: true,
		Namespace:      "prod",
		ServiceName:    "api",
	}

	// Outbound direction should be a no-op.
	outConn := *conn
	outConn.Direction = model.DirectionOutbound
	if err := ic.OnRequest(context.Background(), &outConn, &model.HTTPRequestContext{
		Method:  "GET",
		URL:     &url.URL{Path: "/"},
		Headers: http.Header{},
	}); err != nil {
		t.Fatalf("expected outbound OnRequest to be no-op, got %v", err)
	}

	// Inbound HTTP request denied with 403 Forbidden.
	err := ic.OnRequest(context.Background(), conn, &model.HTTPRequestContext{
		Method:  "GET",
		URL:     &url.URL{Path: "/secret"},
		Headers: http.Header{},
	})
	var rej *domain.HTTPRejectError
	if !errors.As(err, &rej) || rej.StatusCode != http.StatusForbidden || rej.OmitBody {
		t.Fatalf("expected 403 HTTPRejectError, got %+v (err=%v)", rej, err)
	}

	// Inbound gRPC request denied with PERMISSION_DENIED (grpc-status=7).
	err = ic.OnRequest(context.Background(), conn, &model.HTTPRequestContext{
		Method:  "POST",
		URL:     &url.URL{Path: "/payment.v1.PaymentService/Charge"},
		Headers: http.Header{"Content-Type": {"application/grpc"}},
	})
	rej = nil
	if !errors.As(err, &rej) || rej.StatusCode != http.StatusOK || !rej.OmitBody || rej.Trailers.Get("Grpc-Status") != "7" {
		t.Fatalf("expected gRPC PERMISSION_DENIED HTTPRejectError, got %+v (err=%v)", rej, err)
	}
}

func TestBridge_AuthzRequiresL7BlocksL4Bypass(t *testing.T) {
	cfg := model.DefaultHTTPConfig()
	cfg.SniffTimeout = "40ms"
	b, err := NewBridge(cfg, true)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}

	clientDown, proxyDown := net.Pipe()
	proxyUp, serverUp := net.Pipe()
	defer clientDown.Close()
	defer serverUp.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- b.Bridge(context.Background(), proxyDown, proxyUp, model.ConnectionMeta{
			Direction:       model.DirectionInbound,
			ConfiguredProto: model.ProtocolAuto,
			CallerIdentity:  "spiffe://omnimesh.local/ns/prod/sa/web",
			CallerVerified:  true,
			Namespace:       "prod",
			ServiceName:     "api",
			AuthzRequiresL7: true,
		})
	}()

	// Send non-HTTP raw binary bytes attempting to trigger L4 passthrough fallback.
	_, _ = clientDown.Write([]byte{0x00, 0x01, 0x02, 0x03})

	select {
	case bridgeErr := <-errCh:
		if !errors.Is(bridgeErr, domain.ErrForbidden) {
			t.Fatalf("expected ErrForbidden blocking L4 fallback when AuthzRequiresL7=true, got %v", bridgeErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Bridge to reject L4 bypass")
	}

	// Verify zero bytes reached upstream.
	_ = serverUp.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 16)
	if n, err := serverUp.Read(buf); n > 0 {
		t.Fatalf("expected 0 bytes forwarded upstream, got %d (%v)", n, err)
	}
}

func TestBridge_RespondForbiddenProtocols(t *testing.T) {
	cfg := model.DefaultHTTPConfig()
	cfg.SniffTimeout = "60ms"
	b, err := NewBridge(cfg, true)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}

	t.Run("HTTP/1.1 receives 403 Forbidden", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()

		done := make(chan error, 1)
		go func() {
			done <- b.RespondForbidden(context.Background(), c2, model.ConnectionMeta{
				Direction:       model.DirectionOutbound,
				ConfiguredProto: model.ProtocolAuto,
			})
		}()

		req, _ := http.NewRequest("GET", "http://api.prod.mesh/test", nil)
		if err := req.Write(c1); err != nil {
			t.Fatalf("write http1 request: %v", err)
		}
		_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c1), req)
		if err != nil {
			t.Fatalf("read http1 response: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "Forbidden") {
			t.Fatalf("expected 403 Forbidden, got status=%d body=%q", resp.StatusCode, string(body))
		}
		if err := <-done; err != nil {
			t.Fatalf("RespondForbidden error: %v", err)
		}
	})

	t.Run("TCP closes immediately", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()

		if err := b.RespondForbidden(context.Background(), c2, model.ConnectionMeta{
			Direction:       model.DirectionOutbound,
			ConfiguredProto: model.ProtocolTCP,
		}); err != nil {
			t.Fatalf("RespondForbidden TCP error: %v", err)
		}

		_ = c1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 8)
		n, err := c1.Read(buf)
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF on closed TCP conn, got n=%d err=%v", n, err)
		}
	})
}
