package httpproxy

import (
	"context"
	"net/http"
	"strings"

	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

var _ outbound.HeaderInterceptor = (*AuthzInterceptor)(nil)

// AuthzInterceptor enforces L7 HTTP/1.1, HTTP/2, and gRPC authorization policies
// on inbound mesh requests using the verified caller identity and connection metadata.
type AuthzInterceptor struct {
	authorizer inbound.Authorizer
}

// NewAuthzInterceptor constructs an AuthzInterceptor backed by authorizer.
func NewAuthzInterceptor(authorizer inbound.Authorizer) *AuthzInterceptor {
	return &AuthzInterceptor{authorizer: authorizer}
}

// Name returns the interceptor identifier.
func (a *AuthzInterceptor) Name() string {
	return "authz"
}

// OnRequest evaluates L7 authorization on inbound requests and rejects denied requests
// with HTTP 403 Forbidden or gRPC PERMISSION_DENIED (status 7).
func (a *AuthzInterceptor) OnRequest(ctx context.Context, conn *model.ConnectionMeta, req *model.HTTPRequestContext) error {
	if a == nil || a.authorizer == nil || conn == nil || req == nil {
		return nil
	}
	if conn.Direction != model.DirectionInbound {
		return nil
	}

	reqPath := "/"
	if req.URL != nil && req.URL.Path != "" {
		reqPath = req.URL.Path
	}

	isGRPC := isGRPCContentType(req.Headers.Get("Content-Type"))
	var grpcService, grpcMethod string
	if isGRPC {
		grpcService, grpcMethod = parseGRPCPath(reqPath)
	}

	destProto := conn.RawProtocol
	if destProto == "" {
		destProto = string(conn.DetectedProto)
	}

	decision := a.authorizer.AuthorizeHTTP(ctx, model.AuthzRequest{
		Layer:              model.AuthzLayerL7,
		CallerIdentity:     conn.CallerIdentity,
		CallerVerified:     conn.CallerVerified,
		SourceNodeID:       conn.SourceNodeID,
		SourceAddr:         conn.SourceAddr,
		DestNamespace:      conn.Namespace,
		DestServiceName:    conn.ServiceName,
		DestNodeServiceID:  conn.NodeServiceID,
		DestPort:           conn.DestPort,
		DestProtocol:       destProto,
		DestLabels:         conn.ServiceLabels,
		InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method:      req.Method,
			Path:        reqPath,
			Headers:     req.Headers,
			IsGRPC:      isGRPC,
			GRPCService: grpcService,
			GRPCMethod:  grpcMethod,
			TraceID:     req.TraceContext.TraceIDHex(),
			RequestID:   req.RequestID,
		},
	})

	if decision.Allowed {
		return nil
	}

	if isGRPC {
		return &domain.HTTPRejectError{
			StatusCode: http.StatusOK,
			Message:    "permission denied",
			OmitBody:   true,
			Headers: http.Header{
				"Content-Type": {"application/grpc"},
			},
			Trailers: http.Header{
				"Grpc-Status":  {"7"},
				"Grpc-Message": {"permission denied"},
			},
		}
	}

	return &domain.HTTPRejectError{
		StatusCode: http.StatusForbidden,
		Message:    "Forbidden\n",
	}
}

// OnResponse is a no-op for L7 authorization.
func (a *AuthzInterceptor) OnResponse(_ context.Context, _ *model.ConnectionMeta, _ *model.HTTPRequestContext, _ *model.HTTPResponseContext) error {
	return nil
}

func isGRPCContentType(ct string) bool {
	ct = strings.TrimSpace(ct)
	if len(ct) < len("application/grpc") {
		return false
	}
	if !strings.EqualFold(ct[:len("application/grpc")], "application/grpc") {
		return false
	}
	if len(ct) == len("application/grpc") {
		return true
	}
	next := ct[len("application/grpc")]
	return next == '+' || next == ';' || next == ' ' || next == '\t'
}

func parseGRPCPath(p string) (service string, method string) {
	trimmed := strings.TrimPrefix(p, "/")
	idx := strings.IndexByte(trimmed, '/')
	if idx <= 0 || idx+1 >= len(trimmed) {
		return "", ""
	}
	return trimmed[:idx], trimmed[idx+1:]
}
