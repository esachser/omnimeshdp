package outbound

import (
	"context"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

// HeaderInterceptor inspects and/or mutates HTTP/1.1 and HTTP/2 headers across request and response phases.
// Implementations MUST be safe for concurrent use across goroutines.
type HeaderInterceptor interface {
	// Name returns a unique identifier for logging and diagnostics.
	Name() string

	// OnRequest runs before forwarding the request upstream.
	// Returning *domain.HTTPRejectError rejects the request directly with the configured HTTP status.
	// Returning any other non-nil error logs and fails with 500 Internal Server Error unless fail_open is enabled.
	OnRequest(ctx context.Context, conn *model.ConnectionMeta, req *model.HTTPRequestContext) error

	// OnResponse runs after receiving upstream response headers and before writing them downstream.
	OnResponse(ctx context.Context, conn *model.ConnectionMeta, req *model.HTTPRequestContext, resp *model.HTTPResponseContext) error
}

// HTTPCompletionObserver is an optional interface that a HeaderInterceptor or observer may implement
// to receive final telemetry after the response body and trailers finish streaming.
type HTTPCompletionObserver interface {
	OnComplete(ctx context.Context, conn *model.ConnectionMeta, req *model.HTTPRequestContext, resp *model.HTTPResponseContext, err error)
}
