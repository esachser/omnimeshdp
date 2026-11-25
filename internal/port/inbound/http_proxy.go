package inbound

import (
	"context"
	"net"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

// HTTPStreamBridge bridges a downstream and upstream connection pair, applying L7 HTTP/1.1 or
// HTTP/2 header inspection/injection when applicable and falling back to raw L4 TCP streaming otherwise.
type HTTPStreamBridge interface {
	Bridge(ctx context.Context, downstream net.Conn, upstream net.Conn, meta model.ConnectionMeta) error
}

// HTTPForbiddenResponder writes a protocol-appropriate access denied response (HTTP 403 or
// gRPC PERMISSION_DENIED) directly to a downstream connection when an upstream peer rejects
// an HBONE CONNECT tunnel with HTTP 403 Forbidden.
type HTTPForbiddenResponder interface {
	RespondForbidden(ctx context.Context, downstream net.Conn, meta model.ConnectionMeta) error
}
