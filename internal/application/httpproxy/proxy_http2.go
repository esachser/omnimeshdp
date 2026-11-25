package httpproxy

import (
	"context"
	"net"
	"net/http"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"golang.org/x/net/http2"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func (b *Bridge) proxyHTTP2(ctx context.Context, downstream net.Conn, upstream net.Conn, meta model.ConnectionMeta) error {
	h2Transport := &http2.Transport{
		AllowHTTP:                  true,
		DisableCompression:         true,
		StrictMaxConcurrentStreams: true,
	}

	clientConn, err := h2Transport.NewClientConn(upstream)
	if err != nil {
		return err
	}
	defer clientConn.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = downstream.Close()
		_ = upstream.Close()
	})
	defer stop()

	h2Server := &http2.Server{
		MaxReadFrameSize: 1 << 20,
		IdleTimeout:      b.idleTimeout,
	}

	h2Server.ServeConn(downstream, &http2.ServeConnOpts{
		Context: ctx,
		Handler: b.newReverseProxyHandler(roundTripperFunc(clientConn.RoundTrip), meta),
	})
	return nil
}
