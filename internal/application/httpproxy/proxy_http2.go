package httpproxy

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func (b *Bridge) proxyHTTP2(ctx context.Context, downstream net.Conn, upstream net.Conn, meta model.ConnectionMeta) error {
	protos := new(http.Protocols)
	protos.SetUnencryptedHTTP2(true)
	h2Transport := &http.Transport{
		Protocols: protos,
		HTTP2: &http.HTTP2Config{
			StrictMaxConcurrentRequests: true,
		},
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return upstream, nil
		},
	}

	ln := newSingleConnListener(ctx, downstream)
	defer ln.Close()

	srv := &http.Server{
		Handler:        b.newReverseProxyHandler(h2Transport, meta),
		MaxHeaderBytes: b.cfg.MaxHeaderBytes,
		IdleTimeout:    b.idleTimeout,
		HTTP2: &http.HTTP2Config{
			MaxReadFrameSize: 1 << 20,
		},
		Protocols: protos,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	stop := context.AfterFunc(ctx, func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	defer stop()

	err := srv.Serve(ln)
	if err != nil && (errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}
