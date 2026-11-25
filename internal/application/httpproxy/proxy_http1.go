package httpproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func (b *Bridge) proxyHTTP1(ctx context.Context, downstream net.Conn, upstream net.Conn, meta model.ConnectionMeta) error {
	var dialOnce sync.Once
	tr := &http.Transport{
		DisableCompression:  true,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		MaxConnsPerHost:     1,
		IdleConnTimeout:     b.idleTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var conn net.Conn
			dialOnce.Do(func() {
				conn = upstream
			})
			if conn == nil {
				return nil, errors.New("upstream connection already consumed")
			}
			return conn, nil
		},
	}
	defer tr.CloseIdleConnections()

	ln := newSingleConnListener(ctx, downstream)
	defer ln.Close()

	var protos http.Protocols
	protos.SetHTTP1(true)

	srv := &http.Server{
		Handler:        b.newReverseProxyHandler(tr, meta),
		MaxHeaderBytes: b.cfg.MaxHeaderBytes,
		IdleTimeout:    b.idleTimeout,
		Protocols:      &protos,
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

// singleConnListener yields a single pre-accepted connection to http.Server.Serve
// and then blocks until that connection (including any hijacked upgrade) closes or ctx ends.
type singleConnListener struct {
	conn   *closeTrackingConn
	served bool
	closed chan struct{}
	once   sync.Once
	ctx    context.Context
}

func newSingleConnListener(ctx context.Context, conn net.Conn) *singleConnListener {
	closed := make(chan struct{})
	l := &singleConnListener{
		closed: closed,
		ctx:    ctx,
	}
	l.conn = &closeTrackingConn{
		Conn: conn,
		onClose: func() {
			l.once.Do(func() { close(closed) })
		},
	}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.served {
		l.served = true
		return l.conn, nil
	}
	select {
	case <-l.closed:
	case <-l.ctx.Done():
	}
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

type closeTrackingConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *closeTrackingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose)
	return err
}

func (c *closeTrackingConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}
