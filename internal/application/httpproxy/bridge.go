package httpproxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

var _ inbound.HTTPStreamBridge = (*Bridge)(nil)

type exchangeKey struct{}

type proxyExchange struct {
	startTime time.Time
	reqCtx    *model.HTTPRequestContext
	respCtx   *model.HTTPResponseContext
	resRef    *http.Response
	rejected  *domain.HTTPRejectError
	err       error
}

// Bridge implements inbound.HTTPStreamBridge for both outbound and inbound data plane paths.
// It inspects and mutates HTTP/1.1 and HTTP/2 (h2c) request/response headers while transparently
// falling back to raw L4 TCP streaming for non-HTTP or TLS traffic.
type Bridge struct {
	cfg          model.HTTPConfig
	sniffTimeout time.Duration
	idleTimeout  time.Duration

	meshSanitizer *MeshMetadataInterceptor
	trace         *TraceContextInterceptor
	meshInjector  *MeshMetadataInterceptor
	rules         *RuleEngineInterceptor
	custom        []outbound.HeaderInterceptor

	bufPool *copyBufferPool
}

// NewBridge constructs a validated Bridge from cfg, SPIRE mode, and optional custom Go interceptors.
func NewBridge(cfg model.HTTPConfig, spireDisabled bool, customInterceptors ...outbound.HeaderInterceptor) (*Bridge, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	sniffTimeout, err := cfg.ParsedSniffTimeout()
	if err != nil {
		return nil, err
	}
	idleTimeout, err := cfg.ParsedIdleTimeout()
	if err != nil {
		return nil, err
	}

	b := &Bridge{
		cfg:          cfg,
		sniffTimeout: sniffTimeout,
		idleTimeout:  idleTimeout,
		bufPool:      newCopyBufferPool(32 * 1024),
	}

	if cfg.MeshHeaders.Enabled {
		allowUnverified := cfg.MeshHeaders.ShouldAllowUnverifiedIdentity(spireDisabled)
		mesh := NewMeshMetadataInterceptor(cfg.MeshHeaders, allowUnverified)
		b.meshSanitizer = mesh
		b.meshInjector = mesh
	}
	if cfg.Tracing.Enabled {
		b.trace = NewTraceContextInterceptor(cfg.Tracing)
	}
	if len(cfg.Rules) > 0 {
		rules, err := NewRuleEngineInterceptor(cfg.Rules)
		if err != nil {
			return nil, err
		}
		b.rules = rules
	}
	for _, ic := range customInterceptors {
		if ic != nil {
			b.custom = append(b.custom, ic)
		}
	}

	return b, nil
}

func (b *Bridge) isDirectionEnabled(dir model.TrafficDirection) bool {
	if !b.cfg.Enabled {
		return false
	}
	switch dir {
	case model.DirectionOutbound:
		return b.cfg.Outbound.Enabled
	case model.DirectionInbound:
		return b.cfg.Inbound.Enabled
	default:
		return true
	}
}

// Bridge connects downstream to upstream, running HTTP/1.1 or HTTP/2 header pipelines when
// applicable and falling back to raw bidirectional L4 copying otherwise.
func (b *Bridge) Bridge(ctx context.Context, downstream net.Conn, upstream net.Conn, meta model.ConnectionMeta) error {
	defer downstream.Close()
	defer upstream.Close()

	if !b.isDirectionEnabled(meta.Direction) || meta.ConfiguredProto == model.ProtocolTCP {
		meta.DetectedProto = model.ProtocolTCP
		return b.bridgeL4(ctx, downstream, upstream)
	}

	var targetConn net.Conn = downstream
	var proto model.HTTPProtocol

	switch meta.ConfiguredProto {
	case model.ProtocolHTTP1:
		proto = model.ProtocolHTTP1
	case model.ProtocolHTTP2:
		proto = model.ProtocolHTTP2
	default: // ProtocolAuto or ProtocolHTTP
		peek := NewPeekableConn(downstream)
		proto = peek.Sniff(ctx, b.sniffTimeout, b.cfg.MaxSniffBytes)
		targetConn = peek
	}

	meta.DetectedProto = proto

	switch proto {
	case model.ProtocolHTTP1:
		return b.proxyHTTP1(ctx, targetConn, upstream, meta)
	case model.ProtocolHTTP2:
		return b.proxyHTTP2(ctx, targetConn, upstream, meta)
	default:
		return b.bridgeL4(ctx, targetConn, upstream)
	}
}

func (b *Bridge) bridgeL4(ctx context.Context, downstream net.Conn, upstream net.Conn) error {
	stop := context.AfterFunc(ctx, func() {
		_ = downstream.Close()
		_ = upstream.Close()
	})
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := b.bufPool.Get()
		defer b.bufPool.Put(buf)
		_, _ = io.CopyBuffer(upstream, downstream, buf)
		if cw, ok := upstream.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		buf := b.bufPool.Get()
		defer b.bufPool.Put(buf)
		_, _ = io.CopyBuffer(downstream, upstream, buf)
		if cw, ok := downstream.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	wg.Wait()
	return nil
}

func (b *Bridge) newReverseProxyHandler(baseTransport http.RoundTripper, meta model.ConnectionMeta) http.Handler {
	rp := &httputil.ReverseProxy{
		Transport:     &rejectCheckingTransport{base: baseTransport},
		FlushInterval: -1,
		BufferPool:    b.bufPool,
		Rewrite: func(pr *httputil.ProxyRequest) {
			b.rewriteRequest(pr, meta)
		},
		ModifyResponse: func(res *http.Response) error {
			return b.modifyResponse(res, meta)
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			b.handleProxyError(rw, req, err)
		},
	}

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ex := &proxyExchange{startTime: time.Now()}
		crw := &countingResponseWriter{ResponseWriter: rw}

		var bodyCounter *countingReadCloser
		if req.Body != nil && req.Body != http.NoBody {
			bodyCounter = &countingReadCloser{ReadCloser: req.Body}
			req.Body = bodyCounter
		}

		ctx := context.WithValue(req.Context(), exchangeKey{}, ex)
		rp.ServeHTTP(crw, req.WithContext(ctx))

		var bytesIn int64
		if bodyCounter != nil {
			bytesIn = bodyCounter.count.Load()
		}
		b.completeExchange(ctx, &meta, ex, bytesIn, crw.count.Load())
	})
}

func (b *Bridge) rewriteRequest(pr *httputil.ProxyRequest, meta model.ConnectionMeta) {
	// ReverseProxy strips forwarding headers before calling Rewrite. Restore them so
	// transparent traffic preserves existing headers unless MeshMetadataInterceptor appends.
	restoreForwardedHeaders(pr.In.Header, pr.Out.Header)

	// Keep URL.Host constant so http.Transport always reuses the single upstream connection
	// across requests with different Host headers, while preserving pr.Out.Host verbatim.
	pr.Out.URL.Scheme = "http"
	pr.Out.URL.Host = "omnimesh-upstream"
	pr.Out.Host = pr.In.Host

	if pr.In.Trailer != nil && pr.Out.Body != nil {
		pr.Out.Body = &trailerForwardingBody{
			ReadCloser: pr.Out.Body,
			inTrailer:  &pr.In.Trailer,
			outTrailer: &pr.Out.Trailer,
		}
	}

	ex, _ := pr.In.Context().Value(exchangeKey{}).(*proxyExchange)
	reqCtx := &model.HTTPRequestContext{
		Method:        pr.Out.Method,
		URL:           pr.Out.URL,
		Host:          pr.Out.Host,
		ProtoMajor:    pr.In.ProtoMajor,
		ProtoMinor:    pr.In.ProtoMinor,
		Headers:       pr.Out.Header,
		Trailers:      pr.Out.Trailer,
		ContentLength: pr.Out.ContentLength,
	}
	if ex != nil {
		reqCtx.StartTime = ex.startTime
		ex.reqCtx = reqCtx
	}

	if err := b.runRequestPipeline(pr.Out.Context(), &meta, reqCtx); err != nil {
		var rej *domain.HTTPRejectError
		if errors.As(err, &rej) {
			if ex != nil {
				ex.rejected = rej
				ex.err = err
			}
			return
		}
		if b.cfg.FailOpen {
			log.Printf("[HTTP L7] request interceptor error ignored (fail_open=true): %v\n", err)
			return
		}
		if ex != nil {
			ex.err = err
		}
	}
}

func (b *Bridge) modifyResponse(res *http.Response, meta model.ConnectionMeta) error {
	if meta.DetectedProto == model.ProtocolHTTP1 && res.Close {
		res.Header.Set("Connection", "close")
	}

	ex, _ := res.Request.Context().Value(exchangeKey{}).(*proxyExchange)
	var reqCtx *model.HTTPRequestContext
	if ex != nil {
		reqCtx = ex.reqCtx
	}

	respCtx := &model.HTTPResponseContext{
		StatusCode: res.StatusCode,
		ProtoMajor: res.ProtoMajor,
		ProtoMinor: res.ProtoMinor,
		Headers:    res.Header,
		Trailers:   res.Trailer,
	}
	if ex != nil {
		ex.respCtx = respCtx
		ex.resRef = res
	}

	if err := b.runResponsePipeline(res.Request.Context(), &meta, reqCtx, respCtx); err != nil {
		if b.cfg.FailOpen {
			log.Printf("[HTTP L7] response interceptor error ignored (fail_open=true): %v\n", err)
			return nil
		}
		if ex != nil {
			ex.err = err
		}
		return err
	}
	return nil
}

func (b *Bridge) handleProxyError(rw http.ResponseWriter, req *http.Request, err error) {
	ex, _ := req.Context().Value(exchangeKey{}).(*proxyExchange)
	if ex != nil && ex.rejected != nil {
		for k, vals := range ex.rejected.Headers {
			for _, v := range vals {
				rw.Header().Add(k, v)
			}
		}
		status := ex.rejected.StatusCode
		if status <= 0 {
			status = http.StatusForbidden
		}
		if req.ProtoMajor == 1 {
			rw.Header().Set("Connection", "close")
		}
		if ex.rejected.Message != "" && rw.Header().Get("Content-Type") == "" {
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		rw.WriteHeader(status)
		if ex.rejected.Message != "" {
			_, _ = io.WriteString(rw, ex.rejected.Message)
		}
		ex.respCtx = &model.HTTPResponseContext{StatusCode: status, Headers: rw.Header()}
		return
	}

	if ex != nil && ex.err != nil && errors.Is(err, ex.err) {
		log.Printf("[HTTP L7] interceptor error: %v\n", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		ex.respCtx = &model.HTTPResponseContext{StatusCode: http.StatusInternalServerError, Headers: rw.Header()}
		return
	}

	if ex != nil {
		ex.err = err
		ex.respCtx = &model.HTTPResponseContext{StatusCode: http.StatusBadGateway, Headers: rw.Header()}
	}
	if req.Context().Err() == nil {
		log.Printf("[HTTP L7] upstream proxy error: %v\n", err)
	}
	http.Error(rw, "Bad Gateway", http.StatusBadGateway)
}

func (b *Bridge) runRequestPipeline(ctx context.Context, conn *model.ConnectionMeta, req *model.HTTPRequestContext) error {
	if b.meshSanitizer != nil {
		b.meshSanitizer.SanitizeRequest(conn, req)
	}
	if b.trace != nil {
		if err := b.trace.OnRequest(ctx, conn, req); err != nil {
			return err
		}
	}
	if b.meshInjector != nil {
		if err := b.meshInjector.InjectRequest(conn, req); err != nil {
			return err
		}
	}
	if b.rules != nil {
		if err := b.rules.OnRequest(ctx, conn, req); err != nil {
			return err
		}
	}
	for _, ic := range b.custom {
		if err := ic.OnRequest(ctx, conn, req); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bridge) runResponsePipeline(ctx context.Context, conn *model.ConnectionMeta, req *model.HTTPRequestContext, resp *model.HTTPResponseContext) error {
	for i := len(b.custom) - 1; i >= 0; i-- {
		if err := b.custom[i].OnResponse(ctx, conn, req, resp); err != nil {
			return err
		}
	}
	if b.rules != nil {
		if err := b.rules.OnResponse(ctx, conn, req, resp); err != nil {
			return err
		}
	}
	if b.trace != nil {
		if err := b.trace.OnResponse(ctx, conn, req, resp); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bridge) completeExchange(ctx context.Context, conn *model.ConnectionMeta, ex *proxyExchange, bytesIn, bytesOut int64) {
	if ex == nil {
		return
	}
	if ex.respCtx == nil {
		ex.respCtx = &model.HTTPResponseContext{}
	}
	ex.respCtx.Duration = time.Since(ex.startTime)
	ex.respCtx.BytesIn = bytesIn
	ex.respCtx.BytesOut = bytesOut
	if ex.resRef != nil && ex.err == nil && len(ex.resRef.Trailer) > 0 {
		ex.respCtx.Trailers = ex.resRef.Trailer
	}

	for _, ic := range b.custom {
		if obs, ok := ic.(outbound.HTTPCompletionObserver); ok {
			obs.OnComplete(ctx, conn, ex.reqCtx, ex.respCtx, ex.err)
		}
	}

	if ex.reqCtx != nil {
		path := ""
		if ex.reqCtx.URL != nil {
			path = ex.reqCtx.URL.Path
		}
		destSvc := conn.ServiceName
		if conn.Namespace != "" && conn.ServiceName != "" {
			destSvc = conn.Namespace + "/" + conn.ServiceName
		}
		log.Printf("[HTTP L7] direction=%s proto=%s method=%s path=%s status=%d duration_ms=%.2f trace_id=%s request_id=%s caller=%s dest_service=%s node_service_id=%s\n",
			conn.Direction,
			conn.DetectedProto,
			ex.reqCtx.Method,
			path,
			ex.respCtx.StatusCode,
			float64(ex.respCtx.Duration.Microseconds())/1000.0,
			ex.reqCtx.TraceContext.TraceIDHex(),
			ex.reqCtx.RequestID,
			conn.CallerIdentity,
			destSvc,
			conn.NodeServiceID,
		)
	}
}

func restoreForwardedHeaders(in, out http.Header) {
	for _, key := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if vals, ok := in[key]; ok {
			out[key] = slices.Clone(vals)
		}
	}
}

type rejectCheckingTransport struct {
	base http.RoundTripper
}

func (t *rejectCheckingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if ex, ok := req.Context().Value(exchangeKey{}).(*proxyExchange); ok && ex.err != nil {
		return nil, ex.err
	}
	return t.base.RoundTrip(req)
}

type trailerForwardingBody struct {
	io.ReadCloser
	inTrailer  *http.Header
	outTrailer *http.Header
	copied     bool
}

func (b *trailerForwardingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF && !b.copied {
		b.copied = true
		if b.inTrailer != nil && *b.inTrailer != nil && b.outTrailer != nil {
			if *b.outTrailer == nil {
				*b.outTrailer = make(http.Header, len(*b.inTrailer))
			}
			for k, vals := range *b.inTrailer {
				(*b.outTrailer)[k] = slices.Clone(vals)
			}
		}
	}
	return n, err
}

type countingReadCloser struct {
	io.ReadCloser
	count atomic.Int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.count.Add(int64(n))
	}
	return n, err
}

type countingResponseWriter struct {
	http.ResponseWriter
	count atomic.Int64
}

func (w *countingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.count.Add(int64(n))
	}
	return n, err
}

// Unwrap allows http.ResponseController to discover Flusher and Hijacker on the underlying writer.
func (w *countingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

type copyBufferPool struct {
	size int
	pool sync.Pool
}

func newCopyBufferPool(size int) *copyBufferPool {
	return &copyBufferPool{
		size: size,
		pool: sync.Pool{
			New: func() any {
				buf := make([]byte, size)
				return &buf
			},
		},
	}
}

func (p *copyBufferPool) Get() []byte {
	return *p.pool.Get().(*[]byte)
}

func (p *copyBufferPool) Put(b []byte) {
	if cap(b) >= p.size {
		b = b[:p.size]
		p.pool.Put(&b)
	}
}
