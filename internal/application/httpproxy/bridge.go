package httpproxy

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

var (
	_ inbound.HTTPStreamBridge       = (*Bridge)(nil)
	_ inbound.HTTPForbiddenResponder = (*Bridge)(nil)
)

type exchangeKey struct{}

type proxyExchange struct {
	startTime time.Time
	reqCtx    *model.HTTPRequestContext
	respCtx   *model.HTTPResponseContext
	resRef    *http.Response
	rejected  *domain.HTTPRejectError
	span      outbound.SpanHandle
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
	authzMu       sync.RWMutex
	authz         *AuthzInterceptor
	meshInjector  *MeshMetadataInterceptor
	rules         *RuleEngineInterceptor
	custom        []outbound.HeaderInterceptor

	telemetryMu sync.RWMutex
	telemetry   outbound.TelemetryProvider

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

// SetAuthorizer configures the inbound L7 Authorizer enforced by the HTTP/1.1 and HTTP/2 request pipeline.
func (b *Bridge) SetAuthorizer(authorizer inbound.Authorizer) {
	b.authzMu.Lock()
	defer b.authzMu.Unlock()
	if authorizer == nil {
		b.authz = nil
		return
	}
	b.authz = NewAuthzInterceptor(authorizer)
}

// SetTelemetry configures the TelemetryProvider used for L7 HTTP/gRPC and L4 TCP metrics and tracing.
func (b *Bridge) SetTelemetry(tp outbound.TelemetryProvider) {
	b.telemetryMu.Lock()
	defer b.telemetryMu.Unlock()
	b.telemetry = tp
}

func (b *Bridge) telemetryRecorders() (outbound.MetricRecorder, outbound.TraceRecorder) {
	b.telemetryMu.RLock()
	tp := b.telemetry
	b.telemetryMu.RUnlock()
	if tp == nil {
		return nil, nil
	}
	return tp.Metrics(), tp.Tracer()
}

// InboundL7Enabled reports whether L7 HTTP inspection is currently enabled for inbound connections.
func (b *Bridge) InboundL7Enabled() bool {
	return b.isDirectionEnabled(model.DirectionInbound)
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

	_, tracer := b.telemetryRecorders()

	if !b.isDirectionEnabled(meta.Direction) || meta.ConfiguredProto == model.ProtocolTCP {
		meta.DetectedProto = model.ProtocolTCP
		if meta.AuthzRequiresL7 {
			log.Printf("[Authz] event=authz.denied layer=l7 reason=l7_required caller=%q dest_service=%s/%s node_service_id=%q\n",
				meta.CallerIdentity, meta.Namespace, meta.ServiceName, meta.NodeServiceID)
			if tracer != nil {
				tracer.SpanFromContext(ctx).SetError(domain.ErrForbidden, "l7 authorization required")
			}
			return domain.ErrForbidden
		}
		return b.bridgeL4(ctx, downstream, upstream, meta)
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
		if tracer != nil {
			if outer := tracer.SpanFromContext(ctx); outer != nil {
				outer.SetName(outbound.SpanNameHBONETunnel)
			}
		}
		return b.proxyHTTP1(ctx, targetConn, upstream, meta)
	case model.ProtocolHTTP2:
		if tracer != nil {
			if outer := tracer.SpanFromContext(ctx); outer != nil {
				outer.SetName(outbound.SpanNameHBONETunnel)
			}
		}
		return b.proxyHTTP2(ctx, targetConn, upstream, meta)
	default:
		if meta.AuthzRequiresL7 {
			log.Printf("[Authz] event=authz.denied layer=l7 reason=l7_required caller=%q dest_service=%s/%s node_service_id=%q\n",
				meta.CallerIdentity, meta.Namespace, meta.ServiceName, meta.NodeServiceID)
			if tracer != nil {
				tracer.SpanFromContext(ctx).SetError(domain.ErrForbidden, "l7 authorization required")
			}
			return domain.ErrForbidden
		}
		return b.bridgeL4(ctx, targetConn, upstream, meta)
	}
}

func (b *Bridge) bridgeL4(ctx context.Context, downstream net.Conn, upstream net.Conn, meta model.ConnectionMeta) error {
	metrics, tracer := b.telemetryRecorders()
	start := time.Now()
	srcSvc, srcNS := model.ParseCallerService(meta.CallerIdentity)
	destSvc, destNS := formatBridgeDestLabels(meta)

	if tracer != nil {
		tracer.SpanFromContext(ctx).SetAttributes(model.MetricAttribute{Key: outbound.AttrProtocol, Value: "tcp"})
	}
	if metrics != nil {
		metrics.AddUpDownCounter(ctx, outbound.MetricRequestsActive, 1,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
		)
	}

	stop := context.AfterFunc(ctx, func() {
		_ = downstream.Close()
		_ = upstream.Close()
	})
	defer stop()

	var bytesSent, bytesReceived int64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := b.bufPool.Get()
		defer b.bufPool.Put(buf)
		n, _ := io.CopyBuffer(upstream, downstream, buf)
		bytesSent = n
		if cw, ok := upstream.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		buf := b.bufPool.Get()
		defer b.bufPool.Put(buf)
		n, _ := io.CopyBuffer(downstream, upstream, buf)
		bytesReceived = n
		if cw, ok := downstream.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	wg.Wait()

	if metrics != nil {
		metrics.AddUpDownCounter(context.Background(), outbound.MetricRequestsActive, -1,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
		)
		durMs := float64(time.Since(start).Nanoseconds()) / 1e6
		if metrics.CombinedRequestMetricEnabled() {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrSourceNamespace, Value: srcNS},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
				model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "tcp"},
				model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: "ok"},
			)
		}
		if meta.Direction == model.DirectionInbound {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsIngressTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrSourceNamespace, Value: srcNS},
				model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "tcp"},
				model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: "ok"},
			)
		} else {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsEgressTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
				model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "tcp"},
				model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: "ok"},
			)
		}
		metrics.RecordHistogram(context.Background(), outbound.MetricRequestsDurationMs, durMs,
			model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "tcp"},
		)
		if bytesSent > 0 {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsBytesSent, bytesSent,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			)
		}
		if bytesReceived > 0 {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsBytesReceived, bytesReceived,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			)
		}
	}
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

		metrics, _ := b.telemetryRecorders()
		destSvc, destNS := formatBridgeDestLabels(meta)
		if metrics != nil {
			metrics.AddUpDownCounter(req.Context(), outbound.MetricRequestsActive, 1,
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
			)
		}

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
		if ex.rejected.Message != "" && !ex.rejected.OmitBody && rw.Header().Get("Content-Type") == "" {
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		rw.WriteHeader(status)
		if ex.rejected.Message != "" && !ex.rejected.OmitBody {
			_, _ = io.WriteString(rw, ex.rejected.Message)
		}
		for k, vals := range ex.rejected.Trailers {
			rw.Header()[http.TrailerPrefix+k] = slices.Clone(vals)
		}
		ex.respCtx = &model.HTTPResponseContext{StatusCode: status, Headers: rw.Header(), Trailers: ex.rejected.Trailers}
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

	pipeCtx := ctx
	if _, tracer := b.telemetryRecorders(); tracer != nil {
		carrier := outbound.HTTPHeaderCarrier(req.Headers)
		extractedCtx := tracer.ExtractContext(context.Background(), carrier)
		extractedSC := tracer.SpanContextFromContext(extractedCtx)

		parentCtx := extractedCtx
		if !extractedSC.Valid {
			if conn != nil && conn.Direction == model.DirectionInbound {
				parentCtx = ctx
			} else {
				parentCtx = context.Background()
			}
		}

		spanName := outbound.SpanNameEgress
		spanKind := model.SpanKindClient
		dirLabel := "egress"
		nodeLabel := ""
		if conn != nil {
			nodeLabel = conn.SourceNodeID
			if conn.Direction == model.DirectionInbound {
				spanName = outbound.SpanNameIngress
				spanKind = model.SpanKindServer
				dirLabel = "ingress"
				nodeLabel = conn.DestNodeID
			}
		}

		srcSvc, srcNS := "unknown", "unknown"
		destSvc, destNS, destAddr := "unknown", "unknown", ""
		if conn != nil {
			srcSvc, srcNS = model.ParseCallerService(conn.CallerIdentity)
			destSvc, destNS = formatBridgeDestLabels(*conn)
			destAddr = conn.DestAddr
		}

		reqPath := "/"
		if req.URL != nil && req.URL.Path != "" {
			reqPath = req.URL.Path
		}
		isGRPC := isGRPCContentType(req.Headers.Get("Content-Type"))
		protoAttr := "http"
		if isGRPC {
			protoAttr = "grpc"
		}

		attrs := []model.MetricAttribute{
			{Key: outbound.AttrDirection, Value: dirLabel},
			{Key: outbound.AttrNode, Value: nodeLabel},
			{Key: outbound.AttrSourceService, Value: srcSvc},
			{Key: outbound.AttrSourceNamespace, Value: srcNS},
			{Key: outbound.AttrDestinationService, Value: destSvc},
			{Key: outbound.AttrDestinationNamespace, Value: destNS},
			{Key: outbound.AttrDestinationEndpoint, Value: destAddr},
			{Key: outbound.AttrProtocol, Value: protoAttr},
			{Key: outbound.AttrHTTPMethod, Value: req.Method},
			{Key: outbound.AttrHTTPURL, Value: reqPath},
		}
		if isGRPC {
			grpcSvc, grpcMethod := parseGRPCPath(reqPath)
			attrs = append(attrs, model.MetricAttribute{Key: outbound.AttrRPCSystem, Value: "grpc"})
			if grpcSvc != "" {
				attrs = append(attrs, model.MetricAttribute{Key: outbound.AttrRPCService, Value: grpcSvc})
			}
			if grpcMethod != "" {
				attrs = append(attrs, model.MetricAttribute{Key: outbound.AttrRPCMethod, Value: grpcMethod})
			}
		}

		var span outbound.SpanHandle
		pipeCtx, span = tracer.StartSpan(parentCtx, spanName, spanKind, attrs...)
		if ex, ok := ctx.Value(exchangeKey{}).(*proxyExchange); ok && ex != nil {
			ex.span = span
		}

		sc := span.SpanContext()
		if sc.Valid {
			tracer.InjectContext(pipeCtx, carrier)
			if tidBytes, err := hex.DecodeString(sc.TraceID); err == nil && len(tidBytes) == 16 {
				copy(req.TraceContext.TraceID[:], tidBytes)
			}
			if sidBytes, err := hex.DecodeString(sc.SpanID); err == nil && len(sidBytes) == 8 {
				copy(req.TraceContext.ParentID[:], sidBytes)
			}
			if extractedSC.Valid {
				if inSID, err := hex.DecodeString(extractedSC.SpanID); err == nil && len(inSID) == 8 {
					copy(req.TraceContext.IncomingParentID[:], inSID)
				}
			}
			req.TraceContext.TraceFlags = sc.TraceFlags
			req.TraceContext.Valid = true
			req.TraceContext.Incoming = extractedSC.Valid
			req.TraceContext.Generated = !extractedSC.Valid
		}
	}

	if b.trace != nil {
		if err := b.trace.OnRequest(pipeCtx, conn, req); err != nil {
			return err
		}
	}
	b.authzMu.RLock()
	authzIc := b.authz
	b.authzMu.RUnlock()
	if authzIc != nil {
		if err := authzIc.OnRequest(pipeCtx, conn, req); err != nil {
			return err
		}
	}
	if b.meshInjector != nil {
		if err := b.meshInjector.InjectRequest(conn, req); err != nil {
			return err
		}
	}
	if b.rules != nil {
		if err := b.rules.OnRequest(pipeCtx, conn, req); err != nil {
			return err
		}
	}
	for _, ic := range b.custom {
		if err := ic.OnRequest(pipeCtx, conn, req); err != nil {
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

	metrics, _ := b.telemetryRecorders()
	if metrics != nil && conn != nil {
		srcSvc, srcNS := model.ParseCallerService(conn.CallerIdentity)
		destSvc, destNS := formatBridgeDestLabels(*conn)

		metrics.AddUpDownCounter(context.Background(), outbound.MetricRequestsActive, -1,
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
		)

		isGRPC := isExchangeGRPC(conn, ex)
		protoLabel := protocolMetricLabel(*conn, isGRPC)
		grpcStatus := extractGRPCStatus(ex)

		respCode := "error"
		if isGRPC && grpcStatus != "" {
			respCode = grpcStatus
		} else if ex.respCtx.StatusCode > 0 {
			respCode = strconv.Itoa(ex.respCtx.StatusCode)
		}

		durMs := float64(ex.respCtx.Duration.Nanoseconds()) / 1e6
		if metrics.CombinedRequestMetricEnabled() {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrSourceNamespace, Value: srcNS},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
				model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: protoLabel},
				model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: respCode},
			)
		}
		if conn.Direction == model.DirectionInbound {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsIngressTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrSourceNamespace, Value: srcNS},
				model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: protoLabel},
				model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: respCode},
			)
		} else {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsEgressTotal, 1,
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: destNS},
				model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: protoLabel},
				model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: respCode},
			)
		}
		metrics.RecordHistogram(context.Background(), outbound.MetricRequestsDurationMs, durMs,
			model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: protoLabel},
		)
		if bytesIn > 0 {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsBytesSent, bytesIn,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			)
		}
		if bytesOut > 0 {
			metrics.AddCounter(context.Background(), outbound.MetricRequestsBytesReceived, bytesOut,
				model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
				model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			)
		}
	}

	if ex.span != nil {
		isGRPC := conn != nil && isExchangeGRPC(conn, ex)
		grpcStatus := extractGRPCStatus(ex)
		if ex.respCtx.StatusCode > 0 {
			ex.span.SetAttributes(model.MetricAttribute{
				Key:   outbound.AttrHTTPStatusCode,
				Value: strconv.Itoa(ex.respCtx.StatusCode),
			})
		}
		if isGRPC && grpcStatus != "" {
			ex.span.SetAttributes(model.MetricAttribute{
				Key:   outbound.AttrRPCGRPCStatusCode,
				Value: grpcStatus,
			})
		}

		isErr := (ex.err != nil && ex.rejected == nil) ||
			ex.respCtx.StatusCode >= 500 ||
			ex.respCtx.StatusCode == http.StatusForbidden ||
			(isGRPC && grpcStatus != "" && grpcStatus != "0")
		if isErr {
			desc := ""
			if ex.err != nil {
				desc = ex.err.Error()
			} else if isGRPC && grpcStatus != "" && grpcStatus != "0" {
				desc = "grpc status " + grpcStatus
			} else {
				desc = "http status " + strconv.Itoa(ex.respCtx.StatusCode)
			}
			ex.span.SetError(ex.err, desc)
		}
		ex.span.End()
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

func formatBridgeDestLabels(conn model.ConnectionMeta) (service, namespace string) {
	namespace = strings.TrimSpace(conn.Namespace)
	if namespace == "" {
		namespace = "unknown"
	}
	name := strings.TrimSpace(conn.ServiceName)
	if name == "" {
		name = strings.TrimSpace(conn.NodeServiceID)
	}
	if name == "" {
		return "unknown", namespace
	}
	if conn.Namespace != "" && conn.ServiceName != "" {
		return conn.Namespace + "/" + conn.ServiceName, namespace
	}
	return name, namespace
}

func isExchangeGRPC(conn *model.ConnectionMeta, ex *proxyExchange) bool {
	if conn != nil && strings.EqualFold(strings.TrimSpace(conn.RawProtocol), "grpc") {
		return true
	}
	if ex != nil && ex.reqCtx != nil && ex.reqCtx.Headers != nil {
		if isGRPCContentType(ex.reqCtx.Headers.Get("Content-Type")) {
			return true
		}
	}
	if ex != nil && ex.respCtx != nil && ex.respCtx.Headers != nil {
		if isGRPCContentType(ex.respCtx.Headers.Get("Content-Type")) {
			return true
		}
	}
	return false
}

func protocolMetricLabel(conn model.ConnectionMeta, isGRPC bool) string {
	if isGRPC {
		return "grpc"
	}
	switch conn.DetectedProto {
	case model.ProtocolHTTP2:
		return "http2"
	case model.ProtocolHTTP1:
		return "http1"
	default:
		return "tcp"
	}
}

func extractGRPCStatus(ex *proxyExchange) string {
	if ex == nil || ex.respCtx == nil {
		return ""
	}
	if ex.respCtx.Trailers != nil {
		if v := ex.respCtx.Trailers.Get("Grpc-Status"); v != "" {
			return v
		}
	}
	if ex.respCtx.Headers != nil {
		if v := ex.respCtx.Headers.Get("Grpc-Status"); v != "" {
			return v
		}
	}
	return ""
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

// RespondForbidden writes a protocol-appropriate access denied response (HTTP 403 or gRPC
// PERMISSION_DENIED) directly to downstream when an outbound HBONE CONNECT receives HTTP 403.
func (b *Bridge) RespondForbidden(ctx context.Context, downstream net.Conn, meta model.ConnectionMeta) error {
	if downstream == nil {
		return nil
	}
	defer downstream.Close()

	if !b.isDirectionEnabled(model.DirectionOutbound) || meta.ConfiguredProto == model.ProtocolTCP {
		return nil
	}

	var targetConn net.Conn = downstream
	proto := meta.ConfiguredProto
	if proto != model.ProtocolHTTP1 && proto != model.ProtocolHTTP2 {
		peek := NewPeekableConn(downstream)
		proto = peek.Sniff(ctx, b.sniffTimeout, b.cfg.MaxSniffBytes)
		targetConn = peek
	}

	switch proto {
	case model.ProtocolHTTP1:
		return b.serveSingleForbidden(ctx, targetConn, false, meta)
	case model.ProtocolHTTP2:
		return b.serveSingleForbidden(ctx, targetConn, true, meta)
	default:
		return nil
	}
}

func (b *Bridge) serveSingleForbidden(ctx context.Context, downstream net.Conn, isH2 bool, meta model.ConnectionMeta) error {
	respCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var protos http.Protocols
	if isH2 {
		protos.SetUnencryptedHTTP2(true)
	} else {
		protos.SetHTTP1(true)
	}

	ln := newSingleConnListener(respCtx, downstream)
	defer ln.Close()

	var once sync.Once
	var srv *http.Server
	var shutdownTimer atomic.Pointer[time.Timer]
	srv = &http.Server{
		MaxHeaderBytes: b.cfg.MaxHeaderBytes,
		Protocols:      &protos,
		BaseContext: func(net.Listener) context.Context {
			return respCtx
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isH2 && (isGRPCContentType(r.Header.Get("Content-Type")) || strings.EqualFold(meta.RawProtocol, "grpc")) {
				w.Header().Set("Content-Type", "application/grpc")
				w.WriteHeader(http.StatusOK)
				w.Header()[http.TrailerPrefix+"Grpc-Status"] = []string{"7"}
				w.Header()[http.TrailerPrefix+"Grpc-Message"] = []string{"permission denied"}
			} else {
				if !isH2 {
					w.Header().Set("Connection", "close")
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "Forbidden\n")
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			once.Do(func() {
				delay := 10 * time.Millisecond
				if isH2 {
					delay = 50 * time.Millisecond
				}
				shutdownTimer.Store(time.AfterFunc(delay, func() {
					_ = srv.Shutdown(respCtx)
				}))
			})
		}),
	}
	defer func() {
		if t := shutdownTimer.Load(); t != nil {
			t.Stop()
		}
	}()
	if isH2 {
		srv.HTTP2 = &http.HTTP2Config{MaxReadFrameSize: 1 << 20}
	}

	stop := context.AfterFunc(respCtx, func() {
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
