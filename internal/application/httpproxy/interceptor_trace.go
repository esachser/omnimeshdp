package httpproxy

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	randv2 "math/rand/v2"
	"net/http"
	"strings"
	"sync"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http/httpguts"
)

var _ outbound.HeaderInterceptor = (*TraceContextInterceptor)(nil)

// TraceContextInterceptor inspects, validates, preserves, or generates W3C traceparent/tracestate
// and x-request-id headers across HTTP/1.1 and HTTP/2 requests and responses.
type TraceContextInterceptor struct {
	cfg             model.TracingConfig
	mode            string
	requestIDHeader string
	propagator      propagation.TraceContext
	rngPool         sync.Pool
}

// NewTraceContextInterceptor creates a TraceContextInterceptor configured by cfg.
func NewTraceContextInterceptor(cfg model.TracingConfig) *TraceContextInterceptor {
	mode := strings.ToLower(strings.TrimSpace(cfg.TraceparentMode))
	if mode == "" {
		mode = "preserve"
	}
	reqIDHeader := strings.TrimSpace(cfg.RequestIDHeader)
	if reqIDHeader == "" {
		reqIDHeader = "x-request-id"
	}

	return &TraceContextInterceptor{
		cfg:             cfg,
		mode:            mode,
		requestIDHeader: http.CanonicalHeaderKey(reqIDHeader),
		propagator:      propagation.TraceContext{},
		rngPool: sync.Pool{
			New: func() any {
				var seed [32]byte
				_, _ = cryptorand.Read(seed[:])
				return randv2.NewChaCha8(seed)
			},
		},
	}
}

// Name returns the interceptor identifier.
func (i *TraceContextInterceptor) Name() string {
	return "trace-context"
}

// OnRequest inspects incoming traceparent/tracestate and x-request-id headers, generates missing
// or invalid correlation identifiers as configured, and populates req.TraceContext and req.RequestID.
func (i *TraceContextInterceptor) OnRequest(_ context.Context, _ *model.ConnectionMeta, req *model.HTTPRequestContext) error {
	if req == nil {
		return nil
	}
	if req.Headers == nil {
		req.Headers = make(http.Header)
	}

	i.processTraceContext(req)
	i.processRequestID(req)
	return nil
}

// OnResponse optionally echoes x-request-id and x-trace-id onto response headers when absent.
func (i *TraceContextInterceptor) OnResponse(_ context.Context, _ *model.ConnectionMeta, req *model.HTTPRequestContext, resp *model.HTTPResponseContext) error {
	if !i.cfg.EchoResponseHeaders || req == nil || resp == nil {
		return nil
	}
	if resp.Headers == nil {
		resp.Headers = make(http.Header)
	}
	if req.RequestID != "" && resp.Headers.Get(i.requestIDHeader) == "" {
		resp.Headers.Set(i.requestIDHeader, req.RequestID)
	}
	if req.TraceContext.Valid && resp.Headers.Get("X-Trace-Id") == "" {
		resp.Headers.Set("X-Trace-Id", req.TraceContext.TraceIDHex())
	}
	return nil
}

func (i *TraceContextInterceptor) processTraceContext(req *model.HTTPRequestContext) {
	carrier := propagation.HeaderCarrier(req.Headers)
	extracted := i.propagator.Extract(context.Background(), carrier)
	sc := trace.SpanContextFromContext(extracted)

	if sc.IsValid() {
		tc := model.TraceContext{
			Version:    0,
			TraceID:    [16]byte(sc.TraceID()),
			ParentID:   [8]byte(sc.SpanID()),
			TraceFlags: byte(sc.TraceFlags()),
			TraceState: sc.TraceState().String(),
			Valid:      true,
			Incoming:   true,
		}

		if i.mode == "new_span" {
			newSpanID := i.newSpanID()
			tc.IncomingParentID = tc.ParentID
			tc.ParentID = [8]byte(newSpanID)
			newSC := sc.WithSpanID(newSpanID)
			i.propagator.Inject(trace.ContextWithSpanContext(context.Background(), newSC), carrier)
		}

		req.TraceContext = tc
		return
	}

	if !i.cfg.GenerateTraceparent {
		return
	}

	tid := i.newTraceID()
	sid := i.newSpanID()
	var flags trace.TraceFlags
	if i.cfg.DefaultSampled {
		flags = trace.FlagsSampled
	}

	newSC := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: flags,
		Remote:     true,
	})

	// Clear any stale tracestate when generating a brand-new trace-id (W3C Trace Context §3.3).
	req.Headers.Del("Tracestate")
	i.propagator.Inject(trace.ContextWithSpanContext(context.Background(), newSC), carrier)

	req.TraceContext = model.TraceContext{
		Version:    0,
		TraceID:    [16]byte(tid),
		ParentID:   [8]byte(sid),
		TraceFlags: byte(flags),
		Valid:      true,
		Incoming:   false,
		Generated:  true,
	}
}

func (i *TraceContextInterceptor) processRequestID(req *model.HTTPRequestContext) {
	existing := req.Headers.Get(i.requestIDHeader)
	if existing != "" && !model.ContainsUnsafeHeaderChars(existing) && httpguts.ValidHeaderFieldValue(existing) {
		req.RequestID = existing
		return
	}
	if !i.cfg.GenerateRequestID {
		return
	}
	id := uuid.NewString()
	req.Headers.Set(i.requestIDHeader, id)
	req.RequestID = id
}

func (i *TraceContextInterceptor) newTraceID() trace.TraceID {
	rng := i.rngPool.Get().(*randv2.ChaCha8)
	defer i.rngPool.Put(rng)

	var tid trace.TraceID
	for !tid.IsValid() {
		binary.LittleEndian.PutUint64(tid[:8], rng.Uint64())
		binary.LittleEndian.PutUint64(tid[8:], rng.Uint64())
	}
	return tid
}

func (i *TraceContextInterceptor) newSpanID() trace.SpanID {
	rng := i.rngPool.Get().(*randv2.ChaCha8)
	defer i.rngPool.Put(rng)

	var sid trace.SpanID
	for !sid.IsValid() {
		binary.LittleEndian.PutUint64(sid[:], rng.Uint64())
	}
	return sid
}
