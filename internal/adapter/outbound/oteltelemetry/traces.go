package oteltelemetry

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const tracerScopeName = "github.com/esachser/omnimeshdp"

func buildTracerProvider(
	ctx context.Context,
	cfg model.TracesConfig,
	res *resource.Resource,
	extraExporters []sdktrace.SpanExporter,
	syncProcessor bool,
) (*sdktrace.TracerProvider, error) {
	baseSampler := buildBaseSampler(cfg)
	sampler := baseSampler
	if cfg.AlwaysSampleErrors {
		sampler = &errorAwareSampler{base: baseSampler}
	}

	var exporters []sdktrace.SpanExporter
	if cfg.Enabled {
		for _, expCfg := range cfg.Exporters {
			switch strings.ToLower(strings.TrimSpace(expCfg.Type)) {
			case "none", "":
			case "otlp-grpc":
				exp, err := newOTLPGRPCTraceExporter(ctx, expCfg)
				if err != nil {
					return nil, fmt.Errorf("failed to create OTLP gRPC trace exporter: %w", err)
				}
				exporters = append(exporters, exp)
			case "otlp-http":
				exp, err := newOTLPHTTPTraceExporter(ctx, expCfg)
				if err != nil {
					return nil, fmt.Errorf("failed to create OTLP HTTP trace exporter: %w", err)
				}
				exporters = append(exporters, exp)
			}
		}
	}
	for _, exp := range extraExporters {
		if exp != nil {
			exporters = append(exporters, exp)
		}
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	}
	for _, exp := range exporters {
		var sp sdktrace.SpanProcessor
		if syncProcessor {
			sp = sdktrace.NewSimpleSpanProcessor(exp)
		} else {
			sp = sdktrace.NewBatchSpanProcessor(exp)
		}
		if cfg.AlwaysSampleErrors {
			sp = newErrorSamplingSpanProcessor(sp, cfg.MaxErrorTracesPerSec)
		}
		opts = append(opts, sdktrace.WithSpanProcessor(sp))
	}

	return sdktrace.NewTracerProvider(opts...), nil
}

func buildBaseSampler(cfg model.TracesConfig) sdktrace.Sampler {
	switch cfg.NormalizedSampler() {
	case "always_on":
		return sdktrace.AlwaysSample()
	case "always_off":
		return sdktrace.NeverSample()
	case "traceidratio":
		return sdktrace.TraceIDRatioBased(cfg.SampleRate)
	default: // "parentbased_traceidratio"
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))
	}
}

func newOTLPGRPCTraceExporter(ctx context.Context, cfg model.TelemetryExporterConfig) (sdktrace.SpanExporter, error) {
	endpoint := stripEndpointScheme(cfg.Target)
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(endpoint),
	}
	if cfg.Insecure || strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.Target)), "http://") {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
	}
	if d, ok := parseOptionalDuration(cfg.Timeout); ok {
		opts = append(opts, otlptracegrpc.WithTimeout(d))
	}
	return otlptracegrpc.New(ctx, opts...)
}

func newOTLPHTTPTraceExporter(ctx context.Context, cfg model.TelemetryExporterConfig) (sdktrace.SpanExporter, error) {
	target := strings.TrimSpace(cfg.Target)
	var opts []otlptracehttp.Option
	if u, ok := parseEndpointURL(target, "/v1/traces"); ok {
		opts = append(opts, otlptracehttp.WithEndpointURL(u))
	} else {
		opts = append(opts, otlptracehttp.WithEndpoint(target))
	}
	if cfg.Insecure || strings.HasPrefix(strings.ToLower(target), "http://") {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
	}
	if d, ok := parseOptionalDuration(cfg.Timeout); ok {
		opts = append(opts, otlptracehttp.WithTimeout(d))
	}
	return otlptracehttp.New(ctx, opts...)
}

// errorAwareSampler upgrades Drop decisions to RecordOnly so error spans still record
// attributes and status in memory without forcing non-error spans to be exported.
type errorAwareSampler struct {
	base sdktrace.Sampler
}

func (s *errorAwareSampler) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	res := s.base.ShouldSample(p)
	if res.Decision == sdktrace.Drop {
		res.Decision = sdktrace.RecordOnly
		if parentSC := trace.SpanContextFromContext(p.ParentContext); parentSC.IsValid() {
			res.Tracestate = parentSC.TraceState()
		}
	}
	return res
}

func (s *errorAwareSampler) Description() string {
	return "ErrorAware(" + s.base.Description() + ")"
}

// errorSamplingSpanProcessor promotes unsampled error spans to sampled within a per-second rate cap
// before forwarding to the wrapped SpanProcessor.
type errorSamplingSpanProcessor struct {
	next    sdktrace.SpanProcessor
	limiter *tokenBucketLimiter
}

func newErrorSamplingSpanProcessor(next sdktrace.SpanProcessor, maxPerSec int) *errorSamplingSpanProcessor {
	var limiter *tokenBucketLimiter
	if maxPerSec > 0 {
		limiter = newTokenBucketLimiter(maxPerSec)
	}
	return &errorSamplingSpanProcessor{
		next:    next,
		limiter: limiter,
	}
}

func (p *errorSamplingSpanProcessor) OnStart(parent context.Context, s sdktrace.ReadWriteSpan) {
	p.next.OnStart(parent, s)
}

func (p *errorSamplingSpanProcessor) OnEnd(s sdktrace.ReadOnlySpan) {
	if s.SpanContext().IsSampled() {
		p.next.OnEnd(s)
		return
	}
	if s.Status().Code == codes.Error && (p.limiter == nil || p.limiter.Allow()) {
		p.next.OnEnd(promotedSampledSpan{ReadOnlySpan: s})
	}
}

func (p *errorSamplingSpanProcessor) Shutdown(ctx context.Context) error {
	return p.next.Shutdown(ctx)
}

func (p *errorSamplingSpanProcessor) ForceFlush(ctx context.Context) error {
	return p.next.ForceFlush(ctx)
}

type promotedSampledSpan struct {
	sdktrace.ReadOnlySpan
}

func (s promotedSampledSpan) SpanContext() trace.SpanContext {
	return s.ReadOnlySpan.SpanContext().WithTraceFlags(s.ReadOnlySpan.SpanContext().TraceFlags() | trace.FlagsSampled)
}

type tokenBucketLimiter struct {
	mu         sync.Mutex
	rate       float64
	capacity   float64
	tokens     float64
	lastRefill time.Time
}

func newTokenBucketLimiter(perSec int) *tokenBucketLimiter {
	cap := float64(perSec)
	return &tokenBucketLimiter{
		rate:       cap,
		capacity:   cap,
		tokens:     cap,
		lastRefill: time.Now(),
	}
}

func (l *tokenBucketLimiter) Allow() bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	elapsed := now.Sub(l.lastRefill).Seconds()
	if elapsed > 0 {
		l.tokens += elapsed * l.rate
		if l.tokens > l.capacity {
			l.tokens = l.capacity
		}
		l.lastRefill = now
	}
	if l.tokens < 1.0 {
		return false
	}
	l.tokens -= 1.0
	return true
}

type otelTraceRecorder struct {
	tracer     trace.Tracer
	propagator propagation.TextMapPropagator
}

func newOTelTraceRecorder(tp *sdktrace.TracerProvider) *otelTraceRecorder {
	return &otelTraceRecorder{
		tracer: tp.Tracer(tracerScopeName),
		propagator: propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	}
}

func (r *otelTraceRecorder) StartSpan(
	ctx context.Context,
	name string,
	kind model.SpanKind,
	attrs ...model.MetricAttribute,
) (context.Context, outbound.SpanHandle) {
	if r == nil {
		return ctx, outbound.NoopSpanHandle{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var buf [8]attribute.KeyValue
	kvs := toOTelAttrs(buf[:0], attrs)
	spanCtx, span := r.tracer.Start(
		ctx,
		name,
		trace.WithSpanKind(toOTelSpanKind(kind)),
		trace.WithAttributes(kvs...),
	)
	return spanCtx, otelSpanHandle{span: span}
}

func (r *otelTraceRecorder) SpanFromContext(ctx context.Context) outbound.SpanHandle {
	if r == nil || ctx == nil {
		return outbound.NoopSpanHandle{}
	}
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return outbound.NoopSpanHandle{}
	}
	return otelSpanHandle{span: span}
}

func (r *otelTraceRecorder) InjectContext(ctx context.Context, carrier outbound.PropagationCarrier) {
	if r == nil || ctx == nil || carrier == nil {
		return
	}
	r.propagator.Inject(ctx, propagationCarrierAdapter{carrier: carrier})
}

func (r *otelTraceRecorder) ExtractContext(ctx context.Context, carrier outbound.PropagationCarrier) context.Context {
	if r == nil || carrier == nil {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return r.propagator.Extract(ctx, propagationCarrierAdapter{carrier: carrier})
}

func (r *otelTraceRecorder) SpanContextFromContext(ctx context.Context) model.SpanContext {
	if r == nil || ctx == nil {
		return model.SpanContext{}
	}
	sc := trace.SpanFromContext(ctx).SpanContext()
	return toModelSpanContext(sc)
}

type otelSpanHandle struct {
	span trace.Span
}

func (h otelSpanHandle) SetName(name string) {
	if h.span != nil && name != "" {
		h.span.SetName(name)
	}
}

func (h otelSpanHandle) SetAttributes(attrs ...model.MetricAttribute) {
	if h.span == nil || len(attrs) == 0 {
		return
	}
	var buf [8]attribute.KeyValue
	h.span.SetAttributes(toOTelAttrs(buf[:0], attrs)...)
}

func (h otelSpanHandle) SetError(err error, description string) {
	if h.span == nil {
		return
	}
	if err != nil {
		h.span.RecordError(err)
		if description == "" {
			description = err.Error()
		}
	}
	h.span.SetStatus(codes.Error, description)
}

func (h otelSpanHandle) SpanContext() model.SpanContext {
	if h.span == nil {
		return model.SpanContext{}
	}
	return toModelSpanContext(h.span.SpanContext())
}

func (h otelSpanHandle) End() {
	if h.span != nil {
		h.span.End()
	}
}

type propagationCarrierAdapter struct {
	carrier outbound.PropagationCarrier
}

func (a propagationCarrierAdapter) Get(key string) string        { return a.carrier.Get(key) }
func (a propagationCarrierAdapter) Set(key, value string)        { a.carrier.Set(key, value) }
func (a propagationCarrierAdapter) Keys() []string               { return a.carrier.Keys() }

func toOTelSpanKind(kind model.SpanKind) trace.SpanKind {
	switch kind {
	case model.SpanKindClient:
		return trace.SpanKindClient
	case model.SpanKindServer:
		return trace.SpanKindServer
	default:
		return trace.SpanKindInternal
	}
}

func toModelSpanContext(sc trace.SpanContext) model.SpanContext {
	if !sc.IsValid() {
		return model.SpanContext{}
	}
	tid := sc.TraceID()
	sid := sc.SpanID()
	return model.SpanContext{
		TraceID:    hex.EncodeToString(tid[:]),
		SpanID:     hex.EncodeToString(sid[:]),
		TraceFlags: byte(sc.TraceFlags()),
		Sampled:    sc.IsSampled(),
		Valid:      true,
	}
}
