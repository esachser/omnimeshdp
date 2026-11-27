package oteltelemetry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
)

var _ outbound.TelemetryProvider = (*Provider)(nil)

// Option configures an oteltelemetry.Provider.
type Option func(*providerOptions)

type providerOptions struct {
	extraMetricReaders    []sdkmetric.Reader
	extraSpanExporters    []sdktrace.SpanExporter
	syncSpanProcessor     bool
	metricsListener       net.Listener
	metricsListenerOpener func(network, addr string) (net.Listener, error)
}

// WithMetricReader attaches an additional sdkmetric.Reader (e.g., sdkmetric.NewManualReader in tests).
func WithMetricReader(r sdkmetric.Reader) Option {
	return func(o *providerOptions) {
		if r != nil {
			o.extraMetricReaders = append(o.extraMetricReaders, r)
		}
	}
}

// WithSpanExporter attaches an additional sdktrace.SpanExporter (e.g., tracetest.NewInMemoryExporter in tests).
func WithSpanExporter(e sdktrace.SpanExporter) Option {
	return func(o *providerOptions) {
		if e != nil {
			o.extraSpanExporters = append(o.extraSpanExporters, e)
		}
	}
}

// WithSyncSpanProcessor configures tracing to export ended spans synchronously via SimpleSpanProcessor.
// Useful for deterministic tests.
func WithSyncSpanProcessor() Option {
	return func(o *providerOptions) {
		o.syncSpanProcessor = true
	}
}

// WithMetricsListener supplies a pre-bound net.Listener for the Prometheus HTTP scrape server.
func WithMetricsListener(ln net.Listener) Option {
	return func(o *providerOptions) {
		o.metricsListener = ln
	}
}

// WithMetricsListenerOpener supplies a custom listener opener for the Prometheus HTTP scrape server.
func WithMetricsListenerOpener(fn func(network, addr string) (net.Listener, error)) Option {
	return func(o *providerOptions) {
		o.metricsListenerOpener = fn
	}
}

// Provider implements outbound.TelemetryProvider using the OpenTelemetry Go SDK.
type Provider struct {
	cfg            model.ObservabilityConfig
	meterProvider  *sdkmetric.MeterProvider
	tracerProvider *sdktrace.TracerProvider
	metricsRec     outbound.MetricRecorder
	traceRec       outbound.TraceRecorder

	promRegistry  *prometheus.Registry
	metricsServer *http.Server
	metricsLn     net.Listener
	metricsAddr   string
	httpWG        sync.WaitGroup
}

// NewProvider validates cfg, builds the OTel Resource, initializes configured metric and trace
// pipelines (plus Prometheus HTTP endpoint when configured), and returns a ready Provider.
func NewProvider(ctx context.Context, cfg model.ObservabilityConfig, nodeID string, opts ...Option) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var pOpts providerOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&pOpts)
		}
	}

	res, err := buildResource(cfg.Resource, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to build OpenTelemetry resource: %w", err)
	}

	p := &Provider{
		cfg:        cfg,
		metricsRec: outbound.NoopMetricRecorder{},
		traceRec:   outbound.NoopTraceRecorder{},
	}

	cleanupOnErr := func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = p.Shutdown(shutCtx)
	}

	if cfg.Metrics.Enabled || len(pOpts.extraMetricReaders) > 0 {
		mp, promReg, err := buildMeterProvider(ctx, cfg.Metrics, res, pOpts.extraMetricReaders)
		if err != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("failed to initialize metrics pipeline: %w", err)
		}
		p.meterProvider = mp
		p.promRegistry = promReg
		p.metricsRec = newOTelMetricRecorder(mp, cfg.Metrics)

		if cfg.Metrics.Enabled && promReg != nil {
			if err := p.startPrometheusServer(cfg.Metrics, promReg, &pOpts); err != nil {
				cleanupOnErr()
				return nil, fmt.Errorf("failed to start Prometheus metrics server: %w", err)
			}
		}
	}

	if cfg.Traces.Enabled || len(pOpts.extraSpanExporters) > 0 {
		tp, err := buildTracerProvider(ctx, cfg.Traces, res, pOpts.extraSpanExporters, pOpts.syncSpanProcessor)
		if err != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("failed to initialize tracing pipeline: %w", err)
		}
		p.tracerProvider = tp
		p.traceRec = newOTelTraceRecorder(tp)
	}

	return p, nil
}

// Metrics returns the configured MetricRecorder (or NoopMetricRecorder when metrics are disabled).
func (p *Provider) Metrics() outbound.MetricRecorder {
	if p == nil || p.metricsRec == nil {
		return outbound.NoopMetricRecorder{}
	}
	return p.metricsRec
}

// Tracer returns the configured TraceRecorder (or NoopTraceRecorder when tracing is disabled).
func (p *Provider) Tracer() outbound.TraceRecorder {
	if p == nil || p.traceRec == nil {
		return outbound.NoopTraceRecorder{}
	}
	return p.traceRec
}

// MetricsAddr returns the bound address of the Prometheus HTTP scrape server, or "" if not running.
func (p *Provider) MetricsAddr() string {
	if p == nil {
		return ""
	}
	return p.metricsAddr
}

// Shutdown gracefully stops the Prometheus HTTP server and flushes/shuts down OTel providers.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var errs []error
	if p.metricsServer != nil {
		if err := p.metricsServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, err)
		}
		p.httpWG.Wait()
	} else if p.metricsLn != nil {
		_ = p.metricsLn.Close()
	}

	if p.tracerProvider != nil {
		if err := p.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if p.meterProvider != nil {
		if err := p.meterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (p *Provider) startPrometheusServer(cfg model.MetricsConfig, reg *prometheus.Registry, pOpts *providerOptions) error {
	ln := pOpts.metricsListener
	if ln == nil {
		endpoint := strings.TrimSpace(cfg.Endpoint)
		if endpoint == "" {
			endpoint = model.DefaultMetricsEndpoint
		}
		opener := pOpts.metricsListenerOpener
		if opener == nil {
			opener = net.Listen
		}
		var err error
		ln, err = opener("tcp", endpoint)
		if err != nil {
			return err
		}
	}

	mux := http.NewServeMux()
	metricsPath := cfg.NormalizedPath()
	mux.Handle(metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))
	if metricsPath != "/healthz" {
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	p.metricsLn = ln
	p.metricsAddr = ln.Addr().String()
	p.metricsServer = srv

	p.httpWG.Add(1)
	go func() {
		defer p.httpWG.Done()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[Observability] Prometheus HTTP server exited with error: %v\n", err)
		}
	}()

	log.Printf("[Observability] Prometheus metrics endpoint listening on http://%s%s\n", p.metricsAddr, metricsPath)
	return nil
}

func buildResource(cfg model.TelemetryResourceConfig, nodeID string) (*resource.Resource, error) {
	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = "omnimesh-agent"
	}
	serviceNamespace := strings.TrimSpace(cfg.ServiceNamespace)
	if serviceNamespace == "" {
		serviceNamespace = "omnimesh"
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String(serviceName),
		semconv.ServiceNamespaceKey.String(serviceNamespace),
	}
	if env := strings.TrimSpace(cfg.DeploymentEnvironment); env != "" {
		attrs = append(attrs, attribute.String("deployment.environment.name", env))
	}
	if strings.TrimSpace(nodeID) != "" {
		attrs = append(attrs, attribute.String(outbound.AttrNode, strings.TrimSpace(nodeID)))
	}
	if len(cfg.Attributes) > 0 {
		keys := make([]string, 0, len(cfg.Attributes))
		for k := range cfg.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.TrimSpace(k) != "" {
				attrs = append(attrs, attribute.String(k, cfg.Attributes[k]))
			}
		}
	}

	return resource.Merge(
		resource.Default(),
		resource.NewSchemaless(attrs...),
	)
}
