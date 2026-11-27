package oteltelemetry

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

const meterScopeName = "github.com/esachser/omnimeshdp"

var (
	defaultDurationMsBuckets = []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}
	defaultAuthzUsBuckets    = []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000}
)

type metricMeta struct {
	description string
	unit        string
}

var metricMetadata = map[string]metricMeta{
	outbound.MetricRequestsTotal:             {description: "Total requests proxied by the agent", unit: "1"},
	outbound.MetricRequestsIngressTotal:      {description: "Total requests received by local services", unit: "1"},
	outbound.MetricRequestsEgressTotal:       {description: "Total requests sent to upstream services", unit: "1"},
	outbound.MetricRequestsDurationMs:        {description: "End-to-end request latency from agent perspective", unit: "ms"},
	outbound.MetricRequestsActive:            {description: "Currently in-flight requests", unit: "1"},
	outbound.MetricRequestsBytesSent:         {description: "Total bytes sent in the request direction", unit: "By"},
	outbound.MetricRequestsBytesReceived:     {description: "Total bytes received in the response direction", unit: "By"},
	outbound.MetricConnectionsActive:         {description: "Currently active proxied connections", unit: "1"},
	outbound.MetricConnectionsTotal:          {description: "Total connections handled", unit: "1"},
	outbound.MetricConnectionsDurationMs:     {description: "Proxied connection lifetime", unit: "ms"},
	outbound.MetricHBONETunnelsActive:        {description: "Active HBONE HTTP/2 tunnels to peer agents", unit: "1"},
	outbound.MetricHBONEStreamsActive:        {description: "Active HBONE CONNECT HTTP/2 streams", unit: "1"},
	outbound.MetricHBONEStreamsTotal:         {description: "Total HBONE CONNECT streams opened", unit: "1"},
	outbound.MetricHBONEBytesSent:            {description: "Total bytes sent through HBONE tunnels", unit: "By"},
	outbound.MetricHBONEBytesReceived:        {description: "Total bytes received through HBONE tunnels", unit: "By"},
	outbound.MetricMTLSHandshakesTotal:       {description: "Total mTLS handshakes", unit: "1"},
	outbound.MetricMTLSHandshakesDurationMs:  {description: "mTLS handshake latency", unit: "ms"},
	outbound.MetricMTLSSVIDExpirySeconds:     {description: "Seconds until active SVID expires", unit: "s"},
	outbound.MetricMTLSSVIDRotationsTotal:    {description: "Total observed SVID rotations", unit: "1"},
	outbound.MetricRetriesTotal:              {description: "Total routing retry attempts", unit: "1"},
	outbound.MetricRetriesExhausted:          {description: "Connections where all retries were exhausted", unit: "1"},
	outbound.MetricRetriesSuccess:            {description: "Connections that succeeded on a retry attempt", unit: "1"},
	outbound.MetricLBSelectionsTotal:         {description: "Load balancer endpoint selections", unit: "1"},
	outbound.MetricLBEndpointsHealthy:        {description: "Number of healthy endpoints", unit: "1"},
	outbound.MetricLBEndpointsTotal:          {description: "Total endpoints configured", unit: "1"},
	outbound.MetricLBNoHealthyEndpoints:      {description: "Route resolutions finding zero healthy endpoints", unit: "1"},
	outbound.MetricHealthProbesTotal:         {description: "Active health check probes sent", unit: "1"},
	outbound.MetricHealthProbesDurationMs:    {description: "Active health check probe latency", unit: "ms"},
	outbound.MetricHealthTransitions:         {description: "Endpoint health state transitions", unit: "1"},
	outbound.MetricAuthzDecisionsTotal:       {description: "Authorization decisions evaluated", unit: "1"},
	outbound.MetricAuthzDenialsTotal:         {description: "Authorization denials by reason", unit: "1"},
	outbound.MetricAuthzEvaluationDurationUs: {description: "Authorization policy evaluation latency in microseconds", unit: "us"},
	outbound.MetricAuthzPoliciesCached:       {description: "Number of compiled policies in the agent cache", unit: "1"},
}

func buildMeterProvider(
	ctx context.Context,
	cfg model.MetricsConfig,
	res *resource.Resource,
	extraReaders []sdkmetric.Reader,
) (*sdkmetric.MeterProvider, *prometheus.Registry, error) {
	interval, err := cfg.ParsedExportInterval()
	if err != nil {
		return nil, nil, err
	}

	var opts []sdkmetric.Option
	opts = append(opts, sdkmetric.WithResource(res))
	if view := buildMetricsView(cfg.Cardinality); view != nil {
		opts = append(opts, sdkmetric.WithView(view))
	}

	var promReg *prometheus.Registry
	if cfg.Enabled {
		for _, expCfg := range cfg.Exporters {
			switch strings.ToLower(strings.TrimSpace(expCfg.Type)) {
			case "prometheus":
				if promReg == nil {
					promReg = prometheus.NewRegistry()
					// WithoutUnits prevents doubled suffixes such as _duration_ms_milliseconds.
					promExp, err := otelprom.New(
						otelprom.WithRegisterer(promReg),
						otelprom.WithoutUnits(),
					)
					if err != nil {
						return nil, nil, fmt.Errorf("failed to create prometheus exporter: %w", err)
					}
					opts = append(opts, sdkmetric.WithReader(promExp))
				}
			case "otlp-grpc":
				exp, err := newOTLPGRPCMetricExporter(ctx, expCfg)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to create OTLP gRPC metric exporter: %w", err)
				}
				opts = append(opts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(interval))))
			case "otlp-http":
				exp, err := newOTLPHTTPMetricExporter(ctx, expCfg)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to create OTLP HTTP metric exporter: %w", err)
				}
				opts = append(opts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(interval))))
			}
		}
	}

	for _, r := range extraReaders {
		if r != nil {
			opts = append(opts, sdkmetric.WithReader(r))
		}
	}

	mp := sdkmetric.NewMeterProvider(opts...)
	return mp, promReg, nil
}

func buildMetricsView(cardinality model.MetricsCardinalityConfig) sdkmetric.View {
	dropByMetric := make(map[string]map[string]struct{}, len(cardinality.DropLabels))
	for metricName, labels := range cardinality.DropLabels {
		if len(labels) == 0 {
			continue
		}
		set := make(map[string]struct{}, len(labels))
		for _, l := range labels {
			if trimmed := strings.TrimSpace(l); trimmed != "" {
				set[trimmed] = struct{}{}
			}
		}
		if len(set) > 0 {
			dropByMetric[metricName] = set
		}
	}

	durationMsBuckets := defaultDurationMsBuckets
	if custom, ok := cardinality.HistogramBuckets["duration_ms"]; ok && len(custom) > 0 {
		durationMsBuckets = slices.Clone(custom)
	}
	authzUsBuckets := defaultAuthzUsBuckets
	if custom, ok := cardinality.HistogramBuckets["authz_duration_us"]; ok && len(custom) > 0 {
		authzUsBuckets = slices.Clone(custom)
	}

	return func(inst sdkmetric.Instrument) (sdkmetric.Stream, bool) {
		var stream sdkmetric.Stream
		changed := false

		if dropSet, ok := dropByMetric[inst.Name]; ok && len(dropSet) > 0 {
			stream.AttributeFilter = func(kv attribute.KeyValue) bool {
				_, dropped := dropSet[string(kv.Key)]
				return !dropped
			}
			changed = true
		}

		if inst.Kind == sdkmetric.InstrumentKindHistogram {
			var boundaries []float64
			if exact, ok := cardinality.HistogramBuckets[inst.Name]; ok && len(exact) > 0 {
				boundaries = slices.Clone(exact)
			} else if inst.Name == outbound.MetricAuthzEvaluationDurationUs {
				boundaries = authzUsBuckets
			} else if strings.HasSuffix(inst.Name, ".duration_ms") {
				boundaries = durationMsBuckets
			}
			if len(boundaries) > 0 {
				stream.Aggregation = sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: boundaries,
				}
				changed = true
			}
		}

		if !changed {
			return sdkmetric.Stream{}, false
		}
		stream.Name = inst.Name
		stream.Description = inst.Description
		stream.Unit = inst.Unit
		return stream, true
	}
}

func newOTLPGRPCMetricExporter(ctx context.Context, cfg model.TelemetryExporterConfig) (sdkmetric.Exporter, error) {
	endpoint := stripEndpointScheme(cfg.Target)
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(endpoint),
	}
	if cfg.Insecure || strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.Target)), "http://") {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetricgrpc.WithHeaders(cfg.Headers))
	}
	if d, ok := parseOptionalDuration(cfg.Timeout); ok {
		opts = append(opts, otlpmetricgrpc.WithTimeout(d))
	}
	return otlpmetricgrpc.New(ctx, opts...)
}

func newOTLPHTTPMetricExporter(ctx context.Context, cfg model.TelemetryExporterConfig) (sdkmetric.Exporter, error) {
	target := strings.TrimSpace(cfg.Target)
	var opts []otlpmetrichttp.Option
	if u, ok := parseEndpointURL(target, "/v1/metrics"); ok {
		opts = append(opts, otlpmetrichttp.WithEndpointURL(u))
	} else {
		opts = append(opts, otlpmetrichttp.WithEndpoint(target))
	}
	if cfg.Insecure || strings.HasPrefix(strings.ToLower(target), "http://") {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
	}
	if d, ok := parseOptionalDuration(cfg.Timeout); ok {
		opts = append(opts, otlpmetrichttp.WithTimeout(d))
	}
	return otlpmetrichttp.New(ctx, opts...)
}

func stripEndpointScheme(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if idx := strings.Index(trimmed, "://"); idx != -1 {
		if u, err := url.Parse(trimmed); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return trimmed
}

func parseEndpointURL(raw, defaultPath string) (string, bool) {
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw, true
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = defaultPath
	}
	return u.String(), true
}

func parseOptionalDuration(raw string) (time.Duration, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}
	d, err := time.ParseDuration(trimmed)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

type otelMetricRecorder struct {
	meter          metric.Meter
	combinedReq    bool
	maxCardinality int

	mu             sync.RWMutex
	counters       map[string]metric.Int64Counter
	upDownCounters map[string]metric.Int64UpDownCounter
	gauges         map[string]metric.Float64Gauge
	histograms     map[string]metric.Float64Histogram

	cardMu   sync.Mutex
	cardSeen map[string]*cardinalityTracker
}

type cardinalityTracker struct {
	seen   map[uint64]struct{}
	warned bool
}

func newOTelMetricRecorder(mp *sdkmetric.MeterProvider, cfg model.MetricsConfig) *otelMetricRecorder {
	return &otelMetricRecorder{
		meter:          mp.Meter(meterScopeName),
		combinedReq:    cfg.CombinedRequestMetric.Enabled,
		maxCardinality: cfg.Cardinality.MaxLabelCardinality,
		counters:       make(map[string]metric.Int64Counter),
		upDownCounters: make(map[string]metric.Int64UpDownCounter),
		gauges:         make(map[string]metric.Float64Gauge),
		histograms:     make(map[string]metric.Float64Histogram),
		cardSeen:       make(map[string]*cardinalityTracker),
	}
}

func (r *otelMetricRecorder) CombinedRequestMetricEnabled() bool {
	return r.combinedReq
}

func (r *otelMetricRecorder) AddCounter(ctx context.Context, name string, delta int64, attrs ...model.MetricAttribute) {
	if r == nil || delta == 0 {
		return
	}
	inst := r.getCounter(name)
	if inst == nil {
		return
	}
	var buf [8]attribute.KeyValue
	kvs := toOTelAttrs(buf[:0], attrs)
	r.trackCardinality(name, attrs)
	inst.Add(ctx, delta, metric.WithAttributes(kvs...))
}

func (r *otelMetricRecorder) AddUpDownCounter(ctx context.Context, name string, delta int64, attrs ...model.MetricAttribute) {
	if r == nil || delta == 0 {
		return
	}
	inst := r.getUpDownCounter(name)
	if inst == nil {
		return
	}
	var buf [8]attribute.KeyValue
	kvs := toOTelAttrs(buf[:0], attrs)
	r.trackCardinality(name, attrs)
	inst.Add(ctx, delta, metric.WithAttributes(kvs...))
}

func (r *otelMetricRecorder) RecordGauge(ctx context.Context, name string, value float64, attrs ...model.MetricAttribute) {
	if r == nil {
		return
	}
	inst := r.getGauge(name)
	if inst == nil {
		return
	}
	var buf [8]attribute.KeyValue
	kvs := toOTelAttrs(buf[:0], attrs)
	r.trackCardinality(name, attrs)
	inst.Record(ctx, value, metric.WithAttributes(kvs...))
}

func (r *otelMetricRecorder) RecordHistogram(ctx context.Context, name string, value float64, attrs ...model.MetricAttribute) {
	if r == nil {
		return
	}
	inst := r.getHistogram(name)
	if inst == nil {
		return
	}
	var buf [8]attribute.KeyValue
	kvs := toOTelAttrs(buf[:0], attrs)
	r.trackCardinality(name, attrs)
	inst.Record(ctx, value, metric.WithAttributes(kvs...))
}

func (r *otelMetricRecorder) getCounter(name string) metric.Int64Counter {
	r.mu.RLock()
	c, ok := r.counters[name]
	r.mu.RUnlock()
	if ok {
		return c
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	meta := metricMetadata[name]
	c, err := r.meter.Int64Counter(name, metric.WithDescription(meta.description), metric.WithUnit(meta.unit))
	if err != nil {
		return nil
	}
	r.counters[name] = c
	return c
}

func (r *otelMetricRecorder) getUpDownCounter(name string) metric.Int64UpDownCounter {
	r.mu.RLock()
	c, ok := r.upDownCounters[name]
	r.mu.RUnlock()
	if ok {
		return c
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.upDownCounters[name]; ok {
		return c
	}
	meta := metricMetadata[name]
	c, err := r.meter.Int64UpDownCounter(name, metric.WithDescription(meta.description), metric.WithUnit(meta.unit))
	if err != nil {
		return nil
	}
	r.upDownCounters[name] = c
	return c
}

func (r *otelMetricRecorder) getGauge(name string) metric.Float64Gauge {
	r.mu.RLock()
	g, ok := r.gauges[name]
	r.mu.RUnlock()
	if ok {
		return g
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[name]; ok {
		return g
	}
	meta := metricMetadata[name]
	g, err := r.meter.Float64Gauge(name, metric.WithDescription(meta.description), metric.WithUnit(meta.unit))
	if err != nil {
		return nil
	}
	r.gauges[name] = g
	return g
}

func (r *otelMetricRecorder) getHistogram(name string) metric.Float64Histogram {
	r.mu.RLock()
	h, ok := r.histograms[name]
	r.mu.RUnlock()
	if ok {
		return h
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histograms[name]; ok {
		return h
	}
	meta := metricMetadata[name]
	h, err := r.meter.Float64Histogram(name, metric.WithDescription(meta.description), metric.WithUnit(meta.unit))
	if err != nil {
		return nil
	}
	r.histograms[name] = h
	return h
}

func (r *otelMetricRecorder) trackCardinality(name string, attrs []model.MetricAttribute) {
	if r.maxCardinality <= 0 {
		return
	}
	sig := hashMetricAttrs(attrs)

	r.cardMu.Lock()
	tracker, ok := r.cardSeen[name]
	if !ok {
		tracker = &cardinalityTracker{seen: make(map[uint64]struct{})}
		r.cardSeen[name] = tracker
	}
	if _, exists := tracker.seen[sig]; exists {
		r.cardMu.Unlock()
		return
	}
	if len(tracker.seen) <= r.maxCardinality {
		tracker.seen[sig] = struct{}{}
	}
	shouldWarn := !tracker.warned && len(tracker.seen) > r.maxCardinality
	if shouldWarn {
		tracker.warned = true
	}
	r.cardMu.Unlock()

	if shouldWarn {
		log.Printf("[Observability] Warning: metric %q exceeded max_label_cardinality=%d\n", name, r.maxCardinality)
	}
}

func hashMetricAttrs(attrs []model.MetricAttribute) uint64 {
	if len(attrs) == 0 {
		return 0
	}
	var buf [8]model.MetricAttribute
	cp := append(buf[:0], attrs...)
	if len(cp) > 1 {
		sort.Slice(cp, func(i, j int) bool {
			return cp[i].Key < cp[j].Key
		})
	}
	h := fnv.New64a()
	for _, a := range cp {
		_, _ = h.Write([]byte(a.Key))
		_, _ = h.Write([]byte{'='})
		_, _ = h.Write([]byte(a.Value))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}

func toOTelAttrs(dst []attribute.KeyValue, attrs []model.MetricAttribute) []attribute.KeyValue {
	for _, a := range attrs {
		if a.Key != "" {
			dst = append(dst, attribute.String(a.Key, a.Value))
		}
	}
	return dst
}
