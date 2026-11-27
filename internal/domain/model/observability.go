package model

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain"
)

const (
	// DefaultMetricsEndpoint is the default Prometheus scrape listen address for the agent.
	DefaultMetricsEndpoint = ":9091"
	// DefaultMetricsPath is the default HTTP path serving Prometheus exposition metrics.
	DefaultMetricsPath = "/metrics"
	// DefaultMetricsExportInterval is the default push interval for OTLP metric exporters.
	DefaultMetricsExportInterval = 15 * time.Second
	// DefaultMaxLabelCardinality is the default warning threshold for unique label combinations per metric.
	DefaultMaxLabelCardinality = 1000
	// DefaultTraceSampleRate is the default head-based sampling probability (1%).
	DefaultTraceSampleRate = 0.01
	// DefaultMaxErrorTracesPerSec caps error-promoted spans per second to avoid backend spikes during outages.
	DefaultMaxErrorTracesPerSec = 100
)

// MetricAttribute represents a low-cardinality key-value attribute attached to metrics or spans.
type MetricAttribute struct {
	Key   string
	Value string
}

// SpanKind classifies the role of a distributed trace span.
type SpanKind int

const (
	SpanKindInternal SpanKind = iota
	SpanKindClient
	SpanKindServer
)

// SpanContext holds domain-level trace correlation identifiers without coupling to an OTel SDK.
type SpanContext struct {
	TraceID    string
	SpanID     string
	TraceFlags byte
	Sampled    bool
	Valid      bool
}

// ObservabilityConfig configures OpenTelemetry metrics and distributed tracing per spec/observability.md.
type ObservabilityConfig struct {
	Metrics  MetricsConfig           `json:"metrics"`
	Traces   TracesConfig            `json:"traces"`
	Resource TelemetryResourceConfig `json:"resource"`
}

// MetricsConfig configures OTel metrics collection, exporters, and cardinality controls.
type MetricsConfig struct {
	Enabled               bool                        `json:"enabled"`
	Endpoint              string                      `json:"endpoint"`
	Path                  string                      `json:"path"`
	ExportInterval        string                      `json:"export_interval"`
	CombinedRequestMetric CombinedRequestMetricConfig `json:"combined_request_metric"`
	Exporters             []TelemetryExporterConfig   `json:"exporters"`
	Cardinality           MetricsCardinalityConfig    `json:"cardinality"`
}

// CombinedRequestMetricConfig toggles the combined source x destination request counter.
type CombinedRequestMetricConfig struct {
	Enabled bool `json:"enabled"`
}

// MetricsCardinalityConfig controls label dropping, cardinality warnings, and histogram buckets.
type MetricsCardinalityConfig struct {
	MaxLabelCardinality int                  `json:"max_label_cardinality"`
	DropLabels          map[string][]string  `json:"drop_labels,omitempty"`
	HistogramBuckets    map[string][]float64 `json:"histogram_buckets,omitempty"`
}

// TracesConfig configures OTel distributed tracing sampling and exporters.
type TracesConfig struct {
	Enabled              bool                      `json:"enabled"`
	Sampler              string                    `json:"sampler"`
	SampleRate           float64                   `json:"sample_rate"`
	AlwaysSampleErrors   bool                      `json:"always_sample_errors"`
	MaxErrorTracesPerSec int                       `json:"max_error_traces_per_sec"`
	Exporters            []TelemetryExporterConfig `json:"exporters"`
}

// TelemetryExporterConfig describes a pull (prometheus) or push (otlp-grpc / otlp-http) exporter.
type TelemetryExporterConfig struct {
	Type     string            `json:"type"`
	Target   string            `json:"target,omitempty"`
	Insecure bool              `json:"insecure,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Timeout  string            `json:"timeout,omitempty"`
}

// TelemetryResourceConfig configures standard OpenTelemetry resource attributes.
type TelemetryResourceConfig struct {
	ServiceName           string            `json:"service_name"`
	ServiceNamespace      string            `json:"service_namespace"`
	DeploymentEnvironment string            `json:"deployment_environment,omitempty"`
	Attributes            map[string]string `json:"attributes,omitempty"`
}

// DefaultObservabilityConfig returns the default RFC-0005 aligned configuration (opt-in disabled by default).
func DefaultObservabilityConfig() ObservabilityConfig {
	return ObservabilityConfig{
		Metrics: MetricsConfig{
			Enabled:        false,
			Endpoint:       DefaultMetricsEndpoint,
			Path:           DefaultMetricsPath,
			ExportInterval: "15s",
			CombinedRequestMetric: CombinedRequestMetricConfig{
				Enabled: true,
			},
			Exporters: []TelemetryExporterConfig{
				{Type: "prometheus"},
			},
			Cardinality: MetricsCardinalityConfig{
				MaxLabelCardinality: DefaultMaxLabelCardinality,
				HistogramBuckets: map[string][]float64{
					"duration_ms":       {1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
					"authz_duration_us": {1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000},
				},
			},
		},
		Traces: TracesConfig{
			Enabled:              false,
			Sampler:              "parentbased_traceidratio",
			SampleRate:           DefaultTraceSampleRate,
			AlwaysSampleErrors:   true,
			MaxErrorTracesPerSec: DefaultMaxErrorTracesPerSec,
		},
		Resource: TelemetryResourceConfig{
			ServiceName:      "omnimesh-agent",
			ServiceNamespace: "omnimesh",
		},
	}
}

// ParsedExportInterval parses and validates MetricsConfig.ExportInterval.
func (m MetricsConfig) ParsedExportInterval() (time.Duration, error) {
	raw := strings.TrimSpace(m.ExportInterval)
	if raw == "" {
		return DefaultMetricsExportInterval, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid metrics.export_interval %q: %w", domain.ErrInvalidObservabilityConfig, m.ExportInterval, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%w: metrics.export_interval must be > 0, got %v", domain.ErrInvalidObservabilityConfig, d)
	}
	return d, nil
}

// NormalizedPath returns the HTTP path for Prometheus scraping, defaulting to "/metrics".
func (m MetricsConfig) NormalizedPath() string {
	p := strings.TrimSpace(m.Path)
	if p == "" {
		return DefaultMetricsPath
	}
	return p
}

// NormalizedSampler returns the canonical lowercase trace sampler name.
func (t TracesConfig) NormalizedSampler() string {
	s := strings.ToLower(strings.TrimSpace(t.Sampler))
	if s == "" {
		return "parentbased_traceidratio"
	}
	return s
}

// Validate validates ObservabilityConfig and all nested metric, trace, and exporter settings.
func (c ObservabilityConfig) Validate() error {
	if err := c.Metrics.validate(); err != nil {
		return err
	}
	if err := c.Traces.validate(); err != nil {
		return err
	}
	return nil
}

func (m MetricsConfig) validate() error {
	hasPrometheus := false
	for i, exp := range m.Exporters {
		typ := strings.ToLower(strings.TrimSpace(exp.Type))
		switch typ {
		case "prometheus":
			hasPrometheus = true
		case "otlp-grpc", "otlp-http":
			if strings.TrimSpace(exp.Target) == "" {
				return fmt.Errorf("%w: metrics.exporters[%d] (%s) requires a non-empty target", domain.ErrInvalidObservabilityConfig, i, typ)
			}
		default:
			return fmt.Errorf("%w: metrics.exporters[%d] has unsupported type %q", domain.ErrInvalidObservabilityConfig, i, exp.Type)
		}
		if err := validateExporterTimeout(exp.Timeout, fmt.Sprintf("metrics.exporters[%d]", i)); err != nil {
			return err
		}
	}

	endpoint := strings.TrimSpace(m.Endpoint)
	if endpoint != "" {
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return fmt.Errorf("%w: invalid metrics.endpoint %q: %w", domain.ErrInvalidObservabilityConfig, m.Endpoint, err)
		}
	} else if m.Enabled && hasPrometheus {
		return fmt.Errorf("%w: metrics.endpoint is required when prometheus exporter is enabled", domain.ErrInvalidObservabilityConfig)
	}

	if p := strings.TrimSpace(m.Path); p != "" && !strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: metrics.path must start with '/', got %q", domain.ErrInvalidObservabilityConfig, m.Path)
	}

	if _, err := m.ParsedExportInterval(); err != nil {
		return err
	}

	if m.Cardinality.MaxLabelCardinality < 0 {
		return fmt.Errorf("%w: metrics.cardinality.max_label_cardinality must be >= 0, got %d",
			domain.ErrInvalidObservabilityConfig, m.Cardinality.MaxLabelCardinality)
	}

	for name, buckets := range m.Cardinality.HistogramBuckets {
		if len(buckets) == 0 {
			return fmt.Errorf("%w: metrics.cardinality.histogram_buckets[%q] must not be empty",
				domain.ErrInvalidObservabilityConfig, name)
		}
		for i, b := range buckets {
			if math.IsNaN(b) || math.IsInf(b, 0) {
				return fmt.Errorf("%w: metrics.cardinality.histogram_buckets[%q][%d] must be finite",
					domain.ErrInvalidObservabilityConfig, name, i)
			}
			if i > 0 && b <= buckets[i-1] {
				return fmt.Errorf("%w: metrics.cardinality.histogram_buckets[%q] must be strictly increasing",
					domain.ErrInvalidObservabilityConfig, name)
			}
		}
	}

	return nil
}

func (t TracesConfig) validate() error {
	switch t.NormalizedSampler() {
	case "parentbased_traceidratio", "always_on", "always_off", "traceidratio":
	default:
		return fmt.Errorf("%w: unsupported traces.sampler %q", domain.ErrInvalidObservabilityConfig, t.Sampler)
	}

	if math.IsNaN(t.SampleRate) || t.SampleRate < 0.0 || t.SampleRate > 1.0 {
		return fmt.Errorf("%w: traces.sample_rate must be in [0.0, 1.0], got %v", domain.ErrInvalidObservabilityConfig, t.SampleRate)
	}

	if t.MaxErrorTracesPerSec < 0 {
		return fmt.Errorf("%w: traces.max_error_traces_per_sec must be >= 0, got %d",
			domain.ErrInvalidObservabilityConfig, t.MaxErrorTracesPerSec)
	}

	for i, exp := range t.Exporters {
		typ := strings.ToLower(strings.TrimSpace(exp.Type))
		switch typ {
		case "none":
		case "otlp-grpc", "otlp-http":
			if strings.TrimSpace(exp.Target) == "" {
				return fmt.Errorf("%w: traces.exporters[%d] (%s) requires a non-empty target", domain.ErrInvalidObservabilityConfig, i, typ)
			}
		default:
			return fmt.Errorf("%w: traces.exporters[%d] has unsupported type %q", domain.ErrInvalidObservabilityConfig, i, exp.Type)
		}
		if err := validateExporterTimeout(exp.Timeout, fmt.Sprintf("traces.exporters[%d]", i)); err != nil {
			return err
		}
	}

	return nil
}

func validateExporterTimeout(raw, field string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	d, err := time.ParseDuration(trimmed)
	if err != nil {
		return fmt.Errorf("%w: invalid %s.timeout %q: %w", domain.ErrInvalidObservabilityConfig, field, raw, err)
	}
	if d <= 0 {
		return fmt.Errorf("%w: %s.timeout must be > 0, got %v", domain.ErrInvalidObservabilityConfig, field, d)
	}
	return nil
}

// ParseCallerService normalizes a SPIFFE workload URI (spiffe://<td >/ns/<ns>/sa/<sa>)
// into low-cardinality (serviceName, namespace) telemetry labels, returning ("unknown", "unknown")
// when the identity is empty or not a workload SVID.
func ParseCallerService(callerIdentity string) (serviceName, namespace string) {
	if id, ok := ParseSPIFFEIdentity(callerIdentity); ok && id.IsWorkload {
		return id.ServiceName, id.Namespace
	}
	return "unknown", "unknown"
}
