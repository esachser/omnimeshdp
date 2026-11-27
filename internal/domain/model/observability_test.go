package model_test

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func TestDefaultObservabilityConfig(t *testing.T) {
	cfg := model.DefaultObservabilityConfig()
	if cfg.Metrics.Enabled {
		t.Fatalf("expected metrics.enabled to default to false")
	}
	if cfg.Metrics.Endpoint != model.DefaultMetricsEndpoint {
		t.Fatalf("expected default metrics endpoint %q, got %q", model.DefaultMetricsEndpoint, cfg.Metrics.Endpoint)
	}
	if cfg.Metrics.Path != model.DefaultMetricsPath {
		t.Fatalf("expected default metrics path %q, got %q", model.DefaultMetricsPath, cfg.Metrics.Path)
	}
	if cfg.Metrics.ExportInterval != "15s" {
		t.Fatalf("expected default export_interval 15s, got %q", cfg.Metrics.ExportInterval)
	}
	if !cfg.Metrics.CombinedRequestMetric.Enabled {
		t.Fatalf("expected combined_request_metric.enabled to default to true")
	}
	if len(cfg.Metrics.Exporters) != 1 || cfg.Metrics.Exporters[0].Type != "prometheus" {
		t.Fatalf("expected default prometheus exporter, got %+v", cfg.Metrics.Exporters)
	}
	if cfg.Traces.Enabled {
		t.Fatalf("expected traces.enabled to default to false")
	}
	if cfg.Traces.Sampler != "parentbased_traceidratio" || cfg.Traces.SampleRate != 0.01 {
		t.Fatalf("unexpected default trace sampler config: %+v", cfg.Traces)
	}
	if !cfg.Traces.AlwaysSampleErrors || cfg.Traces.MaxErrorTracesPerSec != 100 {
		t.Fatalf("unexpected default error sampling config: %+v", cfg.Traces)
	}
	if cfg.Resource.ServiceName != "omnimesh-agent" || cfg.Resource.ServiceNamespace != "omnimesh" {
		t.Fatalf("unexpected default resource config: %+v", cfg.Resource)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default observability config should be valid: %v", err)
	}
}

func TestObservabilityConfigLoadAndEnvOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")
	configJSON := `{
		"observability": {
			"metrics": {
				"enabled": true,
				"endpoint": "127.0.0.1:19091",
				"path": "/prom",
				"export_interval": "10s",
				"combined_request_metric": {"enabled": false},
				"exporters": [
					{"type": "prometheus"},
					{"type": "otlp-grpc", "target": "collector:4317", "insecure": true, "timeout": "5s"}
				],
				"cardinality": {
					"max_label_cardinality": 500,
					"drop_labels": {
						"omnimesh.agent.requests.total": ["source_service"]
					},
					"histogram_buckets": {
						"duration_ms": [1, 10, 100, 1000]
					}
				}
			},
			"traces": {
				"enabled": true,
				"sampler": "traceidratio",
				"sample_rate": 0.25,
				"always_sample_errors": false,
				"max_error_traces_per_sec": 50,
				"exporters": [
					{"type": "otlp-http", "target": "http://collector:4318", "insecure": true}
				]
			},
			"resource": {
				"service_name": "edge-agent",
				"service_namespace": "prod-mesh",
				"deployment_environment": "production",
				"attributes": {"region": "us-east-1"}
			}
		}
	}`
	if err := os.WriteFile(configFile, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if !cfg.Observability.Metrics.Enabled || cfg.Observability.Metrics.Endpoint != "127.0.0.1:19091" || cfg.Observability.Metrics.Path != "/prom" {
		t.Fatalf("unexpected metrics config: %+v", cfg.Observability.Metrics)
	}
	if cfg.Observability.Metrics.CombinedRequestMetric.Enabled {
		t.Fatalf("expected combined_request_metric.enabled=false")
	}
	if !cfg.Observability.Traces.Enabled || cfg.Observability.Traces.SampleRate != 0.25 || cfg.Observability.Traces.AlwaysSampleErrors {
		t.Fatalf("unexpected traces config: %+v", cfg.Observability.Traces)
	}
	if cfg.Observability.Resource.ServiceName != "edge-agent" || cfg.Observability.Resource.DeploymentEnvironment != "production" {
		t.Fatalf("unexpected resource config: %+v", cfg.Observability.Resource)
	}

	// Verify env overrides (including standard OTEL_* fallbacks).
	t.Setenv("OBSERVABILITY_METRICS_ENABLED", "false")
	t.Setenv("OBSERVABILITY_METRICS_ENDPOINT", "127.0.0.1:29091")
	t.Setenv("OBSERVABILITY_METRICS_PATH", "/metrics-env")
	t.Setenv("OBSERVABILITY_METRICS_EXPORT_INTERVAL", "20s")
	t.Setenv("OBSERVABILITY_METRICS_COMBINED_REQUEST_ENABLED", "true")
	t.Setenv("OBSERVABILITY_METRICS_OTLP_ENDPOINT", "otel-metrics:4318")
	t.Setenv("OBSERVABILITY_METRICS_OTLP_PROTOCOL", "http")
	t.Setenv("OBSERVABILITY_METRICS_OTLP_INSECURE", "true")

	t.Setenv("OBSERVABILITY_TRACES_ENABLED", "true")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "0.5")
	t.Setenv("OBSERVABILITY_TRACES_ALWAYS_SAMPLE_ERRORS", "true")
	t.Setenv("OBSERVABILITY_TRACES_MAX_ERROR_TRACES_PER_SEC", "200")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "otel-traces:4317")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc")
	t.Setenv("OBSERVABILITY_TRACES_OTLP_INSECURE", "true")

	t.Setenv("OTEL_SERVICE_NAME", "override-agent")
	t.Setenv("OBSERVABILITY_SERVICE_NAMESPACE", "override-ns")
	t.Setenv("OBSERVABILITY_DEPLOYMENT_ENVIRONMENT", "staging")

	cfgEnv, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig with env overrides failed: %v", err)
	}
	if cfgEnv.Observability.Metrics.Enabled || cfgEnv.Observability.Metrics.Endpoint != "127.0.0.1:29091" || cfgEnv.Observability.Metrics.Path != "/metrics-env" {
		t.Fatalf("unexpected metrics config after env override: %+v", cfgEnv.Observability.Metrics)
	}
	if !cfgEnv.Observability.Metrics.CombinedRequestMetric.Enabled || cfgEnv.Observability.Metrics.ExportInterval != "20s" {
		t.Fatalf("unexpected metrics toggles after env override: %+v", cfgEnv.Observability.Metrics)
	}
	if cfgEnv.Observability.Metrics.Exporters[1].Type != "otlp-http" || cfgEnv.Observability.Metrics.Exporters[1].Target != "otel-metrics:4318" {
		t.Fatalf("expected metrics OTLP exporter to be overridden, got %+v", cfgEnv.Observability.Metrics.Exporters)
	}
	if cfgEnv.Observability.Traces.Sampler != "always_on" || cfgEnv.Observability.Traces.SampleRate != 0.5 || !cfgEnv.Observability.Traces.AlwaysSampleErrors || cfgEnv.Observability.Traces.MaxErrorTracesPerSec != 200 {
		t.Fatalf("unexpected traces config after env override: %+v", cfgEnv.Observability.Traces)
	}
	if cfgEnv.Observability.Traces.Exporters[0].Type != "otlp-grpc" || cfgEnv.Observability.Traces.Exporters[0].Target != "otel-traces:4317" {
		t.Fatalf("expected traces OTLP exporter to be overridden, got %+v", cfgEnv.Observability.Traces.Exporters)
	}
	if cfgEnv.Observability.Resource.ServiceName != "override-agent" || cfgEnv.Observability.Resource.ServiceNamespace != "override-ns" || cfgEnv.Observability.Resource.DeploymentEnvironment != "staging" {
		t.Fatalf("unexpected resource config after env override: %+v", cfgEnv.Observability.Resource)
	}
}

func TestObservabilityConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.ObservabilityConfig)
	}{
		{
			name: "invalid metrics endpoint",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.Endpoint = "not-a-host-port"
			},
		},
		{
			name: "empty metrics endpoint when prometheus enabled",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.Enabled = true
				c.Metrics.Endpoint = ""
			},
		},
		{
			name: "metrics path without leading slash",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.Path = "metrics"
			},
		},
		{
			name: "non-positive export interval",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.ExportInterval = "0s"
			},
		},
		{
			name: "negative max label cardinality",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.Cardinality.MaxLabelCardinality = -1
			},
		},
		{
			name: "empty histogram buckets",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.Cardinality.HistogramBuckets["duration_ms"] = []float64{}
			},
		},
		{
			name: "non-increasing histogram buckets",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.Cardinality.HistogramBuckets["duration_ms"] = []float64{10, 10, 20}
			},
		},
		{
			name: "NaN histogram bucket",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.Cardinality.HistogramBuckets["duration_ms"] = []float64{1, math.NaN()}
			},
		},
		{
			name: "unsupported metrics exporter type",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.Exporters = []model.TelemetryExporterConfig{{Type: "statsd"}}
			},
		},
		{
			name: "otlp metric exporter missing target",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.Exporters = []model.TelemetryExporterConfig{{Type: "otlp-grpc"}}
			},
		},
		{
			name: "invalid exporter timeout",
			mutate: func(c *model.ObservabilityConfig) {
				c.Metrics.Exporters = []model.TelemetryExporterConfig{{Type: "otlp-grpc", Target: "localhost:4317", Timeout: "-1s"}}
			},
		},
		{
			name: "unsupported trace sampler",
			mutate: func(c *model.ObservabilityConfig) {
				c.Traces.Sampler = "unknown_sampler"
			},
		},
		{
			name: "sample rate out of range",
			mutate: func(c *model.ObservabilityConfig) {
				c.Traces.SampleRate = 1.5
			},
		},
		{
			name: "negative max error traces per sec",
			mutate: func(c *model.ObservabilityConfig) {
				c.Traces.MaxErrorTracesPerSec = -5
			},
		},
		{
			name: "unsupported trace exporter",
			mutate: func(c *model.ObservabilityConfig) {
				c.Traces.Exporters = []model.TelemetryExporterConfig{{Type: "jaeger", Target: "localhost:14250"}}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.DefaultObservabilityConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error for %s, got nil", tc.name)
			}
			if !errors.Is(err, domain.ErrInvalidObservabilityConfig) {
				t.Fatalf("expected ErrInvalidObservabilityConfig, got %v", err)
			}
		})
	}
}

func TestParseCallerService(t *testing.T) {
	svc, ns := model.ParseCallerService("spiffe://omnimesh.local/ns/prod/sa/frontend")
	if svc != "frontend" || ns != "prod" {
		t.Fatalf("expected (frontend, prod), got (%q, %q)", svc, ns)
	}

	svc, ns = model.ParseCallerService("spiffe://omnimesh.local/spire/agent/node-1")
	if svc != "unknown" || ns != "unknown" {
		t.Fatalf("expected non-workload SPIFFE ID to map to (unknown, unknown), got (%q, %q)", svc, ns)
	}

	svc, ns = model.ParseCallerService("")
	if svc != "unknown" || ns != "unknown" {
		t.Fatalf("expected empty identity to map to (unknown, unknown), got (%q, %q)", svc, ns)
	}
}
