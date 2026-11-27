package oteltelemetry_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/oteltelemetry"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestPrometheusScrapeAndOpenMetrics(t *testing.T) {
	cfg := model.DefaultObservabilityConfig()
	cfg.Metrics.Enabled = true
	cfg.Metrics.Endpoint = "127.0.0.1:0"
	cfg.Metrics.Path = "/metrics"
	cfg.Resource.DeploymentEnvironment = "testing"
	cfg.Resource.Attributes = map[string]string{"cluster": "dev-1"}

	reader := sdkmetric.NewManualReader()
	prov, err := oteltelemetry.NewProvider(context.Background(), cfg, "node-test-1", oteltelemetry.WithMetricReader(reader))
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer func() { _ = prov.Shutdown(context.Background()) }()

	addr := prov.MetricsAddr()
	if addr == "" {
		t.Fatalf("expected non-empty Prometheus metrics listen address")
	}

	m := prov.Metrics()
	m.AddCounter(context.Background(), outbound.MetricRequestsTotal, 3,
		model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: "frontend"},
		model.MetricAttribute{Key: outbound.MetricAttrSourceNamespace, Value: "prod"},
		model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: "prod/api"},
		model.MetricAttribute{Key: outbound.MetricAttrDestinationNamespace, Value: "prod"},
		model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "http1"},
		model.MetricAttribute{Key: outbound.MetricAttrResponseCode, Value: "200"},
	)
	m.RecordHistogram(context.Background(), outbound.MetricRequestsDurationMs, 42.5,
		model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: "frontend"},
		model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: "prod/api"},
		model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "http1"},
	)
	m.RecordGauge(context.Background(), outbound.MetricAuthzPoliciesCached, 7)

	// Scrape standard Prometheus exposition format.
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /metrics, got %d", resp.StatusCode)
	}
	body := string(bodyBytes)

	if !strings.Contains(body, "omnimesh_agent_requests_total") {
		t.Fatalf("expected omnimesh_agent_requests_total in /metrics output, got:\n%s", body)
	}
	if !strings.Contains(body, "omnimesh_agent_requests_duration_ms_bucket") {
		t.Fatalf("expected omnimesh_agent_requests_duration_ms_bucket (WithoutUnits) in /metrics output, got:\n%s", body)
	}
	if strings.Contains(body, "duration_ms_milliseconds") {
		t.Fatalf("unexpected doubled unit suffix duration_ms_milliseconds in /metrics output")
	}
	if !strings.Contains(body, "omnimesh_agent_authz_policies_cached") {
		t.Fatalf("expected omnimesh_agent_authz_policies_cached in /metrics output")
	}

	// Scrape /healthz and OpenMetrics content negotiation.
	hzResp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	_ = hzResp.Body.Close()
	if hzResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /healthz, got %d", hzResp.StatusCode)
	}

	reqOM, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/metrics", nil)
	reqOM.Header.Set("Accept", "application/openmetrics-text;version=1.0.0")
	omResp, err := http.DefaultClient.Do(reqOM)
	if err != nil {
		t.Fatalf("OpenMetrics GET /metrics failed: %v", err)
	}
	omBody, _ := io.ReadAll(omResp.Body)
	_ = omResp.Body.Close()
	if !strings.Contains(omResp.Header.Get("Content-Type"), "application/openmetrics-text") {
		t.Fatalf("expected OpenMetrics Content-Type, got %q", omResp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(omBody), "# EOF") {
		t.Fatalf("expected OpenMetrics # EOF marker, got:\n%s", string(omBody))
	}
}

func TestMetricViewsDropLabelsAndCustomBuckets(t *testing.T) {
	cfg := model.DefaultObservabilityConfig()
	cfg.Metrics.CombinedRequestMetric.Enabled = false
	cfg.Metrics.Cardinality.MaxLabelCardinality = 2
	cfg.Metrics.Cardinality.DropLabels = map[string][]string{
		outbound.MetricRequestsTotal: {outbound.MetricAttrSourceService},
	}
	cfg.Metrics.Cardinality.HistogramBuckets = map[string][]float64{
		"duration_ms": {5, 50, 500},
	}

	reader := sdkmetric.NewManualReader()
	prov, err := oteltelemetry.NewProvider(context.Background(), cfg, "node-1", oteltelemetry.WithMetricReader(reader))
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer func() { _ = prov.Shutdown(context.Background()) }()

	m := prov.Metrics()
	if m.CombinedRequestMetricEnabled() {
		t.Fatalf("expected CombinedRequestMetricEnabled() to return false")
	}

	// Emit with source_service (which DropLabels removes) and multiple combinations to exercise cardinality tracker.
	for _, svc := range []string{"svc-a", "svc-b", "svc-c"} {
		m.AddCounter(context.Background(), outbound.MetricRequestsTotal, 1,
			model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: svc},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: "dest"},
		)
	}
	m.RecordHistogram(context.Background(), outbound.MetricRequestsDurationMs, 25,
		model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: "svc-a"},
		model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: "dest"},
		model.MetricAttribute{Key: outbound.MetricAttrProtocol, Value: "http1"},
	)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	var foundReq, foundDur bool
	for _, sm := range rm.ScopeMetrics {
		for _, metric := range sm.Metrics {
			switch metric.Name {
			case outbound.MetricRequestsTotal:
				foundReq = true
				sum := metric.Data.(metricdata.Sum[int64])
				if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 3 {
					t.Fatalf("expected 1 aggregated datapoint of value 3 after dropping source_service, got %+v", sum.DataPoints)
				}
				if _, hasSrc := sum.DataPoints[0].Attributes.Value(outbound.MetricAttrSourceService); hasSrc {
					t.Fatalf("expected source_service attribute to be dropped by View")
				}
			case outbound.MetricRequestsDurationMs:
				foundDur = true
				hist := metric.Data.(metricdata.Histogram[float64])
				if len(hist.DataPoints) != 1 {
					t.Fatalf("expected 1 histogram datapoint, got %d", len(hist.DataPoints))
				}
				bounds := hist.DataPoints[0].Bounds
				if len(bounds) != 3 || bounds[0] != 5 || bounds[1] != 50 || bounds[2] != 500 {
					t.Fatalf("expected custom bounds [5 50 500], got %v", bounds)
				}
			}
		}
	}
	if !foundReq || !foundDur {
		t.Fatalf("missing expected metrics: foundReq=%v foundDur=%v", foundReq, foundDur)
	}
}

func TestErrorBiasedSamplingAndRateLimit(t *testing.T) {
	cfg := model.DefaultObservabilityConfig()
	cfg.Traces.Enabled = true
	cfg.Traces.Sampler = "parentbased_traceidratio"
	cfg.Traces.SampleRate = 0.0 // 0% head sampling
	cfg.Traces.AlwaysSampleErrors = true
	cfg.Traces.MaxErrorTracesPerSec = 2

	exp := tracetest.NewInMemoryExporter()
	prov, err := oteltelemetry.NewProvider(
		context.Background(),
		cfg,
		"node-trace",
		oteltelemetry.WithSpanExporter(exp),
		oteltelemetry.WithSyncSpanProcessor(),
	)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer func() { _ = prov.Shutdown(context.Background()) }()

	tr := prov.Tracer()

	// 1. Non-error span at sample_rate=0.0 must be dropped.
	_, okSpan := tr.StartSpan(context.Background(), outbound.SpanNameEgress, model.SpanKindClient,
		model.MetricAttribute{Key: outbound.AttrProtocol, Value: "http"},
	)
	if okSpan.SpanContext().Sampled {
		t.Fatalf("expected unsampled span at sample_rate=0.0")
	}
	okSpan.End()

	if got := len(exp.GetSpans()); got != 0 {
		t.Fatalf("expected 0 exported spans for non-error span at 0%% rate, got %d", got)
	}

	// 2. Error spans at sample_rate=0.0 must be promoted and exported up to MaxErrorTracesPerSec=2.
	for i := 0; i < 4; i++ {
		_, errSpan := tr.StartSpan(context.Background(), outbound.SpanNameEgress, model.SpanKindClient,
			model.MetricAttribute{Key: outbound.AttrProtocol, Value: "http"},
		)
		errSpan.SetError(errors.New("upstream 502"), "upstream 502")
		errSpan.End()
	}

	spans := exp.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("expected exactly 2 exported error spans due to MaxErrorTracesPerSec=2 rate cap, got %d", len(spans))
	}
	for _, sp := range spans {
		if !sp.SpanContext.IsSampled() {
			t.Fatalf("expected promoted error span to have Sampled flag set")
		}
	}
}

func TestTraceContextInjectExtractAndAuthzObserver(t *testing.T) {
	cfg := model.DefaultObservabilityConfig()
	cfg.Traces.Enabled = true
	cfg.Traces.Sampler = "always_on"
	cfg.Metrics.Enabled = false

	reader := sdkmetric.NewManualReader()
	exp := tracetest.NewInMemoryExporter()
	prov, err := oteltelemetry.NewProvider(
		context.Background(),
		cfg,
		"node-authz",
		oteltelemetry.WithMetricReader(reader),
		oteltelemetry.WithSpanExporter(exp),
		oteltelemetry.WithSyncSpanProcessor(),
	)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer func() { _ = prov.Shutdown(context.Background()) }()

	tr := prov.Tracer()
	spanCtx, span := tr.StartSpan(context.Background(), outbound.SpanNameIngress, model.SpanKindServer)

	headers := make(http.Header)
	tr.InjectContext(spanCtx, outbound.HTTPHeaderCarrier(headers))
	if headers.Get("Traceparent") == "" {
		t.Fatalf("expected traceparent header to be injected")
	}
	extractedCtx := tr.ExtractContext(context.Background(), outbound.HTTPHeaderCarrier(headers))
	extractedSC := tr.SpanContextFromContext(extractedCtx)
	if !extractedSC.Valid || extractedSC.TraceID != span.SpanContext().TraceID || extractedSC.SpanID != span.SpanContext().SpanID {
		t.Fatalf("extracted SpanContext mismatch: got %+v, want %+v", extractedSC, span.SpanContext())
	}

	var customObserverCalls int
	customObs := authzObserverFunc(func(ctx context.Context, req model.AuthzRequest, decision model.AuthzDecision) {
		customObserverCalls++
	})
	obs := oteltelemetry.NewMultiAuthzObserver(
		oteltelemetry.NewAuthzObserver(prov.Metrics(), tr),
		customObs,
	)

	obs.OnAuthzDecision(spanCtx, model.AuthzRequest{
		Layer:          model.AuthzLayerL7,
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/web",
	}, model.AuthzDecision{
		Allowed:                 false,
		Reason:                  model.AuthzReasonExplicitDeny,
		MatchedPolicy:           "prod/deny-web",
		ResolvedDestNamespace:   "prod",
		ResolvedDestServiceName: "payments",
		EvaluationDuration:      250 * time.Microsecond,
	})
	span.End()

	if customObserverCalls != 1 {
		t.Fatalf("expected custom observer to be called once, got %d", customObserverCalls)
	}

	exported := exp.GetSpans()
	if len(exported) != 1 {
		t.Fatalf("expected 1 exported span, got %d", len(exported))
	}
	attrs := map[string]string{}
	for _, kv := range exported[0].Attributes {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}
	if attrs[outbound.AttrAuthzDecision] != "deny" || attrs[outbound.AttrAuthzPolicy] != "prod/deny-web" {
		t.Fatalf("expected authz span attributes, got %+v", attrs)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	metricNames := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metricNames[m.Name] = true
		}
	}
	for _, expected := range []string{
		outbound.MetricAuthzDecisionsTotal,
		outbound.MetricAuthzDenialsTotal,
		outbound.MetricAuthzEvaluationDurationUs,
	} {
		if !metricNames[expected] {
			t.Fatalf("expected metric %q to be recorded, got %+v", expected, metricNames)
		}
	}
}

type authzObserverFunc func(ctx context.Context, req model.AuthzRequest, decision model.AuthzDecision)

func (f authzObserverFunc) OnAuthzDecision(ctx context.Context, req model.AuthzRequest, decision model.AuthzDecision) {
	f(ctx, req, decision)
}

type fakeSVIDSource struct {
	updated chan struct{}
	svid    *x509svid.SVID
}

func (f *fakeSVIDSource) GetX509SVID() (*x509svid.SVID, error) { return f.svid, nil }
func (f *fakeSVIDSource) Updated() <-chan struct{}             { return f.updated }

func TestSVIDMonitorTracksExpiryAndRotations(t *testing.T) {
	cfg := model.DefaultObservabilityConfig()
	reader := sdkmetric.NewManualReader()
	prov, err := oteltelemetry.NewProvider(context.Background(), cfg, "node-svid", oteltelemetry.WithMetricReader(reader))
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer func() { _ = prov.Shutdown(context.Background()) }()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	id := spiffeid.RequireFromString("spiffe://omnimesh.local/ns/omnimesh-system/sa/agent")
	makeSVID := func(serial int64) *x509svid.SVID {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		return &x509svid.SVID{
			ID:           id,
			Certificates: []*x509.Certificate{cert},
			PrivateKey:   key,
		}
	}

	src := &fakeSVIDSource{
		updated: make(chan struct{}, 2),
		svid:    makeSVID(100),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mon := oteltelemetry.NewSVIDMonitor(ctx, src, prov.Metrics())
	defer mon.Stop()

	src.svid = makeSVID(101)
	src.updated <- struct{}{}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err == nil {
			var gotExpiry, gotRotation bool
			for _, sm := range rm.ScopeMetrics {
				for _, m := range sm.Metrics {
					if m.Name == outbound.MetricMTLSSVIDExpirySeconds {
						gotExpiry = true
					}
					if m.Name == outbound.MetricMTLSSVIDRotationsTotal {
						sum := m.Data.(metricdata.Sum[int64])
						if len(sum.DataPoints) > 0 && sum.DataPoints[0].Value >= 1 {
							gotRotation = true
						}
					}
				}
			}
			if gotExpiry && gotRotation {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for SVID expiry and rotation metrics")
}
