package outbound

import (
	"context"
	"net/http"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

// Canonical RFC-0005 agent metric names.
const (
	// 5.1 Request Traffic
	MetricRequestsTotal         = "omnimesh.agent.requests.total"
	MetricRequestsIngressTotal  = "omnimesh.agent.requests.ingress.total"
	MetricRequestsEgressTotal   = "omnimesh.agent.requests.egress.total"
	MetricRequestsDurationMs    = "omnimesh.agent.requests.duration_ms"
	MetricRequestsActive        = "omnimesh.agent.requests.active"
	MetricRequestsBytesSent     = "omnimesh.agent.requests.bytes_sent"
	MetricRequestsBytesReceived = "omnimesh.agent.requests.bytes_received"

	// 5.2 Connections & HBONE Tunnels
	MetricConnectionsActive     = "omnimesh.agent.connections.active"
	MetricConnectionsTotal      = "omnimesh.agent.connections.total"
	MetricConnectionsDurationMs = "omnimesh.agent.connections.duration_ms"
	MetricHBONETunnelsActive    = "omnimesh.agent.hbone.tunnels.active"
	MetricHBONEStreamsActive    = "omnimesh.agent.hbone.streams.active"
	MetricHBONEStreamsTotal     = "omnimesh.agent.hbone.streams.total"
	MetricHBONEBytesSent        = "omnimesh.agent.hbone.bytes_sent"
	MetricHBONEBytesReceived    = "omnimesh.agent.hbone.bytes_received"

	// 5.3 mTLS & SVIDs
	MetricMTLSHandshakesTotal      = "omnimesh.agent.mtls.handshakes.total"
	MetricMTLSHandshakesDurationMs = "omnimesh.agent.mtls.handshakes.duration_ms"
	MetricMTLSSVIDExpirySeconds    = "omnimesh.agent.mtls.svid.expiry_seconds"
	MetricMTLSSVIDRotationsTotal   = "omnimesh.agent.mtls.svid.rotations.total"

	// 5.4 Retries
	MetricRetriesTotal     = "omnimesh.agent.retries.total"
	MetricRetriesExhausted = "omnimesh.agent.retries.exhausted"
	MetricRetriesSuccess   = "omnimesh.agent.retries.success"

	// 5.7 Load Balancing
	MetricLBSelectionsTotal     = "omnimesh.agent.lb.selections.total"
	MetricLBEndpointsHealthy    = "omnimesh.agent.lb.endpoints.healthy"
	MetricLBEndpointsTotal      = "omnimesh.agent.lb.endpoints.total"
	MetricLBNoHealthyEndpoints  = "omnimesh.agent.lb.no_healthy_endpoints"

	// 5.8 Health Checks
	MetricHealthProbesTotal      = "omnimesh.agent.health.probes.total"
	MetricHealthProbesDurationMs = "omnimesh.agent.health.probes.duration_ms"
	MetricHealthTransitions      = "omnimesh.agent.health.transitions"

	// 5.9 Authorization
	MetricAuthzDecisionsTotal       = "omnimesh.agent.authz.decisions.total"
	MetricAuthzDenialsTotal         = "omnimesh.agent.authz.denials.total"
	MetricAuthzEvaluationDurationUs = "omnimesh.agent.authz.evaluation.duration_us"
	MetricAuthzPoliciesCached       = "omnimesh.agent.authz.policies.cached"
)

// Canonical RFC-0005 span names and attribute keys.
const (
	SpanNameEgress      = "omnimesh.egress"
	SpanNameIngress     = "omnimesh.ingress"
	SpanNameHBONETunnel = "omnimesh.hbone.tunnel"

	AttrSourceService        = "omnimesh.source.service"
	AttrSourceNamespace      = "omnimesh.source.namespace"
	AttrDestinationService   = "omnimesh.destination.service"
	AttrDestinationNamespace = "omnimesh.destination.namespace"
	AttrDestinationEndpoint  = "omnimesh.destination.endpoint"
	AttrProtocol             = "omnimesh.protocol"
	AttrDirection            = "omnimesh.direction"
	AttrAuthzDecision        = "omnimesh.authz.decision"
	AttrAuthzPolicy          = "omnimesh.authz.policy"
	AttrRetryAttempt         = "omnimesh.retry.attempt"
	AttrNode                 = "omnimesh.node"

	AttrHTTPMethod     = "http.method"
	AttrHTTPURL        = "http.url"
	AttrHTTPStatusCode = "http.status_code"

	AttrRPCSystem         = "rpc.system"
	AttrRPCService        = "rpc.service"
	AttrRPCMethod         = "rpc.method"
	AttrRPCGRPCStatusCode = "rpc.grpc.status_code"
)

// Canonical metric attribute keys.
const (
	MetricAttrSourceService        = "source_service"
	MetricAttrSourceNamespace      = "source_namespace"
	MetricAttrDestinationService   = "destination_service"
	MetricAttrDestinationNamespace = "destination_namespace"
	MetricAttrProtocol             = "protocol"
	MetricAttrResponseCode         = "response_code"
	MetricAttrResult               = "result"
	MetricAttrPeerNode             = "peer_node"
	MetricAttrPeerService          = "peer_service"
	MetricAttrDirection            = "direction"
	MetricAttrSPIFFEID             = "spiffe_id"
	MetricAttrRetryReason          = "retry_reason"
	MetricAttrEndpoint             = "endpoint"
	MetricAttrAlgorithm            = "algorithm"
	MetricAttrService              = "service"
	MetricAttrFromState            = "from_state"
	MetricAttrToState              = "to_state"
	MetricAttrDecision             = "decision"
	MetricAttrReason               = "reason"
	MetricAttrLayer                = "layer"
)

// PropagationCarrier abstracts header/metadata extraction and injection for distributed trace context.
type PropagationCarrier interface {
	Get(key string) string
	Set(key, value string)
	Keys() []string
}

// HTTPHeaderCarrier adapts http.Header to PropagationCarrier.
type HTTPHeaderCarrier http.Header

// Get returns the first value associated with the given header key.
func (c HTTPHeaderCarrier) Get(key string) string {
	return http.Header(c).Get(key)
}

// Set sets the header entries associated with key to the single element value.
func (c HTTPHeaderCarrier) Set(key, value string) {
	http.Header(c).Set(key, value)
}

// Keys lists all keys currently present in the header map.
func (c HTTPHeaderCarrier) Keys() []string {
	h := http.Header(c)
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	return keys
}

// MetricRecorder defines the outbound port for recording agent metrics without coupling to an OTel SDK.
// Implementations MUST be safe for concurrent use across goroutines.
type MetricRecorder interface {
	AddCounter(ctx context.Context, name string, delta int64, attrs ...model.MetricAttribute)
	AddUpDownCounter(ctx context.Context, name string, delta int64, attrs ...model.MetricAttribute)
	RecordGauge(ctx context.Context, name string, value float64, attrs ...model.MetricAttribute)
	RecordHistogram(ctx context.Context, name string, value float64, attrs ...model.MetricAttribute)
	CombinedRequestMetricEnabled() bool
}

// SpanHandle represents an active distributed trace span.
type SpanHandle interface {
	SetName(name string)
	SetAttributes(attrs ...model.MetricAttribute)
	SetError(err error, description string)
	SpanContext() model.SpanContext
	End()
}

// TraceRecorder defines the outbound port for creating spans and propagating W3C trace context.
// Implementations MUST be safe for concurrent use across goroutines.
type TraceRecorder interface {
	StartSpan(ctx context.Context, name string, kind model.SpanKind, attrs ...model.MetricAttribute) (context.Context, SpanHandle)
	SpanFromContext(ctx context.Context) SpanHandle
	InjectContext(ctx context.Context, carrier PropagationCarrier)
	ExtractContext(ctx context.Context, carrier PropagationCarrier) context.Context
	SpanContextFromContext(ctx context.Context) model.SpanContext
}

// TelemetryProvider groups metric and trace recorders along with graceful flush/shutdown lifecycle.
type TelemetryProvider interface {
	Metrics() MetricRecorder
	Tracer() TraceRecorder
	Shutdown(ctx context.Context) error
}

// NoopTelemetryProvider is a zero-cost TelemetryProvider used when observability is disabled.
type NoopTelemetryProvider struct{}

// NewNoopTelemetryProvider returns a zero-cost TelemetryProvider.
func NewNoopTelemetryProvider() *NoopTelemetryProvider {
	return &NoopTelemetryProvider{}
}

// Metrics returns a NoopMetricRecorder.
func (p *NoopTelemetryProvider) Metrics() MetricRecorder { return NoopMetricRecorder{} }

// Tracer returns a NoopTraceRecorder.
func (p *NoopTelemetryProvider) Tracer() TraceRecorder { return NoopTraceRecorder{} }

// Shutdown is a no-op.
func (p *NoopTelemetryProvider) Shutdown(context.Context) error { return nil }

// NoopMetricRecorder discards all metric observations with zero allocations.
type NoopMetricRecorder struct{}

func (NoopMetricRecorder) AddCounter(context.Context, string, int64, ...model.MetricAttribute) {
}
func (NoopMetricRecorder) AddUpDownCounter(context.Context, string, int64, ...model.MetricAttribute) {
}
func (NoopMetricRecorder) RecordGauge(context.Context, string, float64, ...model.MetricAttribute) {
}
func (NoopMetricRecorder) RecordHistogram(context.Context, string, float64, ...model.MetricAttribute) {
}
func (NoopMetricRecorder) CombinedRequestMetricEnabled() bool { return true }

// NoopTraceRecorder discards all span operations with zero allocations.
type NoopTraceRecorder struct{}

func (NoopTraceRecorder) StartSpan(ctx context.Context, _ string, _ model.SpanKind, _ ...model.MetricAttribute) (context.Context, SpanHandle) {
	return ctx, NoopSpanHandle{}
}
func (NoopTraceRecorder) SpanFromContext(context.Context) SpanHandle               { return NoopSpanHandle{} }
func (NoopTraceRecorder) InjectContext(context.Context, PropagationCarrier)        {}
func (NoopTraceRecorder) ExtractContext(ctx context.Context, _ PropagationCarrier) context.Context {
	return ctx
}
func (NoopTraceRecorder) SpanContextFromContext(context.Context) model.SpanContext {
	return model.SpanContext{}
}

// NoopSpanHandle is a zero-cost SpanHandle.
type NoopSpanHandle struct{}

func (NoopSpanHandle) SetName(string)                    {}
func (NoopSpanHandle) SetAttributes(...model.MetricAttribute) {}
func (NoopSpanHandle) SetError(error, string)            {}
func (NoopSpanHandle) SpanContext() model.SpanContext    { return model.SpanContext{} }
func (NoopSpanHandle) End()                              {}

// MetricAttrSPIFFEIDAttr builds a MetricAttribute for spiffe_id.
func MetricAttrSPIFFEIDAttr(spiffeID string) model.MetricAttribute {
	return model.MetricAttribute{Key: MetricAttrSPIFFEID, Value: spiffeID}
}

var (
	_ TelemetryProvider = (*NoopTelemetryProvider)(nil)
	_ MetricRecorder    = NoopMetricRecorder{}
	_ TraceRecorder     = NoopTraceRecorder{}
	_ SpanHandle        = NoopSpanHandle{}
)
