package oteltelemetry

import (
	"context"
	"strings"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

var _ inbound.AuthzDecisionObserver = (*AuthzTelemetryObserver)(nil)

// AuthzTelemetryObserver records RFC-0005 authorization metrics and stamps active trace spans.
type AuthzTelemetryObserver struct {
	metrics outbound.MetricRecorder
	tracer  outbound.TraceRecorder
}

// NewAuthzObserver creates an AuthzTelemetryObserver backed by the given telemetry recorders.
func NewAuthzObserver(metrics outbound.MetricRecorder, tracer outbound.TraceRecorder) *AuthzTelemetryObserver {
	if metrics == nil {
		metrics = outbound.NoopMetricRecorder{}
	}
	if tracer == nil {
		tracer = outbound.NoopTraceRecorder{}
	}
	return &AuthzTelemetryObserver{
		metrics: metrics,
		tracer:  tracer,
	}
}

// OnAuthzDecision emits authorization decision counters, denial reason counters, evaluation
// latency histograms, and stamps omnimesh.authz.* attributes onto any active trace span.
func (o *AuthzTelemetryObserver) OnAuthzDecision(ctx context.Context, req model.AuthzRequest, decision model.AuthzDecision) {
	srcSvc, _ := model.ParseCallerService(req.CallerIdentity)
	destSvc := formatServiceLabel(decision.ResolvedDestNamespace, decision.ResolvedDestServiceName, req.DestNamespace, req.DestServiceName)
	layer := string(req.Layer)
	if layer == "" {
		layer = string(model.AuthzLayerL4)
	}

	decisionLabel := "deny"
	if decision.DryRun && decision.WouldDeny {
		decisionLabel = "dry_run"
	} else if decision.Allowed {
		decisionLabel = "allow"
	}

	o.metrics.AddCounter(ctx, outbound.MetricAuthzDecisionsTotal, 1,
		model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
		model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
		model.MetricAttribute{Key: outbound.MetricAttrDecision, Value: decisionLabel},
		model.MetricAttribute{Key: outbound.MetricAttrLayer, Value: layer},
	)

	if !decision.Allowed {
		reason := string(decision.Reason)
		if reason == "" {
			reason = string(model.AuthzReasonNoPolicy)
		}
		o.metrics.AddCounter(ctx, outbound.MetricAuthzDenialsTotal, 1,
			model.MetricAttribute{Key: outbound.MetricAttrSourceService, Value: srcSvc},
			model.MetricAttribute{Key: outbound.MetricAttrDestinationService, Value: destSvc},
			model.MetricAttribute{Key: outbound.MetricAttrReason, Value: reason},
			model.MetricAttribute{Key: outbound.MetricAttrLayer, Value: layer},
		)
	}

	if decision.EvaluationDuration >= 0 {
		us := float64(decision.EvaluationDuration.Nanoseconds()) / 1000.0
		o.metrics.RecordHistogram(ctx, outbound.MetricAuthzEvaluationDurationUs, us,
			model.MetricAttribute{Key: outbound.MetricAttrLayer, Value: layer},
		)
	}

	if span := o.tracer.SpanFromContext(ctx); span != nil {
		attrs := []model.MetricAttribute{
			{Key: outbound.AttrAuthzDecision, Value: decisionLabel},
		}
		if decision.MatchedPolicy != "" {
			attrs = append(attrs, model.MetricAttribute{Key: outbound.AttrAuthzPolicy, Value: decision.MatchedPolicy})
		}
		span.SetAttributes(attrs...)
	}
}

func formatServiceLabel(resolvedNS, resolvedName, reqNS, reqName string) string {
	ns := strings.TrimSpace(resolvedNS)
	if ns == "" {
		ns = strings.TrimSpace(reqNS)
	}
	name := strings.TrimSpace(resolvedName)
	if name == "" {
		name = strings.TrimSpace(reqName)
	}
	if name == "" {
		return "unknown"
	}
	if ns != "" {
		return ns + "/" + name
	}
	return name
}

// MultiAuthzObserver fans out authorization decision events to multiple observers.
type MultiAuthzObserver struct {
	observers []inbound.AuthzDecisionObserver
}

// NewMultiAuthzObserver combines non-nil observers into a single AuthzDecisionObserver.
// Returns nil if no non-nil observers are provided.
func NewMultiAuthzObserver(observers ...inbound.AuthzDecisionObserver) inbound.AuthzDecisionObserver {
	filtered := make([]inbound.AuthzDecisionObserver, 0, len(observers))
	for _, obs := range observers {
		if obs != nil {
			filtered = append(filtered, obs)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	return &MultiAuthzObserver{observers: filtered}
}

// OnAuthzDecision invokes every registered observer in order.
func (m *MultiAuthzObserver) OnAuthzDecision(ctx context.Context, req model.AuthzRequest, decision model.AuthzDecision) {
	for _, obs := range m.observers {
		obs.OnAuthzDecision(ctx, req, decision)
	}
}
