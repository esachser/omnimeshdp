package authz_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/application/authz"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

type recordingObserver struct {
	mu        sync.Mutex
	decisions []model.AuthzDecision
}

func (o *recordingObserver) OnAuthzDecision(_ context.Context, _ model.AuthzRequest, decision model.AuthzDecision) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.decisions = append(o.decisions, decision)
}

func mustNewEngine(t *testing.T, cfg model.AuthorizationConfig, opts ...authz.EngineOption) *authz.Engine {
	t.Helper()
	e, err := authz.NewEngine(cfg, opts...)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	return e
}

func TestEngine_DefaultDenyAndAllowDenyPrecedence(t *testing.T) {
	obs := &recordingObserver{}
	cfg := model.DefaultAuthorizationConfig()
	e := mustNewEngine(t, cfg, authz.WithTrustDomain("omnimesh.local"), authz.WithObserver(obs))

	ctx := context.Background()
	orderID := "spiffe://omnimesh.local/ns/production/sa/order-service"
	unknownID := "spiffe://omnimesh.local/ns/production/sa/unknown-service"

	// 1. Strict default-deny before any snapshot arrives.
	d := e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:     orderID,
		CallerVerified:     true,
		DestNamespace:      "production",
		DestServiceName:    "payment-service",
		InboundL7Available: true,
	})
	if d.Allowed || d.Reason != model.AuthzReasonNoPolicy {
		t.Fatalf("expected default deny (no_policy), got %+v", d)
	}

	// 2. Apply snapshot with ALLOW and DENY policies.
	e.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
			{
				Name:      "allow-prod-to-payment",
				Namespace: "production",
				Action:    "ALLOW",
				Source:    &omnimeshv1.SelectorInfo{Namespace: "production", Name: "*"},
				Destination: &omnimeshv1.SelectorInfo{
					Namespace: "production",
					Name:      "payment-service",
				},
			},
			{
				Name:      "deny-unknown",
				Namespace: "production",
				Action:    "DENY",
				Source:    &omnimeshv1.SelectorInfo{Namespace: "production", Name: "unknown-service"},
				Destination: &omnimeshv1.SelectorInfo{
					Namespace: "production",
					Name:      "*",
				},
			},
		},
	})

	// Order service is allowed.
	d = e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:     orderID,
		CallerVerified:     true,
		DestNamespace:      "production",
		DestServiceName:    "payment-service",
		InboundL7Available: true,
	})
	if !d.Allowed || d.Reason != model.AuthzReasonExplicitAllow || d.MatchedPolicy != "production/allow-prod-to-payment" {
		t.Fatalf("expected explicit allow, got %+v", d)
	}

	// Unknown service matches DENY which overrides wildcard ALLOW.
	d = e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:     unknownID,
		CallerVerified:     true,
		DestNamespace:      "production",
		DestServiceName:    "payment-service",
		InboundL7Available: true,
	})
	if d.Allowed || d.Reason != model.AuthzReasonExplicitDeny || d.MatchedPolicy != "production/deny-unknown" {
		t.Fatalf("expected explicit deny overriding allow, got %+v", d)
	}

	// Cross-namespace caller is still denied.
	d = e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:     "spiffe://omnimesh.local/ns/monitoring/sa/prom",
		CallerVerified:     true,
		DestNamespace:      "production",
		DestServiceName:    "payment-service",
		InboundL7Available: true,
	})
	if d.Allowed || d.Reason != model.AuthzReasonNoPolicy {
		t.Fatalf("expected cross-namespace deny, got %+v", d)
	}

	stats := e.Stats()
	if stats.AllowedTotal != 1 || stats.DeniedTotal != 3 || stats.DeniedExplicitTotal != 1 || stats.DeniedNoPolicyTotal != 2 || stats.PoliciesCached != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if len(obs.decisions) != 4 {
		t.Fatalf("expected 4 observer callbacks, got %d", len(obs.decisions))
	}
}

func TestEngine_NamespaceIsolationAndIncrementalUpdates(t *testing.T) {
	e := mustNewEngine(t, model.DefaultAuthorizationConfig(), authz.WithTrustDomain("omnimesh.local"))
	ctx := context.Background()

	e.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "staging", Isolation: "open"},
			{Name: "production", Isolation: "strict"},
		},
		AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
			{
				Name:        "deny-rogue",
				Namespace:   "staging",
				Action:      "DENY",
				Source:      &omnimeshv1.SelectorInfo{Namespace: "staging", Name: "rogue"},
				Destination: &omnimeshv1.SelectorInfo{Namespace: "staging", Name: "*"},
			},
		},
	})

	// Same-namespace open isolation allows staging -> staging.
	d := e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:  "spiffe://omnimesh.local/ns/staging/sa/web",
		CallerVerified:  true,
		DestNamespace:   "staging",
		DestServiceName: "api",
	})
	if !d.Allowed || d.Reason != model.AuthzReasonNamespaceOpen {
		t.Fatalf("expected namespace_open allow, got %+v", d)
	}

	// Explicit DENY overrides open namespace isolation.
	d = e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:  "spiffe://omnimesh.local/ns/staging/sa/rogue",
		CallerVerified:  true,
		DestNamespace:   "staging",
		DestServiceName: "api",
	})
	if d.Allowed || d.Reason != model.AuthzReasonExplicitDeny {
		t.Fatalf("expected explicit deny in open namespace, got %+v", d)
	}

	// Cross-namespace into open namespace is still denied.
	d = e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:  "spiffe://omnimesh.local/ns/production/sa/web",
		CallerVerified:  true,
		DestNamespace:   "staging",
		DestServiceName: "api",
	})
	if d.Allowed || d.Reason != model.AuthzReasonNoPolicy {
		t.Fatalf("expected cross-namespace deny into open namespace, got %+v", d)
	}

	// Update staging back to strict via ScopeUpdate.
	e.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_MODIFY,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "staging", Isolation: "strict"},
		},
	})
	d = e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:  "spiffe://omnimesh.local/ns/staging/sa/web",
		CallerVerified:  true,
		DestNamespace:   "staging",
		DestServiceName: "api",
	})
	if d.Allowed || d.Reason != model.AuthzReasonNoPolicy {
		t.Fatalf("expected strict deny after namespace update, got %+v", d)
	}
}

func TestEngine_LabelsTrustDomainAndUnverifiedIdentity(t *testing.T) {
	e := mustNewEngine(t, model.DefaultAuthorizationConfig(), authz.WithTrustDomain("omnimesh.local"))
	ctx := context.Background()

	e.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "payments", MeshAddr: "10.10.0.5", Port: 8080, Protocol: "http"},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "orders",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "node-canary", RouteName: "orders-canary", Labels: map[string]string{"tier": "backend", "track": "canary"}},
					{NodeId: "node-stable", RouteName: "orders-stable", Labels: map[string]string{"tier": "backend", "track": "stable"}},
				},
			},
		},
		AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
			{
				Name:      "allow-canary-orders",
				Namespace: "prod",
				Action:    "ALLOW",
				Source: &omnimeshv1.SelectorInfo{
					Namespace: "prod",
					Name:      "orders",
					Labels:    map[string]string{"tier": "backend", "track": "canary"},
				},
				Destination: &omnimeshv1.SelectorInfo{
					Namespace: "prod",
					Name:      "payments",
					Labels:    map[string]string{"version": "v2"},
				},
			},
		},
	})

	// Matches via DestMeshIP lookup + source node label + destination label.
	d := e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:     "spiffe://omnimesh.local/ns/prod/sa/orders",
		CallerVerified:     true,
		SourceNodeID:       "node-canary",
		DestMeshIP:         "10.10.0.5",
		DestLabels:         map[string]string{"version": "v2", "env": "prod"},
		InboundL7Available: true,
	})
	if !d.Allowed || d.ResolvedDestNamespace != "prod" || d.ResolvedDestServiceName != "payments" {
		t.Fatalf("expected allow with resolved service meta and label match, got %+v", d)
	}

	// Wrong source node label (stable instead of canary) fails.
	d = e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/orders",
		CallerVerified: true,
		SourceNodeID:   "node-stable",
		DestMeshIP:     "10.10.0.5",
		DestLabels:     map[string]string{"version": "v2"},
	})
	if d.Allowed {
		t.Fatalf("expected deny for non-matching source node labels, got %+v", d)
	}

	// Wrong destination label fails.
	d = e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/orders",
		CallerVerified: true,
		SourceNodeID:   "node-canary",
		DestMeshIP:     "10.10.0.5",
		DestLabels:     map[string]string{"version": "v1"},
	})
	if d.Allowed {
		t.Fatalf("expected deny for non-matching destination labels, got %+v", d)
	}

	// Foreign trust domain is rejected even with identical ns/sa path.
	d = e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "spiffe://evil.corp/ns/prod/sa/orders",
		CallerVerified: true,
		SourceNodeID:   "node-canary",
		DestMeshIP:     "10.10.0.5",
		DestLabels:     map[string]string{"version": "v2"},
	})
	if d.Allowed {
		t.Fatalf("expected foreign trust domain to be denied, got %+v", d)
	}

	// Unverified caller is rejected when allowUnverified == false.
	d = e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/orders",
		CallerVerified: false,
		SourceNodeID:   "node-canary",
		DestMeshIP:     "10.10.0.5",
		DestLabels:     map[string]string{"version": "v2"},
	})
	if d.Allowed || d.Reason != model.AuthzReasonUnauthenticated {
		t.Fatalf("expected unauthenticated deny, got %+v", d)
	}
}

func TestEngine_ModesTruthTableAndTemporalPolicies(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// Mode: permissive allows missing policy but enforces explicit DENY.
	perm := mustNewEngine(t, model.AuthorizationConfig{Mode: "permissive"}, authz.WithTrustDomain("omnimesh.local"))
	perm.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
			{
				Name:        "explicit-deny",
				Namespace:   "prod",
				Action:      "DENY",
				Source:      &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "blocked"},
				Destination: &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "api"},
			},
		},
	})
	if d := perm.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/other", CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "api",
	}); !d.Allowed || d.Reason != model.AuthzReasonPermissiveDefault {
		t.Fatalf("expected permissive default allow, got %+v", d)
	}
	if d := perm.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/blocked", CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "api",
	}); d.Allowed || d.Reason != model.AuthzReasonExplicitDeny {
		t.Fatalf("expected explicit deny even in permissive mode, got %+v", d)
	}

	// Mode: dry_run allows all traffic but marks WouldDeny=true.
	dry := mustNewEngine(t, model.AuthorizationConfig{Mode: "dry_run"}, authz.WithTrustDomain("omnimesh.local"))
	if d := dry.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/other", CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "api",
	}); !d.Allowed || !d.DryRun || !d.WouldDeny || d.Reason != model.AuthzReasonNoPolicy {
		t.Fatalf("expected dry_run would_deny, got %+v", d)
	}

	// Mode: disabled allows even unauthenticated/invalid identity.
	dis := mustNewEngine(t, model.AuthorizationConfig{Mode: "disabled"})
	if d := dis.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "", CallerVerified: false, DestNamespace: "prod", DestServiceName: "api",
	}); !d.Allowed || d.Reason != model.AuthzReasonDisabled {
		t.Fatalf("expected disabled allow, got %+v", d)
	}

	// Temporal policy window.
	tempCfg := model.AuthorizationConfig{
		Mode: "strict",
		LocalPolicies: []model.LocalAuthzPolicy{
			{
				Name:        "temp-access",
				Namespace:   "prod",
				Action:      "allow",
				Source:      model.AuthzSelector{Namespace: "prod", Name: "debug"},
				Destination: model.AuthzSelector{Namespace: "prod", Name: "api"},
				Ports:       []int{8080},
				ValidFrom:   "2026-11-25T11:00:00Z",
				ValidUntil:  "2026-11-25T13:00:00Z",
			},
		},
	}
	clockNow := now
	temp := mustNewEngine(t, tempCfg, authz.WithTrustDomain("omnimesh.local"), authz.WithClock(func() time.Time { return clockNow }))

	// Active inside window + matching port.
	if d := temp.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/debug", CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "api", DestPort: 8080,
	}); !d.Allowed {
		t.Fatalf("expected temporal policy active inside window, got %+v", d)
	}
	// Wrong port denied.
	if d := temp.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/debug", CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "api", DestPort: 9090,
	}); d.Allowed {
		t.Fatalf("expected wrong port to be denied, got %+v", d)
	}
	// Expired after ValidUntil.
	clockNow = now.Add(2 * time.Hour)
	if d := temp.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: "spiffe://omnimesh.local/ns/prod/sa/debug", CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "api", DestPort: 8080,
	}); d.Allowed {
		t.Fatalf("expected expired temporal policy to deny, got %+v", d)
	}
}

func TestEngine_L7HTTPRulesPathNormalizationGRPCAndDeferral(t *testing.T) {
	ctx := context.Background()
	cfg := model.AuthorizationConfig{
		Mode:      "strict",
		EnforceL7: true,
		LocalPolicies: []model.LocalAuthzPolicy{
			{
				Name:        "http-charge-only",
				Namespace:   "prod",
				Action:      "allow",
				Source:      model.AuthzSelector{Namespace: "prod", Name: "orders"},
				Destination: model.AuthzSelector{Namespace: "prod", Name: "payments"},
				Rules: []model.AuthzRule{
					{
						HTTP: &model.HTTPAuthzRule{
							Methods:      []string{"POST"},
							PathPrefixes: []string{"/api/v1/charge"},
							Headers:      map[string]string{"x-api-version": "1"},
						},
					},
				},
			},
			{
				Name:        "grpc-charge-only",
				Namespace:   "prod",
				Action:      "allow",
				Source:      model.AuthzSelector{Namespace: "prod", Name: "orders"},
				Destination: model.AuthzSelector{Namespace: "prod", Name: "grpc-pay"},
				Rules: []model.AuthzRule{
					{
						GRPC: &model.GRPCAuthzRule{
							Services: []string{"payment.v1.PaymentService"},
							Methods:  []string{"Charge"},
						},
					},
				},
			},
		},
	}

	e := mustNewEngine(t, cfg, authz.WithTrustDomain("omnimesh.local"))
	caller := "spiffe://omnimesh.local/ns/prod/sa/orders"

	// L4 check fails closed if inbound L7 is unavailable or protocol is TCP.
	if d := e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: caller, CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "payments",
		DestProtocol: "http", InboundL7Available: false,
	}); d.Allowed || d.Reason != model.AuthzReasonL7Required {
		t.Fatalf("expected L7Required denial when L7 disabled, got %+v", d)
	}
	if d := e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: caller, CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "payments",
		DestProtocol: "tcp", InboundL7Available: true,
	}); d.Allowed || d.Reason != model.AuthzReasonL7Required {
		t.Fatalf("expected L7Required denial on TCP service, got %+v", d)
	}

	// L4 check succeeds with RequiresL7=true when inbound L7 is available.
	if d := e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity: caller, CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "payments",
		DestProtocol: "http", InboundL7Available: true,
	}); !d.Allowed || !d.RequiresL7 || d.Reason != model.AuthzReasonExplicitAllowL7Deferred {
		t.Fatalf("expected L7 deferred allow, got %+v", d)
	}

	// L7 HTTP matching rule succeeds.
	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity: caller, CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "payments",
		DestProtocol: "http", InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method:  "POST",
			Path:    "/api/v1/charge/card",
			Headers: http.Header{"X-Api-Version": {"1"}},
		},
	}); !d.Allowed {
		t.Fatalf("expected L7 HTTP allow, got %+v", d)
	}

	// Path traversal attack /api/v1/charge/../admin must be normalized and denied!
	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity: caller, CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "payments",
		DestProtocol: "http", InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method:  "POST",
			Path:    "/api/v1/charge/../admin",
			Headers: http.Header{"X-Api-Version": {"1"}},
		},
	}); d.Allowed || d.Reason != model.AuthzReasonL7Mismatch {
		t.Fatalf("expected path traversal to fail with l7_mismatch, got %+v", d)
	}

	// gRPC matching service/method succeeds, other method fails.
	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity: caller, CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "grpc-pay",
		DestProtocol: "grpc", InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method:      "POST",
			Path:        "/payment.v1.PaymentService/Charge",
			IsGRPC:      true,
			GRPCService: "payment.v1.PaymentService",
			GRPCMethod:  "Charge",
		},
	}); !d.Allowed {
		t.Fatalf("expected gRPC Charge to be allowed, got %+v", d)
	}
	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity: caller, CallerVerified: true,
		DestNamespace: "prod", DestServiceName: "grpc-pay",
		DestProtocol: "grpc", InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method:      "POST",
			Path:        "/payment.v1.PaymentService/Refund",
			IsGRPC:      true,
			GRPCService: "payment.v1.PaymentService",
			GRPCMethod:  "Refund",
		},
	}); d.Allowed || d.Reason != model.AuthzReasonL7Mismatch {
		t.Fatalf("expected gRPC Refund to be denied with l7_mismatch, got %+v", d)
	}
}

func TestEngine_ControlPlaneFullPolicyFieldsOnSnapshotAndScopeUpdate(t *testing.T) {
	ctx := context.Background()
	clockNow := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

	e := mustNewEngine(
		t,
		model.DefaultAuthorizationConfig(),
		authz.WithTrustDomain("omnimesh.local"),
		authz.WithClock(func() time.Time { return clockNow }),
	)

	// Apply initial ScopeSnapshot with full AuthzPolicyInfo fields (ports, HTTP/gRPC rules,
	// spiffe_id, trust_domain, valid_from, valid_until) plus one malformed timestamp policy.
	e.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
			{
				Name:      "cp-http-policy",
				Namespace: "prod",
				Action:    "ALLOW",
				Source: &omnimeshv1.SelectorInfo{
					SpiffeId: "spiffe://partner.mesh/ns/external/sa/partner-client",
				},
				Destination: &omnimeshv1.SelectorInfo{
					Namespace: "prod",
					Name:      "payments",
				},
				DestinationPorts: []int32{8443},
				Rules: []*omnimeshv1.AuthzRuleInfo{
					{
						Http: &omnimeshv1.HttpAuthzRuleInfo{
							Methods:      []string{"POST"},
							PathPrefixes: []string{"/api/v1/charge"},
							PathExact:    []string{"/healthz"},
							Headers:      map[string]string{"x-tenant": "acme"},
						},
					},
				},
				ValidFrom:  "2026-11-27T11:00:00Z",
				ValidUntil: "2026-11-27T13:00:00Z",
			},
			{
				Name:      "cp-grpc-policy",
				Namespace: "prod",
				Action:    "ALLOW",
				Source: &omnimeshv1.SelectorInfo{
					TrustDomain: "federated.mesh",
					Namespace:   "orders",
					Name:        "checkout",
				},
				Destination: &omnimeshv1.SelectorInfo{
					Namespace: "prod",
					Name:      "grpc-pay",
				},
				Rules: []*omnimeshv1.AuthzRuleInfo{
					{
						Grpc: &omnimeshv1.GrpcAuthzRuleInfo{
							Services: []string{"payment.v1.PaymentService"},
							Methods:  []string{"Charge"},
						},
					},
				},
			},
			{
				Name:        "invalid-timestamp-policy",
				Namespace:   "prod",
				Action:      "ALLOW",
				Source:      &omnimeshv1.SelectorInfo{Namespace: "*", Name: "*"},
				Destination: &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "payments"},
				ValidFrom:   "not-a-timestamp",
			},
		},
	})

	if got := e.PolicyCount(); got != 2 {
		t.Fatalf("expected 2 valid compiled policies (ignoring invalid timestamp), got %d", got)
	}

	partnerID := "spiffe://partner.mesh/ns/external/sa/partner-client"

	// L4 defers to L7 on matching port & SpiffeId.
	if d := e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:     partnerID,
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "payments",
		DestPort:           8443,
		DestProtocol:       "http",
		InboundL7Available: true,
	}); !d.Allowed || !d.RequiresL7 || d.Reason != model.AuthzReasonExplicitAllowL7Deferred {
		t.Fatalf("expected L7-deferred allow on matching port and spiffe_id, got %+v", d)
	}

	// Wrong destination port is denied.
	if d := e.AuthorizeConnection(ctx, model.AuthzRequest{
		CallerIdentity:     partnerID,
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "payments",
		DestPort:           9090,
		DestProtocol:       "http",
		InboundL7Available: true,
	}); d.Allowed {
		t.Fatalf("expected denial for non-matching destination port, got %+v", d)
	}

	// L7 HTTP exact path + header matches.
	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity:     partnerID,
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "payments",
		DestPort:           8443,
		DestProtocol:       "http",
		InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method:  "POST",
			Path:    "/healthz",
			Headers: http.Header{"X-Tenant": {"acme"}},
		},
	}); !d.Allowed || d.MatchedPolicy != "prod/cp-http-policy" {
		t.Fatalf("expected L7 HTTP allow via CP policy, got %+v", d)
	}

	// L7 HTTP wrong header denied with l7_mismatch.
	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity:     partnerID,
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "payments",
		DestPort:           8443,
		DestProtocol:       "http",
		InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method:  "POST",
			Path:    "/api/v1/charge",
			Headers: http.Header{"X-Tenant": {"other"}},
		},
	}); d.Allowed || d.Reason != model.AuthzReasonL7Mismatch {
		t.Fatalf("expected L7 mismatch for wrong header, got %+v", d)
	}

	// Federated trust_domain + gRPC rule matches Charge and denies Refund.
	federatedID := "spiffe://federated.mesh/ns/orders/sa/checkout"
	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity:     federatedID,
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "grpc-pay",
		DestProtocol:       "grpc",
		InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method:      "POST",
			Path:        "/payment.v1.PaymentService/Charge",
			IsGRPC:      true,
			GRPCService: "payment.v1.PaymentService",
			GRPCMethod:  "Charge",
		},
	}); !d.Allowed || d.MatchedPolicy != "prod/cp-grpc-policy" {
		t.Fatalf("expected federated gRPC Charge allow, got %+v", d)
	}
	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity:     federatedID,
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "grpc-pay",
		DestProtocol:       "grpc",
		InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method:      "POST",
			Path:        "/payment.v1.PaymentService/Refund",
			IsGRPC:      true,
			GRPCService: "payment.v1.PaymentService",
			GRPCMethod:  "Refund",
		},
	}); d.Allowed || d.Reason != model.AuthzReasonL7Mismatch {
		t.Fatalf("expected federated gRPC Refund deny with l7_mismatch, got %+v", d)
	}

	// Temporal expiration stops matching after ValidUntil.
	clockNow = time.Date(2026, 11, 27, 13, 0, 0, 0, time.UTC)
	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity:     partnerID,
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "payments",
		DestPort:           8443,
		DestProtocol:       "http",
		InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method:  "POST",
			Path:    "/healthz",
			Headers: http.Header{"X-Tenant": {"acme"}},
		},
	}); d.Allowed {
		t.Fatalf("expected expired CP policy to deny, got %+v", d)
	}

	// ScopeUpdate MODIFY extends ValidUntil, changes port to 9443, and adds GET /status.
	e.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_MODIFY,
		AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
			{
				Name:      "cp-http-policy",
				Namespace: "prod",
				Action:    "ALLOW",
				Source: &omnimeshv1.SelectorInfo{
					SpiffeId: partnerID,
				},
				Destination: &omnimeshv1.SelectorInfo{
					Namespace: "prod",
					Name:      "payments",
				},
				DestinationPorts: []int32{9443},
				Rules: []*omnimeshv1.AuthzRuleInfo{
					{
						Http: &omnimeshv1.HttpAuthzRuleInfo{
							Methods:   []string{"GET"},
							PathExact: []string{"/status"},
						},
					},
				},
				ValidFrom:  "2026-11-27T11:00:00Z",
				ValidUntil: "2026-11-27T15:00:00Z",
			},
		},
	})

	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity:     partnerID,
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "payments",
		DestPort:           9443,
		DestProtocol:       "http",
		InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method: "GET",
			Path:   "/status",
		},
	}); !d.Allowed || d.MatchedPolicy != "prod/cp-http-policy" {
		t.Fatalf("expected updated CP policy on port 9443 GET /status to allow, got %+v", d)
	}

	// ScopeUpdate REMOVE revokes the policy.
	e.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
		AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
			{Name: "cp-http-policy", Namespace: "prod"},
		},
	})

	if d := e.AuthorizeHTTP(ctx, model.AuthzRequest{
		CallerIdentity:     partnerID,
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "payments",
		DestPort:           9443,
		DestProtocol:       "http",
		InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method: "GET",
			Path:   "/status",
		},
	}); d.Allowed || d.Reason != model.AuthzReasonNoPolicy {
		t.Fatalf("expected denial after ScopeUpdate REMOVE, got %+v", d)
	}
}

func TestEngine_ConcurrencyRace(t *testing.T) {
	e := mustNewEngine(t, model.DefaultAuthorizationConfig(), authz.WithTrustDomain("omnimesh.local"))
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			e.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
				Namespaces: []*omnimeshv1.NamespaceInfo{{Name: "prod", Isolation: "strict"}},
				AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
					{
						Name:        fmt.Sprintf("allow-%d", i%3),
						Namespace:   "prod",
						Action:      "ALLOW",
						Source:      &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "web"},
						Destination: &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "api"},
					},
				},
			})
			e.ApplyUpdate(&omnimeshv1.ScopeUpdate{
				Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_ADD,
				AuthzPolicies: []*omnimeshv1.AuthzPolicyInfo{
					{
						Name:        "temp-deny",
						Namespace:   "prod",
						Action:      "DENY",
						Source:      &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "rogue"},
						Destination: &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "api"},
					},
				},
			})
		}
	}()

	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				_ = e.AuthorizeConnection(ctx, model.AuthzRequest{
					CallerIdentity:     "spiffe://omnimesh.local/ns/prod/sa/web",
					CallerVerified:     true,
					DestNamespace:      "prod",
					DestServiceName:    "api",
					InboundL7Available: true,
				})
				_ = e.AuthorizeHTTP(ctx, model.AuthzRequest{
					CallerIdentity:     "spiffe://omnimesh.local/ns/prod/sa/rogue",
					CallerVerified:     true,
					DestNamespace:      "prod",
					DestServiceName:    "api",
					InboundL7Available: true,
					HTTP: &model.HTTPAuthzAttributes{
						Method: "GET",
						Path:   "/items",
					},
				})
			}
		}()
	}

	wg.Wait()
	if stats := e.Stats(); stats.AllowedTotal+stats.DeniedTotal == 0 {
		t.Fatalf("expected non-zero evaluated decisions")
	}
}

func BenchmarkAuthorizeConnection(b *testing.B) {
	e, err := authz.NewEngine(model.AuthorizationConfig{
		Mode:           "strict",
		AuditLogAllows: false,
	}, authz.WithTrustDomain("omnimesh.local"))
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	policies := make([]*omnimeshv1.AuthzPolicyInfo, 0, 50)
	for i := 0; i < 50; i++ {
		policies = append(policies, &omnimeshv1.AuthzPolicyInfo{
			Name:        fmt.Sprintf("p-%02d", i),
			Namespace:   "prod",
			Action:      "ALLOW",
			Source:      &omnimeshv1.SelectorInfo{Namespace: "prod", Name: fmt.Sprintf("svc-%02d", i)},
			Destination: &omnimeshv1.SelectorInfo{Namespace: "prod", Name: "target"},
		})
	}
	e.ApplySnapshot(&omnimeshv1.ScopeSnapshot{AuthzPolicies: policies})

	req := model.AuthzRequest{
		CallerIdentity:     "spiffe://omnimesh.local/ns/prod/sa/svc-25",
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "target",
		InboundL7Available: true,
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := e.AuthorizeConnection(ctx, req); !d.Allowed {
			b.Fatalf("expected allow")
		}
	}
}

func BenchmarkAuthorizeHTTP(b *testing.B) {
	e, err := authz.NewEngine(model.AuthorizationConfig{
		Mode:      "strict",
		EnforceL7: true,
		LocalPolicies: []model.LocalAuthzPolicy{
			{
				Name:        "http-allow",
				Namespace:   "prod",
				Action:      "allow",
				Source:      model.AuthzSelector{Namespace: "prod", Name: "web"},
				Destination: model.AuthzSelector{Namespace: "prod", Name: "api"},
				Rules: []model.AuthzRule{
					{
						HTTP: &model.HTTPAuthzRule{
							Methods:      []string{"GET", "POST"},
							PathPrefixes: []string{"/api/v1/"},
						},
					},
				},
			},
		},
	}, authz.WithTrustDomain("omnimesh.local"))
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	req := model.AuthzRequest{
		CallerIdentity:     "spiffe://omnimesh.local/ns/prod/sa/web",
		CallerVerified:     true,
		DestNamespace:      "prod",
		DestServiceName:    "api",
		DestProtocol:       "http",
		InboundL7Available: true,
		HTTP: &model.HTTPAuthzAttributes{
			Method: "POST",
			Path:   "/api/v1/orders",
		},
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := e.AuthorizeHTTP(ctx, req); !d.Allowed {
			b.Fatalf("expected allow")
		}
	}
}
