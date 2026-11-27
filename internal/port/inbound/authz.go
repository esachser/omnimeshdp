package inbound

import (
	"context"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

// Authorizer evaluates service-to-service access control at L4 (connection establishment)
// and L7 (HTTP/gRPC requests). Implementations MUST be safe for concurrent use.
type Authorizer interface {
	AuthorizeConnection(ctx context.Context, req model.AuthzRequest) model.AuthzDecision
	AuthorizeHTTP(ctx context.Context, req model.AuthzRequest) model.AuthzDecision
}

// AuthzPolicyUpdater consumes Control Plane ScopeSnapshot and ScopeUpdate messages
// to maintain an up-to-date local authorization policy view.
type AuthzPolicyUpdater interface {
	ApplySnapshot(snapshot *omnimeshv1.ScopeSnapshot)
	ApplyUpdate(update *omnimeshv1.ScopeUpdate)
}

// AuthzDecisionObserver is an optional hook notified after every authorization evaluation
// for audit logging, OpenTelemetry metrics, or tracing integration.
type AuthzDecisionObserver interface {
	OnAuthzDecision(ctx context.Context, req model.AuthzRequest, decision model.AuthzDecision)
}
