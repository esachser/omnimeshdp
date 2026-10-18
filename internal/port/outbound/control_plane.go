package outbound

import (
	"context"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

// ControlPlaneClient defines the contract for communicating with the OmniMesh Control Plane.
type ControlPlaneClient interface {
	// Connect establishes the gRPC client connection and bidirectional agent stream.
	Connect(ctx context.Context) error

	// RegisterAndGetSnapshot sends node registration and receives the initial ScopeSnapshot.
	RegisterAndGetSnapshot(ctx context.Context, reg *model.NodeRegistration) (*omnimeshv1.ScopeSnapshot, error)

	// SendUpdateServices sends updated deployed service definitions to the control plane.
	SendUpdateServices(ctx context.Context, services []model.NodeServiceInfo) error

	// StreamUpdates continuously consumes incoming ScopeUpdate messages until context completion.
	StreamUpdates(ctx context.Context, onUpdate func(*omnimeshv1.ScopeUpdate)) error

	// Run executes registration and streaming as a single combined workflow.
	Run(ctx context.Context, reg *model.NodeRegistration) error

	// Close terminates the gRPC connection and stream.
	Close() error
}
