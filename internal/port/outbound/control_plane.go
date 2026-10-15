package outbound

import (
	"context"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

// ControlPlaneClient defines the contract for communicating with the OmniMesh Control Plane.
type ControlPlaneClient interface {
	// Run connects to the control plane, registers the node, and processes the bidirectional stream.
	Run(ctx context.Context, reg *model.NodeRegistration) error
}
