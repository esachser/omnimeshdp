package agent

import (
	"context"
	"log"
	"os"
	"runtime"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

/**
TODO: We must reconnect when connection is lost.
*/

// ControlPlaneAgent orchestrates node registration and telemetry/update streaming with omnimeshcontrol.
type ControlPlaneAgent struct {
	client outbound.ControlPlaneClient
	nodeID string
	target string
}

// NewControlPlaneAgent constructs a new ControlPlaneAgent instance.
func NewControlPlaneAgent(client outbound.ControlPlaneClient) *ControlPlaneAgent {
	nodeID := os.Getenv("NODE_ID")
	if nodeID == "" {
		nodeID = "node-1"
	}

	target := os.Getenv("NETWORK_TARGET")
	if target == "" {
		target = "default"
	}

	return &ControlPlaneAgent{
		client: client,
		nodeID: nodeID,
		target: target,
	}
}

// NewControlPlaneAgentWithConfig constructs a ControlPlaneAgent using explicit nodeID and target.
func NewControlPlaneAgentWithConfig(client outbound.ControlPlaneClient, nodeID, target string) *ControlPlaneAgent {
	if nodeID == "" {
		nodeID = "node-1"
	}
	if target == "" {
		target = "default"
	}
	return &ControlPlaneAgent{
		client: client,
		nodeID: nodeID,
		target: target,
	}
}

// Connect establishes the connection to the control plane (Step 4).
func (a *ControlPlaneAgent) Connect(ctx context.Context) error {
	return a.client.Connect(ctx)
}

// RegisterAndGetSnapshot registers this node and receives the initial ScopeSnapshot (Step 5).
func (a *ControlPlaneAgent) RegisterAndGetSnapshot(
	ctx context.Context,
	externalAddr string,
	services []model.NodeServiceInfo,
) (*omnimeshv1.ScopeSnapshot, error) {
	platform := runtime.GOOS
	if platform != "windows" && platform != "linux" && platform != "darwin" {
		platform = "linux"
	}

	if externalAddr == "" {
		externalAddr = "127.0.0.1:15008"
	}

	reg := &model.NodeRegistration{
		NodeID:   a.nodeID,
		Platform: platform,
		Addr:     externalAddr,
		Labels:   make(map[string]string),
		Services: services,
		Target:   a.target,
	}

	return a.client.RegisterAndGetSnapshot(ctx, reg)
}

// SendDeployedServices sends service updates to the Control Plane (Step 9).
func (a *ControlPlaneAgent) SendDeployedServices(ctx context.Context, services []model.NodeServiceInfo) error {
	return a.client.SendUpdateServices(ctx, services)
}

// StreamUpdates streams updates from the Control Plane (Step 9).
func (a *ControlPlaneAgent) StreamUpdates(ctx context.Context, onUpdate func(*omnimeshv1.ScopeUpdate)) error {
	return a.client.StreamUpdates(ctx, onUpdate)
}

// Close terminates the agent's connection.
func (a *ControlPlaneAgent) Close() error {
	return a.client.Close()
}

// Start begins node registration and streaming with the control plane (legacy runner).
func (a *ControlPlaneAgent) Start(ctx context.Context) error {
	platform := runtime.GOOS
	if platform != "windows" && platform != "linux" && platform != "darwin" {
		platform = "linux"
	}

	reg := &model.NodeRegistration{
		NodeID:   a.nodeID,
		Platform: platform,
		Addr:     "127.0.0.1:15008",
		Labels:   make(map[string]string),
		Services: make([]model.NodeServiceInfo, 0),
		Target:   a.target,
	}

	for {
		err := a.client.Run(ctx, reg)
		if err == nil {
			break
		}
		log.Printf("Failed to run control plane agent: %v\n", err)
		log.Println("Retrying in 5 seconds")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}

	return nil
}
