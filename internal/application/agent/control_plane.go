package agent

import (
	"context"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

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

// Start begins node registration and streaming with the control plane.
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
		time.Sleep(5 * time.Second)
	}

	return nil
}
