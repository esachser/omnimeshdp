package agent

import (
	"context"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

/*
Control plane connection lifecycle:
When the connection to the control plane is lost, the data plane continues
operating uninterrupted with its current routing status and packet interception rules.
In the background, the control plane agent continuously attempts to reconnect,
re-registers the node, retrieves an updated ScopeSnapshot, and resumes streaming updates.
*/

// ControlPlaneAgent orchestrates node registration and telemetry/update streaming with omnimeshcontrol.
type ControlPlaneAgent struct {
	client           outbound.ControlPlaneClient
	nodeID           string
	target           string
	retryInterval    time.Duration

	mu               sync.Mutex
	lastExternalAddr string
	lastServices     []model.NodeServiceInfo
	lastHealth       map[string]*omnimeshv1.HealthReport
	labels           map[string]string
	onSnapshot       func(*omnimeshv1.ScopeSnapshot)
	closeCh          chan struct{}
	closed           bool
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

	retryInterval := 5 * time.Second
	if intervalStr := os.Getenv("CONTROL_PLANE_RETRY_INTERVAL"); intervalStr != "" {
		if d, err := time.ParseDuration(intervalStr); err == nil && d > 0 {
			retryInterval = d
		}
	}

	return &ControlPlaneAgent{
		client:        client,
		nodeID:        nodeID,
		target:        target,
		retryInterval: retryInterval,
		labels:        make(map[string]string),
		lastHealth:    make(map[string]*omnimeshv1.HealthReport),
		closeCh:       make(chan struct{}),
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
		client:        client,
		nodeID:        nodeID,
		target:        target,
		retryInterval: 5 * time.Second,
		labels:        make(map[string]string),
		lastHealth:    make(map[string]*omnimeshv1.HealthReport),
		closeCh:       make(chan struct{}),
	}
}

// SetLabels sets the node labels reported during registration.
func (a *ControlPlaneAgent) SetLabels(labels map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.labels = make(map[string]string, len(labels))
	for k, v := range labels {
		a.labels[k] = v
	}
}

// SetSnapshotHandler registers a callback invoked whenever a new ScopeSnapshot is received upon reconnection.
func (a *ControlPlaneAgent) SetSnapshotHandler(handler func(*omnimeshv1.ScopeSnapshot)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onSnapshot = handler
	if setter, ok := a.client.(interface{ SetSnapshotHandler(func(*omnimeshv1.ScopeSnapshot)) }); ok {
		setter.SetSnapshotHandler(handler)
	}
}

// SetRetryInterval sets the backoff duration between reconnection attempts.
func (a *ControlPlaneAgent) SetRetryInterval(interval time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retryInterval = interval
}

func (a *ControlPlaneAgent) getRetryInterval() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.retryInterval <= 0 {
		return 5 * time.Second
	}
	return a.retryInterval
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

	a.mu.Lock()
	a.lastExternalAddr = externalAddr
	if len(services) > 0 {
		a.lastServices = services
	}
	labelsCopy := make(map[string]string, len(a.labels))
	for k, v := range a.labels {
		labelsCopy[k] = v
	}
	a.mu.Unlock()

	reg := &model.NodeRegistration{
		NodeID:   a.nodeID,
		Platform: platform,
		Addr:     externalAddr,
		Labels:   labelsCopy,
		Services: services,
		Target:   a.target,
	}

	return a.client.RegisterAndGetSnapshot(ctx, reg)
}

// SendDeployedServices sends service updates to the Control Plane (Step 9).
func (a *ControlPlaneAgent) SendDeployedServices(ctx context.Context, services []model.NodeServiceInfo) error {
	a.mu.Lock()
	a.lastServices = services
	a.mu.Unlock()
	return a.client.SendUpdateServices(ctx, services)
}

// SendServiceUpdates sends added and removed services to the Control Plane and updates tracked services.
func (a *ControlPlaneAgent) SendServiceUpdates(ctx context.Context, added, removed []model.NodeServiceInfo) error {
	a.mu.Lock()
	svcMap := make(map[string]model.NodeServiceInfo)
	for _, s := range a.lastServices {
		svcMap[s.Key()] = s
	}
	for _, s := range removed {
		delete(svcMap, s.Key())
		if a.lastHealth != nil {
			// Clean up health for removed services
			for k := range a.lastHealth {
				if s.Key() == s.Namespace+"/"+s.Name+"/"+s.ID {
					delete(a.lastHealth, k)
				}
			}
		}
	}
	for _, s := range added {
		svcMap[s.Key()] = s
	}
	newList := make([]model.NodeServiceInfo, 0, len(svcMap))
	for _, s := range svcMap {
		newList = append(newList, s)
	}
	a.lastServices = newList
	a.mu.Unlock()

	return a.client.SendServiceUpdates(ctx, added, removed)
}

// SendHealthReport sends an endpoint health status report to the Control Plane and tracks it.
func (a *ControlPlaneAgent) SendHealthReport(ctx context.Context, report *omnimeshv1.HealthReport) error {
	a.mu.Lock()
	if a.lastHealth == nil {
		a.lastHealth = make(map[string]*omnimeshv1.HealthReport)
	}
	key := report.Namespace + "/" + report.ServiceName + "/" + report.RouteName
	a.lastHealth[key] = report
	a.mu.Unlock()

	return a.client.SendHealthReport(ctx, report)
}

// StreamUpdates streams updates from the Control Plane (Step 9).
// If the connection to the Control Plane is lost, the data plane continues
// operating uninterrupted with its current routing status, and this agent
// continuously attempts to reconnect in the background.
func (a *ControlPlaneAgent) StreamUpdates(ctx context.Context, onUpdate func(*omnimeshv1.ScopeUpdate)) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		a.mu.Lock()
		closed := a.closed
		a.mu.Unlock()
		if closed {
			return nil
		}

		err := a.client.StreamUpdates(ctx, onUpdate)
		if ctx.Err() != nil {
			log.Println("[ControlPlaneAgent] Context cancelled, stopping stream updates.")
			return nil
		}

		a.mu.Lock()
		closed = a.closed
		a.mu.Unlock()
		if closed {
			return nil
		}

		// Stream ended unexpectedly (connection lost)
		log.Printf("[ControlPlaneAgent] Connection to Control Plane lost: %v. Data plane continues operating with current routing status.\n", err)

		// Reconnect loop: keeps attempting until successful or context cancellation
		if err := a.reconnect(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

// reconnect executes the retry loop to re-establish connection and registration with the Control Plane.
func (a *ControlPlaneAgent) reconnect(ctx context.Context) error {
	attempt := 0

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		a.mu.Lock()
		closed := a.closed
		a.mu.Unlock()
		if closed {
			return nil
		}

		retryInterval := a.getRetryInterval()
		attempt++
		log.Printf("[ControlPlaneAgent] Waiting %v before reconnect attempt %d...\n", retryInterval, attempt)

		select {
		case <-ctx.Done():
			log.Println("[ControlPlaneAgent] Context cancelled during reconnection wait.")
			return ctx.Err()
		case <-a.closeCh:
			log.Println("[ControlPlaneAgent] Agent closed during reconnection wait.")
			return nil
		case <-time.After(retryInterval):
		}

		a.mu.Lock()
		closed = a.closed
		a.mu.Unlock()
		if closed {
			return nil
		}

		log.Printf("[ControlPlaneAgent] Attempting to reconnect to Control Plane (attempt %d)...\n", attempt)

		// Close any stale connection resources
		_ = a.client.Close()

		// Attempt to re-establish connection
		if err := a.client.Connect(ctx); err != nil {
			log.Printf("[ControlPlaneAgent] Reconnect attempt %d failed to connect: %v. Data plane remains active with current routes. Retrying in %v...\n",
				attempt, err, retryInterval)
			continue
		}
		log.Println("[ControlPlaneAgent] Successfully re-established connection to Control Plane.")

		// Retrieve stored node registration parameters
		a.mu.Lock()
		extAddr := a.lastExternalAddr
		services := a.lastServices
		snapshotHandler := a.onSnapshot
		healthReports := make([]*omnimeshv1.HealthReport, 0, len(a.lastHealth))
		for _, hr := range a.lastHealth {
			healthReports = append(healthReports, hr)
		}
		a.mu.Unlock()

		if extAddr == "" {
			extAddr = "127.0.0.1:15008"
		}

		// Re-register node and obtain updated ScopeSnapshot
		log.Println("[ControlPlaneAgent] Re-registering node with Control Plane...")
		snapshot, err := a.RegisterAndGetSnapshot(ctx, extAddr, services)
		if err != nil {
			log.Printf("[ControlPlaneAgent] Reconnect attempt %d failed during node re-registration: %v. Data plane remains active with current routes. Retrying in %v...\n",
				attempt, err, retryInterval)
			continue
		}

		log.Printf("[ControlPlaneAgent] Node successfully re-registered with Control Plane. Received ScopeSnapshot with %d services and %d routes.\n",
			len(snapshot.Services), len(snapshot.Routes))

		// Apply newly received snapshot to update data plane routing tables
		if snapshotHandler != nil && snapshot != nil {
			log.Println("[ControlPlaneAgent] Applying updated ScopeSnapshot to data plane router.")
			snapshotHandler(snapshot)
		}

		// Re-send deployed services if any were previously registered
		if len(services) > 0 {
			log.Printf("[ControlPlaneAgent] Re-sending %d deployed services to Control Plane...\n", len(services))
			if err := a.client.SendServiceUpdates(ctx, services, nil); err != nil {
				log.Printf("[ControlPlaneAgent] Warning: failed to re-send deployed services after reconnect: %v\n", err)
			} else {
				log.Println("[ControlPlaneAgent] Successfully re-sent deployed services to Control Plane.")
			}
		}

		// Re-send health reports if any were tracked
		for _, hr := range healthReports {
			if err := a.client.SendHealthReport(ctx, hr); err != nil {
				log.Printf("[ControlPlaneAgent] Warning: failed to re-send health report for %s/%s after reconnect: %v\n",
					hr.Namespace, hr.ServiceName, err)
			}
		}

		log.Println("[ControlPlaneAgent] Control plane reconnection complete. Resuming update stream.")
		return nil
	}
}

// Close terminates the agent's connection and cancels any pending reconnection attempts.
func (a *ControlPlaneAgent) Close() error {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.closeCh)
	}
	a.mu.Unlock()
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
