package service_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/application/agent"
	"github.com/esachser/omnimeshdp/internal/application/service"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

type mockAgentClient struct {
	mu           sync.Mutex
	addedSent    []model.NodeServiceInfo
	removedSent  []model.NodeServiceInfo
	healthReport *omnimeshv1.HealthReport
	addedCh      chan []model.NodeServiceInfo
	healthCh     chan *omnimeshv1.HealthReport
}

func (m *mockAgentClient) Connect(ctx context.Context) error { return nil }
func (m *mockAgentClient) RegisterAndGetSnapshot(ctx context.Context, reg *model.NodeRegistration) (*omnimeshv1.ScopeSnapshot, error) {
	return &omnimeshv1.ScopeSnapshot{}, nil
}
func (m *mockAgentClient) SendUpdateServices(ctx context.Context, services []model.NodeServiceInfo) error {
	return m.SendServiceUpdates(ctx, services, nil)
}
func (m *mockAgentClient) SendServiceUpdates(ctx context.Context, added, removed []model.NodeServiceInfo) error {
	m.mu.Lock()
	m.addedSent = append(m.addedSent, added...)
	m.removedSent = append(m.removedSent, removed...)
	ch := m.addedCh
	m.mu.Unlock()
	if ch != nil && len(added) > 0 {
		ch <- added
	}
	return nil
}
func (m *mockAgentClient) SendHealthReport(ctx context.Context, report *omnimeshv1.HealthReport) error {
	m.mu.Lock()
	m.healthReport = report
	ch := m.healthCh
	m.mu.Unlock()
	if ch != nil {
		ch <- report
	}
	return nil
}
func (m *mockAgentClient) StreamUpdates(ctx context.Context, onUpdate func(*omnimeshv1.ScopeUpdate)) error {
	<-ctx.Done()
	return nil
}
func (m *mockAgentClient) Run(ctx context.Context, reg *model.NodeRegistration) error { return nil }
func (m *mockAgentClient) Close() error                                                { return nil }

func TestManagerDynamicServiceAndHealthEvents(t *testing.T) {
	// TCP listener to simulate local service
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	mockClient := &mockAgentClient{
		addedCh:  make(chan []model.NodeServiceInfo, 5),
		healthCh: make(chan *omnimeshv1.HealthReport, 5),
	}
	cpAgent := agent.NewControlPlaneAgentWithConfig(mockClient, "test-node", "default")

	tmpDir := t.TempDir()

	mgr := service.NewManager(service.ManagerConfig{
		ServicesDir:       tmpDir,
		ControlPlaneAgent: cpAgent,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("failed to start manager: %v", err)
	}
	defer mgr.Close()

	// Drop a service definition into the watched directory
	svcFile := filepath.Join(tmpDir, "dynamic-svc.json")
	svcJSON := fmt.Sprintf(`{
		"namespace": "default",
		"name": "dynamic-svc",
		"id": "dyn-1",
		"labels": {"app": "dynamic"},
		"health_check": {
			"type": "TCP",
			"address": %q,
			"interval": "50ms",
			"timeout": "50ms",
			"healthy_threshold": 1,
			"unhealthy_threshold": 1
		}
	}`, ln.Addr().String())

	if err := os.WriteFile(svcFile, []byte(svcJSON), 0644); err != nil {
		t.Fatalf("failed to write service file: %v", err)
	}

	// 1. Wait for service update event to control plane
	select {
	case added := <-mockClient.addedCh:
		if len(added) != 1 || added[0].Name != "dynamic-svc" {
			t.Fatalf("unexpected added services received: %v", added)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for service update event to control plane")
	}

	// 2. Wait for health report event to control plane
	select {
	case report := <-mockClient.healthCh:
		if report.ServiceName != "dynamic-svc" || report.Status != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_HEALTHY {
			t.Fatalf("unexpected health report received: %+v", report)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for health report event to control plane")
	}

	if mgr.Watcher() == nil {
		t.Errorf("expected Watcher to not be nil")
	}
	if mgr.HealthChecker() == nil {
		t.Errorf("expected HealthChecker to not be nil")
	}
}

