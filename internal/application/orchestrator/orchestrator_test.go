package orchestrator_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/application/orchestrator"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

// Mock PacketProcessor
type mockPacketProcessor struct {
	runCalled   bool
	closeCalled bool
}

func (m *mockPacketProcessor) Run(ctx context.Context) error {
	m.runCalled = true
	<-ctx.Done()
	return nil
}

func (m *mockPacketProcessor) GetIdentityByPID(pid uint64) (string, bool) {
	return "test-sid", true
}

func (m *mockPacketProcessor) GetOriginalPacketInfo(addr net.Addr, socket uintptr) (*model.OriginalPacketInfo, error) {
	return nil, nil
}

func (m *mockPacketProcessor) Close() error {
	m.closeCalled = true
	return nil
}

// Mock ControlPlaneClient
type mockControlPlaneClient struct {
	mu                   sync.Mutex
	connectCalled        bool
	connectErr           error
	registerCalled       bool
	snapshotErr          error
	snapshotToReturn     *omnimeshv1.ScopeSnapshot
	sendServicesCalled   bool
	servicesSent         []model.NodeServiceInfo
	streamUpdatesCalled  bool
	closeCalled          bool
}

func (m *mockControlPlaneClient) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectCalled = true
	return m.connectErr
}

func (m *mockControlPlaneClient) RegisterAndGetSnapshot(ctx context.Context, reg *model.NodeRegistration) (*omnimeshv1.ScopeSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registerCalled = true
	if m.snapshotErr != nil {
		return nil, m.snapshotErr
	}
	if m.snapshotToReturn != nil {
		return m.snapshotToReturn, nil
	}
	return &omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "default", Name: "svc1", MeshAddr: "10.10.10.1", Port: 80},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{Namespace: "default", ServiceName: "svc1"},
		},
	}, nil
}

func (m *mockControlPlaneClient) SendUpdateServices(ctx context.Context, services []model.NodeServiceInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendServicesCalled = true
	m.servicesSent = services
	return nil
}

func (m *mockControlPlaneClient) StreamUpdates(ctx context.Context, onUpdate func(*omnimeshv1.ScopeUpdate)) error {
	m.mu.Lock()
	m.streamUpdatesCalled = true
	m.mu.Unlock()
	<-ctx.Done()
	return nil
}

func (m *mockControlPlaneClient) Run(ctx context.Context, reg *model.NodeRegistration) error {
	return nil
}

func (m *mockControlPlaneClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled = true
	return nil
}

// Mock TLS Config Provider
type mockTLSProvider struct{}

func (m *mockTLSProvider) GetTLSConfig() (*tls.Config, error) {
	return &tls.Config{}, nil
}

// Mock net.Listener
type mockListener struct {
	addr   string
	closed bool
	mu     sync.Mutex
}

func newMockListener(addr string) *mockListener {
	return &mockListener{addr: addr}
}

func (m *mockListener) Accept() (net.Conn, error) {
	// Block until closed
	time.Sleep(100 * time.Millisecond)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, net.ErrClosed
	}
	return nil, net.ErrClosed
}

func (m *mockListener) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 15001}
}

func validTestConfig() *model.AppConfig {
	cfg := model.DefaultConfig()
	cfg.Spire.Disabled = false
	cfg.Interception.Type = "noop"
	cfg.Interception.Subnets = []string{"10.10.10.0/24"}
	cfg.Services = []model.NodeServiceInfo{
		{Namespace: "default", Name: "my-service", ID: "srv-1"},
	}
	return cfg
}

func TestOrchestrator_FullSuccessfulFlow(t *testing.T) {
	cfg := validTestConfig()
	mockProc := &mockPacketProcessor{}
	mockCP := &mockControlPlaneClient{}

	tlsFactoryCalled := false
	tlsCloserClosed := false

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithProcessorFactory(func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
			return mockProc, nil
		}),
		orchestrator.WithTLSFactory(func(ctx context.Context, socketPath, serverSVID string) (outbound.TLSConfigProvider, io.Closer, error) {
			tlsFactoryCalled = true
			return &mockTLSProvider{}, io.NopCloser(nil), nil
		}),
		orchestrator.WithControlPlaneClientFactory(func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient {
			return mockCP
		}),
		orchestrator.WithListenerOpener(func(network, address string) (net.Listener, error) {
			return newMockListener(address), nil
		}),
	)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- orch.Run(ctx)
	}()

	// Give orchestrator time to advance through steps 1-9
	time.Sleep(100 * time.Millisecond)

	if !tlsFactoryCalled {
		t.Errorf("expected TLS factory to be called in Step 2")
	}
	if !mockCP.connectCalled {
		t.Errorf("expected Control Plane Connect in Step 4")
	}
	if !mockCP.registerCalled {
		t.Errorf("expected Control Plane RegisterAndGetSnapshot in Step 5")
	}
	if !mockProc.runCalled {
		t.Errorf("expected PacketProcessor.Run in Step 7")
	}
	if !mockCP.sendServicesCalled {
		t.Errorf("expected SendUpdateServices in Step 9")
	}
	if !mockCP.streamUpdatesCalled {
		t.Errorf("expected StreamUpdates in Step 9")
	}

	// Step 10: Trigger shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected nil error on clean exit, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for orchestrator shutdown")
	}

	if !mockProc.closeCalled {
		t.Errorf("expected PacketProcessor.Close on cleanup")
	}
	if !mockCP.closeCalled {
		t.Errorf("expected ControlPlaneClient.Close on cleanup")
	}
	_ = tlsCloserClosed
}

func TestOrchestrator_Step1_ConfigLoadFailed(t *testing.T) {
	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfigPath("non_existent_file_path_12345.json"),
	)

	err := orch.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error for non-existent config file")
	}
	if !errors.Is(err, domain.ErrConfigLoadFailed) {
		t.Errorf("expected ErrConfigLoadFailed, got: %v", err)
	}
}

func TestOrchestrator_Step2_SpireConnectionFailed(t *testing.T) {
	cfg := validTestConfig()
	cfg.Spire.Disabled = false

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithTLSFactory(func(ctx context.Context, socketPath, serverSVID string) (outbound.TLSConfigProvider, io.Closer, error) {
			return nil, nil, errors.New("spire agent unavailable")
		}),
	)

	err := orch.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when Spire fails")
	}
	if !errors.Is(err, domain.ErrSpireConnectionFailed) {
		t.Errorf("expected ErrSpireConnectionFailed, got: %v", err)
	}
}

func TestOrchestrator_Step3_PortBindFailed_MustNotProceed(t *testing.T) {
	cfg := validTestConfig()
	cfg.Spire.Disabled = true

	mockCP := &mockControlPlaneClient{}

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithListenerOpener(func(network, address string) (net.Listener, error) {
			return nil, errors.New("address already in use")
		}),
		orchestrator.WithControlPlaneClientFactory(func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient {
			return mockCP
		}),
	)

	err := orch.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when port bind fails")
	}
	if !errors.Is(err, domain.ErrPortBindFailed) {
		t.Errorf("expected ErrPortBindFailed, got: %v", err)
	}

	// "The next step must only run after this one succeeds."
	if mockCP.connectCalled {
		t.Errorf("Step 4 must NOT run if Step 3 port bind fails!")
	}
}

func TestOrchestrator_Step4_ControlPlaneConnectFailed(t *testing.T) {
	cfg := validTestConfig()
	cfg.Spire.Disabled = true

	mockCP := &mockControlPlaneClient{
		connectErr: errors.New("connection refused"),
	}

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithListenerOpener(func(network, address string) (net.Listener, error) {
			return newMockListener(address), nil
		}),
		orchestrator.WithControlPlaneClientFactory(func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient {
			return mockCP
		}),
	)

	err := orch.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when control plane connect fails")
	}
	if !errors.Is(err, domain.ErrControlPlaneConnectionFailed) {
		t.Errorf("expected ErrControlPlaneConnectionFailed, got: %v", err)
	}
	if mockCP.registerCalled {
		t.Errorf("Step 5 must NOT run if Step 4 connect fails!")
	}
}

func TestOrchestrator_Step5_InitialSnapshotFailed(t *testing.T) {
	cfg := validTestConfig()
	cfg.Spire.Disabled = true

	mockCP := &mockControlPlaneClient{
		snapshotErr: errors.New("stream EOF without snapshot"),
	}

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithListenerOpener(func(network, address string) (net.Listener, error) {
			return newMockListener(address), nil
		}),
		orchestrator.WithControlPlaneClientFactory(func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient {
			return mockCP
		}),
	)

	err := orch.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when snapshot fails")
	}
	if !errors.Is(err, domain.ErrInitialScopeSnapshotFailed) {
		t.Errorf("expected ErrInitialScopeSnapshotFailed, got: %v", err)
	}
}

func TestOrchestrator_Step6_NoSubnetsFailed(t *testing.T) {
	cfg := validTestConfig()
	cfg.Spire.Disabled = true
	cfg.Interception.Subnets = []string{} // empty subnets

	mockCP := &mockControlPlaneClient{}

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithListenerOpener(func(network, address string) (net.Listener, error) {
			return newMockListener(address), nil
		}),
		orchestrator.WithControlPlaneClientFactory(func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient {
			return mockCP
		}),
	)

	err := orch.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when subnets are empty")
	}
	if !errors.Is(err, domain.ErrSubnetsConfigFailed) {
		t.Errorf("expected ErrSubnetsConfigFailed, got: %v", err)
	}
}

func TestOrchestrator_Step7_PacketProcessorFailed(t *testing.T) {
	cfg := validTestConfig()
	cfg.Spire.Disabled = true

	mockCP := &mockControlPlaneClient{}

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithListenerOpener(func(network, address string) (net.Listener, error) {
			return newMockListener(address), nil
		}),
		orchestrator.WithControlPlaneClientFactory(func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient {
			return mockCP
		}),
		orchestrator.WithProcessorFactory(func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
			return nil, errors.New("driver not installed")
		}),
	)

	err := orch.Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when processor fails to create")
	}
	if !errors.Is(err, domain.ErrPacketProcessorInitFailed) {
		t.Errorf("expected ErrPacketProcessorInitFailed, got: %v", err)
	}
}
