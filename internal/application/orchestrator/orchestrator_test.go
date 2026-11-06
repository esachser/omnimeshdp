package orchestrator_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/application/orchestrator"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
)

// Mock PacketProcessor
type mockPacketProcessor struct {
	mu          sync.Mutex
	subnets     []string
	runCalled   bool
	closeCalled bool
}

func (m *mockPacketProcessor) Run(ctx context.Context) error {
	m.mu.Lock()
	m.runCalled = true
	m.mu.Unlock()
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
	m.mu.Lock()
	m.closeCalled = true
	m.mu.Unlock()
	return nil
}

func (m *mockPacketProcessor) isRunCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runCalled
}

func (m *mockPacketProcessor) isCloseCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeCalled
}

// Mock ControlPlaneClient
type mockControlPlaneClient struct {
	mu                   sync.Mutex
	connectCalled        bool
	connectErr           error
	registerCalled       bool
	snapshotErr          error
	snapshotToReturn     *omnimeshv1.ScopeSnapshot
	reconnectSnapshot    *omnimeshv1.ScopeSnapshot
	sendServicesCalled   bool
	servicesSent         []model.NodeServiceInfo
	streamUpdatesCalled  bool
	closeCalled          bool
	failStreamCount      int32
	streamErrToReturn    error
	updatesCh            chan *omnimeshv1.ScopeUpdate
	serviceUpdatesCh     chan []model.NodeServiceInfo
	healthReportCh       chan *omnimeshv1.HealthReport
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
	if m.reconnectSnapshot != nil && m.streamUpdatesCalled {
		return m.reconnectSnapshot, nil
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
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{
				Name:    "default",
				Cidr:    "10.10.10.0/24",
				Subnets: []string{"10.10.10.0/24"},
			},
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

func (m *mockControlPlaneClient) SendServiceUpdates(ctx context.Context, added, removed []model.NodeServiceInfo) error {
	m.mu.Lock()
	m.sendServicesCalled = true
	m.servicesSent = added
	ch := m.serviceUpdatesCh
	m.mu.Unlock()
	if ch != nil && len(added) > 0 {
		ch <- added
	}
	return nil
}

func (m *mockControlPlaneClient) SendHealthReport(ctx context.Context, report *omnimeshv1.HealthReport) error {
	m.mu.Lock()
	ch := m.healthReportCh
	m.mu.Unlock()
	if ch != nil {
		ch <- report
	}
	return nil
}

func (m *mockControlPlaneClient) StreamUpdates(ctx context.Context, onUpdate func(*omnimeshv1.ScopeUpdate)) error {
	m.mu.Lock()
	m.streamUpdatesCalled = true
	updatesCh := m.updatesCh
	m.mu.Unlock()

	if atomic.LoadInt32(&m.failStreamCount) > 0 {
		atomic.AddInt32(&m.failStreamCount, -1)
		if m.streamErrToReturn != nil {
			return m.streamErrToReturn
		}
		return errors.New("stream connection lost")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case upd, ok := <-updatesCh:
			if !ok {
				<-ctx.Done()
				return nil
			}
			if onUpdate != nil {
				onUpdate(upd)
			}
		}
	}
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

func (m *mockTLSProvider) GetServerTLSConfig() (*tls.Config, error) {
	return nil, nil
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
	var factorySubnets []string

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithProcessorFactory(func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
			factorySubnets = append([]string(nil), subnets...)
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
	if !mockProc.isRunCalled() {
		t.Errorf("expected PacketProcessor.Run in Step 7")
	}
	if !slices.Equal(factorySubnets, []string{"10.10.10.0/24"}) {
		t.Errorf("expected processor factory to receive namespace subnets [10.10.10.0/24], got %v", factorySubnets)
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

	if !mockProc.isCloseCalled() {
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

func TestOrchestrator_Step6_InvalidNamespaceSubnetsFailed(t *testing.T) {
	cfg := validTestConfig()
	cfg.Spire.Disabled = true

	mockCP := &mockControlPlaneClient{
		snapshotToReturn: &omnimeshv1.ScopeSnapshot{
			Namespaces: []*omnimeshv1.NamespaceInfo{
				{
					Name:    "bad-ns",
					Subnets: []string{"invalid-cidr"},
				},
			},
		},
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
		t.Fatalf("expected error when namespace subnet CIDR is invalid")
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

func TestOrchestrator_ControlPlaneReconnectOnStreamFailure(t *testing.T) {
	cfg := validTestConfig()
	mockProc := &mockPacketProcessor{}

	reconnectSnap := &omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "default", Name: "reconnected-svc", MeshAddr: "10.20.20.1", Port: 8080},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "default",
				ServiceName: "reconnected-svc",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{Addr: "192.168.1.100:15008"},
				},
			},
		},
	}

	mockCP := &mockControlPlaneClient{
		failStreamCount:   1, // Stream drops once during Step 9, triggering reconnect
		reconnectSnapshot: reconnectSnap,
	}

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithProcessorFactory(func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
			return mockProc, nil
		}),
		orchestrator.WithTLSFactory(func(ctx context.Context, socketPath, serverSVID string) (outbound.TLSConfigProvider, io.Closer, error) {
			return &mockTLSProvider{}, io.NopCloser(nil), nil
		}),
		orchestrator.WithControlPlaneClientFactory(func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient {
			return mockCP
		}),
		orchestrator.WithListenerOpener(func(network, address string) (net.Listener, error) {
			return newMockListener(address), nil
		}),
		orchestrator.WithRetryInterval(10*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- orch.Run(ctx)
	}()

	// Wait for startup and reconnect to happen
	var resolved *model.ResolvedRoute
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		if router := orch.Router(); router != nil {
			r := router.ResolveRoute("10.20.20.1", 8080, "fallback")
			if r.TargetHost == "192.168.1.100:15008" {
				resolved = r
				break
			}
		}
	}

	if resolved == nil {
		t.Fatalf("expected router to have updated route for reconnected-svc after reconnect")
	}

	// Trigger clean shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected nil error on shutdown after reconnect, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for orchestrator shutdown after reconnect")
	}
}

// Mock PacketProcessor that also supports runtime subnet updates.
type mockUpdatableProcessor struct {
	mockPacketProcessor
	mu      sync.Mutex
	updates [][]string
}

func (m *mockUpdatableProcessor) UpdateSubnets(subnets []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates = append(m.updates, subnets)
	return nil
}

func runOrchestratorWithProcessor(t *testing.T, proc outbound.PacketProcessor) (*orchestrator.Orchestrator, context.CancelFunc, chan error) {
	t.Helper()
	cfg := validTestConfig()
	cfg.Spire.Disabled = true

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithProcessorFactory(func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
			return proc, nil
		}),
		orchestrator.WithControlPlaneClientFactory(func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient {
			return &mockControlPlaneClient{}
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
	time.Sleep(100 * time.Millisecond)
	return orch, cancel, errCh
}

func TestOrchestrator_UpdateInterceptionSubnets(t *testing.T) {
	proc := &mockUpdatableProcessor{}
	orch, cancel, errCh := runOrchestratorWithProcessor(t, proc)

	newSubnets := []string{"10.20.0.0/16"}
	if err := orch.UpdateInterceptionSubnets(newSubnets); err != nil {
		t.Fatalf("unexpected error updating subnets: %v", err)
	}

	proc.mu.Lock()
	if len(proc.updates) != 1 || len(proc.updates[0]) != 1 || proc.updates[0][0] != "10.20.0.0/16" {
		t.Errorf("expected processor to receive %v, got %v", newSubnets, proc.updates)
	}
	proc.mu.Unlock()

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("expected nil error on shutdown, got: %v", err)
	}

	if err := orch.UpdateInterceptionSubnets(newSubnets); err == nil {
		t.Errorf("expected error when updating subnets after shutdown")
	}
}

func TestOrchestrator_UpdateInterceptionSubnets_Unsupported(t *testing.T) {
	orch, cancel, errCh := runOrchestratorWithProcessor(t, &mockPacketProcessor{})
	defer func() {
		cancel()
		<-errCh
	}()

	err := orch.UpdateInterceptionSubnets([]string{"10.20.0.0/16"})
	if !errors.Is(err, domain.ErrSubnetUpdateUnsupported) {
		t.Fatalf("expected ErrSubnetUpdateUnsupported, got: %v", err)
	}
}

func TestOrchestrator_DynamicNamespaceChanges_WithSubnetUpdater(t *testing.T) {
	cfg := validTestConfig()
	cfg.Spire.Disabled = true

	proc := &mockUpdatableProcessor{}
	updatesCh := make(chan *omnimeshv1.ScopeUpdate, 10)

	mockCP := &mockControlPlaneClient{
		snapshotToReturn: &omnimeshv1.ScopeSnapshot{
			Namespaces: []*omnimeshv1.NamespaceInfo{
				{
					Name:    "ns-1",
					Subnets: []string{"10.10.10.0/24"},
				},
			},
		},
		updatesCh: updatesCh,
	}

	var initialSubnets []string
	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithProcessorFactory(func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
			initialSubnets = append([]string(nil), subnets...)
			return proc, nil
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

	time.Sleep(100 * time.Millisecond)

	if !slices.Equal(initialSubnets, []string{"10.10.10.0/24"}) {
		t.Fatalf("expected initial subnets [10.10.10.0/24], got %v", initialSubnets)
	}
	if !slices.Equal(orch.Subnets(), []string{"10.10.10.0/24"}) {
		t.Fatalf("expected orch.Subnets() [10.10.10.0/24], got %v", orch.Subnets())
	}

	// 1. Add namespace ns-2
	updatesCh <- &omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_ADD,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{
				Name:    "ns-2",
				Subnets: []string{"10.10.12.0/24", "10.10.14.0/24"},
			},
		},
	}
	time.Sleep(50 * time.Millisecond)

	want := []string{"10.10.10.0/24", "10.10.12.0/24", "10.10.14.0/24"}
	if !slices.Equal(orch.Subnets(), want) {
		t.Fatalf("expected orch.Subnets() after ADD %v, got %v", want, orch.Subnets())
	}

	// 2. Modify namespace ns-2
	updatesCh <- &omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_MODIFY,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{
				Name:    "ns-2",
				Subnets: []string{"10.10.16.0/24"},
			},
		},
	}
	time.Sleep(50 * time.Millisecond)

	want = []string{"10.10.10.0/24", "10.10.16.0/24"}
	if !slices.Equal(orch.Subnets(), want) {
		t.Fatalf("expected orch.Subnets() after MODIFY %v, got %v", want, orch.Subnets())
	}

	// 3. Remove namespace ns-1
	updatesCh <- &omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "ns-1"},
		},
	}
	time.Sleep(50 * time.Millisecond)

	want = []string{"10.10.16.0/24"}
	if !slices.Equal(orch.Subnets(), want) {
		t.Fatalf("expected orch.Subnets() after REMOVE ns-1 %v, got %v", want, orch.Subnets())
	}

	// 4. Remove last namespace ns-2
	updatesCh <- &omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "ns-2"},
		},
	}
	time.Sleep(50 * time.Millisecond)

	if len(orch.Subnets()) != 0 {
		t.Fatalf("expected empty orch.Subnets() after removing all namespaces, got %v", orch.Subnets())
	}

	proc.mu.Lock()
	if len(proc.updates) != 4 {
		t.Fatalf("expected 4 UpdateSubnets calls on processor, got %d: %v", len(proc.updates), proc.updates)
	}
	if len(proc.updates[3]) != 0 {
		t.Errorf("expected last UpdateSubnets call to have empty slice, got %v", proc.updates[3])
	}
	proc.mu.Unlock()

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("expected nil error on shutdown, got: %v", err)
	}
}

func TestOrchestrator_DynamicNamespaceChanges_RecreatesProcessorWhenNotUpdatable(t *testing.T) {
	cfg := validTestConfig()
	cfg.Spire.Disabled = true

	updatesCh := make(chan *omnimeshv1.ScopeUpdate, 10)

	// Start with empty namespaces in initial ScopeSnapshot to also test starting from 0 namespaces
	mockCP := &mockControlPlaneClient{
		snapshotToReturn: &omnimeshv1.ScopeSnapshot{},
		updatesCh:        updatesCh,
	}

	var mu sync.Mutex
	var createdProcessors []*mockPacketProcessor

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithProcessorFactory(func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
			mu.Lock()
			defer mu.Unlock()
			p := &mockPacketProcessor{subnets: append([]string(nil), subnets...)}
			createdProcessors = append(createdProcessors, p)
			return p, nil
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

	time.Sleep(100 * time.Millisecond)

	// Initially 0 namespaces -> no processor created yet
	mu.Lock()
	if len(createdProcessors) != 0 {
		t.Fatalf("expected 0 processors when initial snapshot has no namespaces, got %d", len(createdProcessors))
	}
	mu.Unlock()
	if orch.PacketProcessor() != nil {
		t.Fatalf("expected nil PacketProcessor when no namespaces exist")
	}

	// 1. Add namespace ns-1 -> creates processor #1 with [10.10.10.0/24]
	updatesCh <- &omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_ADD,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "ns-1", Subnets: []string{"10.10.10.0/24"}},
		},
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(createdProcessors) != 1 {
		t.Fatalf("expected 1 processor created after adding ns-1, got %d", len(createdProcessors))
	}
	proc1 := createdProcessors[0]
	mu.Unlock()

	if !proc1.isRunCalled() {
		t.Errorf("expected proc1.Run to be called")
	}
	if !slices.Equal(proc1.subnets, []string{"10.10.10.0/24"}) {
		t.Errorf("expected proc1 subnets [10.10.10.0/24], got %v", proc1.subnets)
	}

	// 2. Add namespace ns-2 -> closes proc1, creates processor #2 with [10.10.10.0/24, 10.10.12.0/24]
	updatesCh <- &omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_ADD,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "ns-2", Subnets: []string{"10.10.12.0/24"}},
		},
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(createdProcessors) != 2 {
		t.Fatalf("expected 2 processors created after adding ns-2, got %d", len(createdProcessors))
	}
	proc2 := createdProcessors[1]
	mu.Unlock()

	if !proc1.isCloseCalled() {
		t.Errorf("expected proc1.Close to be called when replaced by proc2")
	}
	if !proc2.isRunCalled() {
		t.Errorf("expected proc2.Run to be called")
	}
	if !slices.Equal(proc2.subnets, []string{"10.10.10.0/24", "10.10.12.0/24"}) {
		t.Errorf("expected proc2 subnets [10.10.10.0/24, 10.10.12.0/24], got %v", proc2.subnets)
	}

	// 3. Remove namespace ns-1 -> closes proc2, creates processor #3 with [10.10.12.0/24]
	updatesCh <- &omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "ns-1"},
		},
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(createdProcessors) != 3 {
		t.Fatalf("expected 3 processors created after removing ns-1, got %d", len(createdProcessors))
	}
	proc3 := createdProcessors[2]
	mu.Unlock()

	if !proc2.isCloseCalled() {
		t.Errorf("expected proc2.Close to be called when replaced by proc3")
	}
	if !proc3.isRunCalled() {
		t.Errorf("expected proc3.Run to be called")
	}
	if !slices.Equal(proc3.subnets, []string{"10.10.12.0/24"}) {
		t.Errorf("expected proc3 subnets [10.10.12.0/24], got %v", proc3.subnets)
	}

	// 4. Remove last namespace ns-2 -> closes proc3, sets PacketProcessor to nil
	updatesCh <- &omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "ns-2"},
		},
	}
	time.Sleep(50 * time.Millisecond)

	if !proc3.isCloseCalled() {
		t.Errorf("expected proc3.Close to be called when all namespaces are removed")
	}
	if orch.PacketProcessor() != nil {
		t.Errorf("expected nil PacketProcessor after removing all namespaces")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("expected nil error on shutdown, got: %v", err)
	}
}

func TestOrchestratorDynamicServicesAndHealth(t *testing.T) {
	tmpDir := t.TempDir()
	servicesDir := filepath.Join(tmpDir, "services.d")
	if err := os.MkdirAll(servicesDir, 0755); err != nil {
		t.Fatalf("failed to create servicesDir: %v", err)
	}

	// Local listener for health check
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

	mockCP := &mockControlPlaneClient{
		snapshotToReturn: &omnimeshv1.ScopeSnapshot{
			Namespaces: []*omnimeshv1.NamespaceInfo{
				{Name: "default", Subnets: []string{"10.0.0.0/24"}},
			},
		},
		serviceUpdatesCh: make(chan []model.NodeServiceInfo, 5),
		healthReportCh:   make(chan *omnimeshv1.HealthReport, 5),
	}

	cfg := model.DefaultConfig()
	cfg.Spire.Disabled = true
	cfg.ServicesDir = servicesDir

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithProcessorFactory(func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
			return &mockPacketProcessor{subnets: subnets}, nil
		}),
		orchestrator.WithControlPlaneClientFactory(func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient {
			return mockCP
		}),
		orchestrator.WithListenerOpener(func(network, address string) (net.Listener, error) {
			return newMockListener(address), nil
		}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- orch.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	if orch.ServiceManager() == nil {
		t.Fatalf("expected ServiceManager to be initialized")
	}

	// Drop a dynamic service file into services.d
	svcFile := filepath.Join(servicesDir, "web.json")
	svcJSON := fmt.Sprintf(`{
		"namespace": "default",
		"name": "web-svc",
		"id": "web-1",
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

	// 1. Verify service update is advised to Control Plane
	select {
	case added := <-mockCP.serviceUpdatesCh:
		if len(added) != 1 || added[0].Name != "web-svc" {
			t.Fatalf("unexpected added services received: %v", added)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for service update event to control plane")
	}

	// 2. Verify health report is advised to Control Plane
	select {
	case hr := <-mockCP.healthReportCh:
		if hr.ServiceName != "web-svc" || hr.Status != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_HEALTHY {
			t.Fatalf("unexpected health report received: %+v", hr)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for health report event to control plane")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("unexpected error on shutdown: %v", err)
	}
}

type mockWorkloadSVIDProvider struct{}

func (m *mockWorkloadSVIDProvider) GetClientTLSConfigByPID(ctx context.Context, pid uint64) (*tls.Config, string, error) {
	return &tls.Config{}, "spiffe://omnimesh.local/ns/default/sa/test-service", nil
}

type testCloser struct {
	onClose func()
}

func (c *testCloser) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

func TestOrchestrator_WorkloadSVIDProviderWiring(t *testing.T) {
	cfg := validTestConfig()
	mockProc := &mockPacketProcessor{}
	mockCP := &mockControlPlaneClient{}

	svidFactoryCalled := false
	svidCloserClosed := false

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithProcessorFactory(func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
			return mockProc, nil
		}),
		orchestrator.WithTLSFactory(func(ctx context.Context, socketPath, serverSVID string) (outbound.TLSConfigProvider, io.Closer, error) {
			return &mockTLSProvider{}, io.NopCloser(nil), nil
		}),
		orchestrator.WithWorkloadSVIDProviderFactory(func(ctx context.Context, socketPath string, bundleSource x509bundle.Source, trustDomain string) (outbound.WorkloadSVIDProvider, io.Closer, error) {
			svidFactoryCalled = true
			return &mockWorkloadSVIDProvider{}, &testCloser{onClose: func() { svidCloserClosed = true }}, nil
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

	time.Sleep(100 * time.Millisecond)

	if !svidFactoryCalled {
		t.Errorf("expected WorkloadSVIDProviderFactory to be called in Step 2")
	}

	if orch.WorkloadSVIDProvider() == nil {
		t.Errorf("expected active WorkloadSVIDProvider on orchestrator")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("unexpected error on shutdown: %v", err)
	}

	if !svidCloserClosed {
		t.Errorf("expected SVID closer to be called during Cleanup")
	}
}

