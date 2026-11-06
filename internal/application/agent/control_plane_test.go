package agent_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/application/agent"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

type mockCPClient struct {
	mu                   sync.Mutex
	connectCalls         int
	registerCalls        int
	sendServicesCalls    int
	streamUpdatesCalls   int
	closeCalls           int

	connectErr           error
	failConnectCount     int32 // fail Connect() N times then succeed
	failRegisterCount    int32 // fail RegisterAndGetSnapshot() N times then succeed
	failStreamCount      int32 // fail StreamUpdates() N times then block on ctx
	snapshotToReturn     *omnimeshv1.ScopeSnapshot
	streamErrToReturn    error
	sentServices         []model.NodeServiceInfo
	lastRegisteredNode   *model.NodeRegistration
	snapshotHandler      func(*omnimeshv1.ScopeSnapshot)
	streamSnapshotToSend *omnimeshv1.ScopeSnapshot
}

func (m *mockCPClient) SetSnapshotHandler(handler func(*omnimeshv1.ScopeSnapshot)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshotHandler = handler
}

func (m *mockCPClient) Connect(ctx context.Context) error {
	m.mu.Lock()
	m.connectCalls++
	m.mu.Unlock()

	if atomic.LoadInt32(&m.failConnectCount) > 0 {
		atomic.AddInt32(&m.failConnectCount, -1)
		return errors.New("connection temporarily unavailable")
	}

	return m.connectErr
}

func (m *mockCPClient) RegisterAndGetSnapshot(ctx context.Context, reg *model.NodeRegistration) (*omnimeshv1.ScopeSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registerCalls++
	m.lastRegisteredNode = reg

	if atomic.LoadInt32(&m.failRegisterCount) > 0 {
		atomic.AddInt32(&m.failRegisterCount, -1)
		return nil, errors.New("registration temporarily unavailable")
	}

	if m.snapshotToReturn != nil {
		return m.snapshotToReturn, nil
	}
	return &omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "default", Name: "test-svc", MeshAddr: "10.0.0.1", Port: 8080},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{Namespace: "default", ServiceName: "test-svc"},
		},
	}, nil
}

func (m *mockCPClient) SendUpdateServices(ctx context.Context, services []model.NodeServiceInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendServicesCalls++
	m.sentServices = services
	return nil
}

func (m *mockCPClient) SendServiceUpdates(ctx context.Context, added, removed []model.NodeServiceInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendServicesCalls++
	m.sentServices = added
	return nil
}

func (m *mockCPClient) SendHealthReport(ctx context.Context, report *omnimeshv1.HealthReport) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return nil
}

func (m *mockCPClient) StreamUpdates(ctx context.Context, onUpdate func(*omnimeshv1.ScopeUpdate)) error {
	m.mu.Lock()
	m.streamUpdatesCalls++
	handler := m.snapshotHandler
	snapToSend := m.streamSnapshotToSend
	m.mu.Unlock()

	if handler != nil && snapToSend != nil {
		handler(snapToSend)
	}

	if atomic.LoadInt32(&m.failStreamCount) > 0 {
		atomic.AddInt32(&m.failStreamCount, -1)
		if m.streamErrToReturn != nil {
			return m.streamErrToReturn
		}
		return errors.New("stream connection lost")
	}

	<-ctx.Done()
	return nil
}

func (m *mockCPClient) Run(ctx context.Context, reg *model.NodeRegistration) error {
	return nil
}

func (m *mockCPClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalls++
	return nil
}

func TestControlPlaneAgent_ReconnectOnStreamFailure(t *testing.T) {
	mock := &mockCPClient{
		failStreamCount:   1, // StreamUpdates fails on first call, triggering reconnect
		streamErrToReturn: errors.New("grpc transport closing"),
		snapshotToReturn: &omnimeshv1.ScopeSnapshot{
			Services: []*omnimeshv1.ServiceInfo{
				{Namespace: "default", Name: "reconnected-svc", MeshAddr: "10.0.0.2", Port: 9090},
			},
		},
	}

	cpAgent := agent.NewControlPlaneAgentWithConfig(mock, "node-test", "target-test")
	cpAgent.SetRetryInterval(10 * time.Millisecond) // Fast retry for testing

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial Step 4 & 5
	if err := cpAgent.Connect(ctx); err != nil {
		t.Fatalf("unexpected connect error: %v", err)
	}

	initialServices := []model.NodeServiceInfo{
		{Namespace: "default", Name: "app-service", ID: "srv-1"},
	}
	_, err := cpAgent.RegisterAndGetSnapshot(ctx, "10.0.0.1:15008", initialServices)
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	// Register snapshot handler to verify reconnected snapshot is delivered
	var snapshotReceived atomic.Value
	cpAgent.SetSnapshotHandler(func(snapshot *omnimeshv1.ScopeSnapshot) {
		snapshotReceived.Store(snapshot)
	})

	// Start StreamUpdates in a goroutine
	streamDone := make(chan error, 1)
	go func() {
		streamDone <- cpAgent.StreamUpdates(ctx, nil)
	}()

	// Wait for reconnection to happen
	time.Sleep(100 * time.Millisecond)

	mock.mu.Lock()
	connectCalls := mock.connectCalls
	registerCalls := mock.registerCalls
	streamCalls := mock.streamUpdatesCalls
	sendServicesCalls := mock.sendServicesCalls
	mock.mu.Unlock()

	// Initial Connect was 1, reconnect should have called Connect again (>= 2)
	if connectCalls < 2 {
		t.Errorf("expected at least 2 connect calls, got %d", connectCalls)
	}
	// Initial Register was 1, reconnect should have called Register again (>= 2)
	if registerCalls < 2 {
		t.Errorf("expected at least 2 register calls, got %d", registerCalls)
	}
	// Initial StreamUpdates failed, reconnect started second StreamUpdates (>= 2)
	if streamCalls < 2 {
		t.Errorf("expected at least 2 StreamUpdates calls, got %d", streamCalls)
	}
	// Services were sent upon reconnect
	if sendServicesCalls < 1 {
		t.Errorf("expected deployed services to be re-sent upon reconnect, got %d", sendServicesCalls)
	}

	// Verify snapshot handler was invoked
	val := snapshotReceived.Load()
	if val == nil {
		t.Errorf("expected snapshot handler to be called upon reconnection")
	} else {
		snap := val.(*omnimeshv1.ScopeSnapshot)
		if len(snap.Services) != 1 || snap.Services[0].Name != "reconnected-svc" {
			t.Errorf("unexpected snapshot content: %+v", snap)
		}
	}

	// Cancel context to cleanly shut down the stream
	cancel()

	select {
	case err := <-streamDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("expected nil or context.Canceled, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout waiting for StreamUpdates to shut down after cancel")
	}
}

func TestControlPlaneAgent_ReconnectRetryLoop(t *testing.T) {
	mock := &mockCPClient{
		failStreamCount: 1, // Fail stream initially
	}

	cpAgent := agent.NewControlPlaneAgentWithConfig(mock, "node-test", "target-test")
	cpAgent.SetRetryInterval(10 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cpAgent.Connect(ctx); err != nil {
		t.Fatalf("unexpected connect error: %v", err)
	}
	if _, err := cpAgent.RegisterAndGetSnapshot(ctx, "10.0.0.1:15008", nil); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	// Now configure mock to fail Connect twice during reconnect
	atomic.StoreInt32(&mock.failConnectCount, 2)

	streamDone := make(chan error, 1)
	go func() {
		streamDone <- cpAgent.StreamUpdates(ctx, nil)
	}()

	// Wait enough for the 2 failed connect attempts (10ms each) + successful connect
	time.Sleep(150 * time.Millisecond)

	mock.mu.Lock()
	connectCalls := mock.connectCalls
	mock.mu.Unlock()

	// Initial (1) + 2 failed retries + 1 successful = at least 4
	if connectCalls < 4 {
		t.Errorf("expected at least 4 Connect calls across retries, got %d", connectCalls)
	}

	cancel()

	select {
	case err := <-streamDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("expected nil or context.Canceled, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout waiting for StreamUpdates to shut down after cancel")
	}
}

func TestControlPlaneAgent_ReconnectRegistrationRetryLoop(t *testing.T) {
	mock := &mockCPClient{
		failStreamCount: 1, // Stream fails initially
	}

	cpAgent := agent.NewControlPlaneAgentWithConfig(mock, "node-test", "target-test")
	cpAgent.SetRetryInterval(10 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cpAgent.Connect(ctx); err != nil {
		t.Fatalf("unexpected connect error: %v", err)
	}
	if _, err := cpAgent.RegisterAndGetSnapshot(ctx, "10.0.0.1:15008", nil); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	// Configure mock to fail RegisterAndGetSnapshot twice during reconnect
	atomic.StoreInt32(&mock.failRegisterCount, 2)

	streamDone := make(chan error, 1)
	go func() {
		streamDone <- cpAgent.StreamUpdates(ctx, nil)
	}()

	// Wait enough for 2 failed registrations + successful registration
	time.Sleep(150 * time.Millisecond)

	mock.mu.Lock()
	regCalls := mock.registerCalls
	mock.mu.Unlock()

	// Initial (1) + 2 failed retries + 1 successful = at least 4
	if regCalls < 4 {
		t.Errorf("expected at least 4 Register calls across retries, got %d", regCalls)
	}

	cancel()

	select {
	case err := <-streamDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("expected nil or context.Canceled, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout waiting for StreamUpdates to shut down after cancel")
	}
}

func TestControlPlaneAgent_CloseStopsReconnectImmediately(t *testing.T) {
	mock := &mockCPClient{
		failStreamCount: 1,
		connectErr:      errors.New("control plane completely down"),
	}

	cpAgent := agent.NewControlPlaneAgentWithConfig(mock, "node-test", "target-test")
	// Set long retry interval to verify Close unblocks without waiting for retryInterval
	cpAgent.SetRetryInterval(5 * time.Second)

	ctx := context.Background() // NOT cancelled

	streamDone := make(chan error, 1)
	go func() {
		streamDone <- cpAgent.StreamUpdates(ctx, nil)
	}()

	// Give time for StreamUpdates to fail and enter reconnect sleep
	time.Sleep(30 * time.Millisecond)

	// Close the agent
	closeStart := time.Now()
	if err := cpAgent.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	select {
	case err := <-streamDone:
		if err != nil {
			t.Errorf("expected nil error on Close, got %v", err)
		}
		if time.Since(closeStart) > 1*time.Second {
			t.Errorf("Close took too long to unblock reconnect: %v", time.Since(closeStart))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("StreamUpdates failed to terminate after agent Close()")
	}
}

func TestControlPlaneAgent_LabelsPreservedAcrossReconnect(t *testing.T) {
	mock := &mockCPClient{
		failStreamCount: 1,
	}

	cpAgent := agent.NewControlPlaneAgentWithConfig(mock, "node-labeled", "target-test")
	cpAgent.SetRetryInterval(10 * time.Millisecond)
	cpAgent.SetLabels(map[string]string{
		"region": "us-east",
		"tier":   "gateway",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cpAgent.Connect(ctx); err != nil {
		t.Fatalf("unexpected connect error: %v", err)
	}
	if _, err := cpAgent.RegisterAndGetSnapshot(ctx, "10.0.0.1:15008", nil); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	mock.mu.Lock()
	initLabels := mock.lastRegisteredNode.Labels
	mock.mu.Unlock()
	if initLabels["region"] != "us-east" || initLabels["tier"] != "gateway" {
		t.Errorf("expected initial labels to match, got: %v", initLabels)
	}

	streamDone := make(chan error, 1)
	go func() {
		streamDone <- cpAgent.StreamUpdates(ctx, nil)
	}()

	// Wait for reconnect to occur
	time.Sleep(100 * time.Millisecond)

	mock.mu.Lock()
	reconnLabels := mock.lastRegisteredNode.Labels
	mock.mu.Unlock()
	if reconnLabels["region"] != "us-east" || reconnLabels["tier"] != "gateway" {
		t.Errorf("expected labels preserved on reconnect, got: %v", reconnLabels)
	}

	cancel()
	<-streamDone
}

func TestControlPlaneAgent_StreamingSnapshotInvokesHandler(t *testing.T) {
	snap := &omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "default", Name: "streaming-snap-svc", MeshAddr: "10.5.5.5", Port: 80},
		},
	}
	mock := &mockCPClient{
		streamSnapshotToSend: snap,
	}

	cpAgent := agent.NewControlPlaneAgentWithConfig(mock, "node-test", "target-test")

	var receivedSnap atomic.Value
	cpAgent.SetSnapshotHandler(func(s *omnimeshv1.ScopeSnapshot) {
		receivedSnap.Store(s)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cpAgent.Connect(ctx); err != nil {
		t.Fatalf("unexpected connect error: %v", err)
	}

	streamDone := make(chan error, 1)
	go func() {
		streamDone <- cpAgent.StreamUpdates(ctx, nil)
	}()

	time.Sleep(50 * time.Millisecond)

	val := receivedSnap.Load()
	if val == nil {
		t.Errorf("expected snapshot handler to be called when stream delivers ScopeSnapshot")
	} else {
		s := val.(*omnimeshv1.ScopeSnapshot)
		if len(s.Services) != 1 || s.Services[0].Name != "streaming-snap-svc" {
			t.Errorf("unexpected snapshot received: %+v", s)
		}
	}

	cancel()
	<-streamDone
}

func TestResolveRegistrationAddr(t *testing.T) {
	// Explicit IP addresses and hostnames must be preserved as-is
	explicitCases := []string{
		"10.0.0.1:15008",
		"192.168.1.50:15008",
		"127.0.0.1:15008",
		"my-node.local:15008",
	}
	for _, tc := range explicitCases {
		got := agent.ResolveRegistrationAddr(tc)
		if got != tc {
			t.Errorf("ResolveRegistrationAddr(%q) = %q, want %q", tc, got, tc)
		}
	}

	// Unspecified addresses must resolve to a valid, non-unspecified IP preserving the port
	unspecifiedCases := []struct {
		input    string
		wantPort string
	}{
		{input: "0.0.0.0:15008", wantPort: "15008"},
		{input: "[::]:15008", wantPort: "15008"},
		{input: ":15008", wantPort: "15008"},
		{input: "0.0.0.0:9443", wantPort: "9443"},
	}
	for _, tc := range unspecifiedCases {
		got := agent.ResolveRegistrationAddr(tc.input)
		host, port, err := net.SplitHostPort(got)
		if err != nil {
			t.Fatalf("ResolveRegistrationAddr(%q) returned invalid host:port %q: %v", tc.input, got, err)
		}
		if port != tc.wantPort {
			t.Errorf("ResolveRegistrationAddr(%q) port = %q, want %q", tc.input, port, tc.wantPort)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			t.Errorf("ResolveRegistrationAddr(%q) host %q is not a valid IP", tc.input, host)
		} else if ip.IsUnspecified() {
			t.Errorf("ResolveRegistrationAddr(%q) resolved to unspecified IP %q", tc.input, host)
		}
	}
}

func TestControlPlaneAgent_RegisterResolvesUnspecifiedAddr(t *testing.T) {
	mock := &mockCPClient{}
	cpAgent := agent.NewControlPlaneAgentWithConfig(mock, "node-test", "target-test")

	ctx := context.Background()
	if err := cpAgent.Connect(ctx); err != nil {
		t.Fatalf("unexpected connect error: %v", err)
	}

	if _, err := cpAgent.RegisterAndGetSnapshot(ctx, "0.0.0.0:15008", nil); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	mock.mu.Lock()
	reg := mock.lastRegisteredNode
	mock.mu.Unlock()

	if reg == nil {
		t.Fatalf("expected node registration to be recorded")
	}

	host, port, err := net.SplitHostPort(reg.Addr)
	if err != nil {
		t.Fatalf("expected valid host:port in registration Addr, got %q: %v", reg.Addr, err)
	}
	if port != "15008" {
		t.Errorf("expected port 15008, got %q", port)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		t.Errorf("expected reachable non-unspecified IP in registration Addr, got %q", reg.Addr)
	}
}
