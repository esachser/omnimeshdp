package service

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// HealthStatusCallback is invoked when an endpoint's health status changes.
type HealthStatusCallback func(svc model.NodeServiceInfo, report *omnimeshv1.HealthReport)

// HealthChecker monitors health for configured services.
type HealthChecker struct {
	mu        sync.Mutex
	probers   map[string]*serviceProber
	onStatus  HealthStatusCallback
	closed    bool
	tcpDialer *net.Dialer
	client    *http.Client
}

type serviceProber struct {
	svc                 model.NodeServiceInfo
	cancel              context.CancelFunc
	currentStatus       omnimeshv1.EndpointHealthStatus
	consecutiveSuccess  int
	consecutiveFailure  int
	lastReportedStatus  omnimeshv1.EndpointHealthStatus
	done                chan struct{}
}

// NewHealthChecker constructs a new HealthChecker.
func NewHealthChecker(onStatus HealthStatusCallback) *HealthChecker {
	return &HealthChecker{
		probers:  make(map[string]*serviceProber),
		onStatus: onStatus,
		tcpDialer: &net.Dialer{
			Timeout: 2 * time.Second,
		},
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// StartService starts or updates a health check worker for the given service.
// If the service has no HealthCheck configuration, any existing prober is stopped.
func (h *HealthChecker) StartService(svc model.NodeServiceInfo) {
	if svc.HealthCheck == nil {
		h.StopService(svc.Key())
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}

	key := svc.Key()
	if old, ok := h.probers[key]; ok {
		if old.svc.Equal(svc) {
			return // unchanged
		}
		old.cancel()
		delete(h.probers, key)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &serviceProber{
		svc:           svc,
		cancel:        cancel,
		currentStatus: omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNSPECIFIED,
		done:          make(chan struct{}),
	}
	h.probers[key] = p
	go h.runProber(ctx, p)
}

// StopService stops and removes the prober for the specified service key.
func (h *HealthChecker) StopService(key string) {
	h.mu.Lock()
	p, ok := h.probers[key]
	if ok {
		p.cancel()
		delete(h.probers, key)
	}
	h.mu.Unlock()

	if ok && p != nil {
		<-p.done
	}
}

// GetStatus returns the current health status of a service.
func (h *HealthChecker) GetStatus(key string) omnimeshv1.EndpointHealthStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p, ok := h.probers[key]; ok {
		return p.currentStatus
	}
	return omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNSPECIFIED
}

// GetAllReports returns the most recent health reports for all tracked services.
func (h *HealthChecker) GetAllReports() []*omnimeshv1.HealthReport {
	h.mu.Lock()
	defer h.mu.Unlock()

	reports := make([]*omnimeshv1.HealthReport, 0, len(h.probers))
	for _, p := range h.probers {
		if p.lastReportedStatus != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNSPECIFIED {
			routeName := p.svc.ID
			if routeName == "" {
				routeName = p.svc.Name
			}
			reports = append(reports, &omnimeshv1.HealthReport{
				Namespace:   p.svc.Namespace,
				ServiceName: p.svc.Name,
				RouteName:   routeName,
				Status:      p.lastReportedStatus,
				ProbeType:   p.svc.HealthCheck.GetProbeType(),
			})
		}
	}
	return reports
}

func (h *HealthChecker) runProber(ctx context.Context, p *serviceProber) {
	defer close(p.done)

	cfg := p.svc.HealthCheck
	interval := cfg.GetInterval()
	timeout := cfg.GetTimeout()
	healthyThresh := cfg.GetHealthyThreshold()
	unhealthyThresh := cfg.GetUnhealthyThreshold()
	probeType := cfg.GetProbeType()
	targetAddr := cfg.GetTargetAddress()
	if strings.TrimSpace(cfg.Address) == "" && cfg.Port == 0 && p.svc.Address() != "" {
		targetAddr = p.svc.Address()
	}

	executeProbe := func() {
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		var err error
		switch probeType {
		case "HTTP":
			err = h.probeHTTP(probeCtx, cfg, targetAddr)
		case "gRPC":
			err = h.probeGRPC(probeCtx, targetAddr)
		default: // TCP
			err = h.probeTCP(probeCtx, targetAddr)
		}

		h.mu.Lock()
		if ctx.Err() != nil {
			h.mu.Unlock()
			return
		}

		var changed bool
		var newStatus omnimeshv1.EndpointHealthStatus

		if err == nil {
			p.consecutiveFailure = 0
			p.consecutiveSuccess++
			if p.consecutiveSuccess >= healthyThresh && p.currentStatus != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_HEALTHY {
				p.currentStatus = omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_HEALTHY
				changed = true
				newStatus = p.currentStatus
			}
		} else {
			p.consecutiveSuccess = 0
			p.consecutiveFailure++
			if p.consecutiveFailure >= unhealthyThresh && p.currentStatus != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNHEALTHY {
				p.currentStatus = omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNHEALTHY
				changed = true
				newStatus = p.currentStatus
			}
		}

		var cb HealthStatusCallback
		var report *omnimeshv1.HealthReport
		if changed {
			p.lastReportedStatus = newStatus
			cb = h.onStatus
			routeName := p.svc.ID
			if routeName == "" {
				routeName = p.svc.Name
			}
			report = &omnimeshv1.HealthReport{
				Namespace:   p.svc.Namespace,
				ServiceName: p.svc.Name,
				RouteName:   routeName,
				Status:      newStatus,
				ProbeType:   probeType,
			}
		}
		h.mu.Unlock()

		if changed && cb != nil && report != nil {
			cb(p.svc, report)
		}
	}

	// Initial probe immediately upon startup
	executeProbe()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			executeProbe()
		}
	}
}

func (h *HealthChecker) probeTCP(ctx context.Context, targetAddr string) error {
	conn, err := h.tcpDialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func (h *HealthChecker) probeHTTP(ctx context.Context, cfg *model.HealthCheckConfig, targetAddr string) error {
	path := cfg.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	url := targetAddr
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url + path
	} else if !strings.HasSuffix(url, path) {
		url = strings.TrimRight(url, "/") + path
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return nil
	}
	return fmt.Errorf("HTTP probe returned status %d", resp.StatusCode)
}

func (h *HealthChecker) probeGRPC(ctx context.Context, targetAddr string) error {
	conn, err := grpc.NewClient(targetAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)
	resp, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		// If health service is not implemented, the connection itself succeeded
		if status.Code(err) == codes.Unimplemented {
			return nil
		}
		return err
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		return fmt.Errorf("gRPC health serving status: %v", resp.Status)
	}
	return nil
}

// Close stops all active health probers.
func (h *HealthChecker) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true

	probers := make([]*serviceProber, 0, len(h.probers))
	for _, p := range h.probers {
		probers = append(probers, p)
		p.cancel()
	}
	h.probers = make(map[string]*serviceProber)
	h.mu.Unlock()

	for _, p := range probers {
		<-p.done
	}
	log.Println("[HealthChecker] All health probers stopped.")
}

