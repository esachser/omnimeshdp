package service_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/oteltelemetry"
	"github.com/esachser/omnimeshdp/internal/application/service"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestHealthCheckerTCP(t *testing.T) {
	// Start a local TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var reportedStatus omnimeshv1.EndpointHealthStatus

	checker := service.NewHealthChecker(func(svc model.NodeServiceInfo, report *omnimeshv1.HealthReport) {
		reportedStatus = report.Status
		wg.Done()
	})
	defer checker.Close()

	svc := model.NodeServiceInfo{
		Namespace: "default",
		Name:      "tcp-service",
		ID:        "tcp-1",
		HealthCheck: &model.HealthCheckConfig{
			Type:               "TCP",
			Address:            ln.Addr().String(),
			Interval:           "100ms",
			Timeout:            "50ms",
			HealthyThreshold:   1,
			UnhealthyThreshold: 1,
		},
	}

	checker.StartService(svc)

	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if reportedStatus != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_HEALTHY {
			t.Errorf("expected HEALTHY status, got %v", reportedStatus)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for TCP health report")
	}

	if status := checker.GetStatus(svc.Key()); status != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_HEALTHY {
		t.Errorf("expected GetStatus to return HEALTHY, got %v", status)
	}
}

func TestHealthCheckerHTTPTransitions(t *testing.T) {
	var isHealthy int32 = 1 // 1 for 200, 0 for 500

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&isHealthy) == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, "OK")
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintln(w, "Error")
		}
	}))
	defer ts.Close()

	statusCh := make(chan omnimeshv1.EndpointHealthStatus, 10)

	checker := service.NewHealthChecker(func(svc model.NodeServiceInfo, report *omnimeshv1.HealthReport) {
		statusCh <- report.Status
	})
	defer checker.Close()

	svc := model.NodeServiceInfo{
		Namespace: "default",
		Name:      "web-service",
		ID:        "web-1",
		HealthCheck: &model.HealthCheckConfig{
			Type:               "HTTP",
			Address:            ts.URL,
			Path:               "/healthz",
			Interval:           "50ms",
			Timeout:            "50ms",
			HealthyThreshold:   1,
			UnhealthyThreshold: 1,
		},
	}

	checker.StartService(svc)

	// 1. Should transition to HEALTHY
	select {
	case status := <-statusCh:
		if status != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_HEALTHY {
			t.Fatalf("expected HEALTHY, got %v", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for initial HEALTHY status")
	}

	// 2. Change server to unhealthy
	atomic.StoreInt32(&isHealthy, 0)

	select {
	case status := <-statusCh:
		if status != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNHEALTHY {
			t.Fatalf("expected UNHEALTHY, got %v", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for UNHEALTHY status")
	}

	// 3. Change server back to healthy
	atomic.StoreInt32(&isHealthy, 1)

	select {
	case status := <-statusCh:
		if status != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_HEALTHY {
			t.Fatalf("expected HEALTHY again, got %v", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for recovered HEALTHY status")
	}

	reports := checker.GetAllReports()
	if len(reports) != 1 {
		t.Errorf("expected 1 report from GetAllReports, got %d", len(reports))
	}
}

func TestHealthCheckerObservabilityMetrics(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if healthy.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	reader := sdkmetric.NewManualReader()
	tp, err := oteltelemetry.NewProvider(context.Background(), model.DefaultObservabilityConfig(), "node-health", oteltelemetry.WithMetricReader(reader))
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer func() { _ = tp.Shutdown(context.Background()) }()

	statusCh := make(chan omnimeshv1.EndpointHealthStatus, 4)
	checker := service.NewHealthChecker(func(_ model.NodeServiceInfo, report *omnimeshv1.HealthReport) {
		statusCh <- report.Status
	})
	checker.SetMetrics(tp.Metrics())
	defer checker.Close()

	checker.StartService(model.NodeServiceInfo{
		Namespace: "prod",
		Name:      "orders",
		ID:        "orders-1",
		HealthCheck: &model.HealthCheckConfig{
			Type:               "HTTP",
			Address:            ts.URL,
			Path:               "/healthz",
			Interval:           "40ms",
			Timeout:            "50ms",
			HealthyThreshold:   1,
			UnhealthyThreshold: 1,
		},
	})

	select {
	case st := <-statusCh:
		if st != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_HEALTHY {
			t.Fatalf("expected HEALTHY, got %v", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for HEALTHY transition")
	}

	healthy.Store(false)
	select {
	case st := <-statusCh:
		if st != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNHEALTHY {
			t.Fatalf("expected UNHEALTHY, got %v", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for UNHEALTHY transition")
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	found := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			found[m.Name] = true
		}
	}
	for _, expected := range []string{
		outbound.MetricHealthProbesTotal,
		outbound.MetricHealthProbesDurationMs,
		outbound.MetricHealthTransitions,
	} {
		if !found[expected] {
			t.Fatalf("expected metric %q, got %+v", expected, found)
		}
	}
}

