package model_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func TestServicesIO(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Single service file
	singleFile := filepath.Join(tmpDir, "svc-single.json")
	singleJSON := `{
		"namespace": "production",
		"name": "auth-service",
		"id": "auth-1",
		"labels": {"tier": "auth"},
		"health_check": {
			"type": "HTTP",
			"address": "127.0.0.1:8080",
			"path": "/healthz",
			"interval": "3s",
			"timeout": "1s"
		}
	}`
	if err := os.WriteFile(singleFile, []byte(singleJSON), 0644); err != nil {
		t.Fatalf("failed to write single service file: %v", err)
	}

	singleSvcs, err := model.ReadServicesFromFile(singleFile)
	if err != nil {
		t.Fatalf("failed to read single service file: %v", err)
	}
	if len(singleSvcs) != 1 {
		t.Fatalf("expected 1 service, got %d", len(singleSvcs))
	}
	if singleSvcs[0].Name != "auth-service" || singleSvcs[0].HealthCheck == nil || singleSvcs[0].HealthCheck.GetProbeType() != "HTTP" {
		t.Fatalf("unexpected parsed service: %+v", singleSvcs[0])
	}

	// 2. Array service file
	arrayFile := filepath.Join(tmpDir, "svc-array.json")
	arrayJSON := `[
		{
			"namespace": "production",
			"name": "cart-service",
			"id": "cart-1"
		},
		{
			"namespace": "production",
			"name": "payment-service",
			"id": "pay-1"
		}
	]`
	if err := os.WriteFile(arrayFile, []byte(arrayJSON), 0644); err != nil {
		t.Fatalf("failed to write array service file: %v", err)
	}

	// 3. Non-JSON / temporary files that should be ignored
	if err := os.WriteFile(filepath.Join(tmpDir, "ignore.txt"), []byte("text"), 0644); err != nil {
		t.Fatalf("failed to write text file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, ".hidden.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write hidden file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "temp.json~"), []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	// 4. Read directory
	dirSvcs, err := model.ReadServicesFromDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read services from dir: %v", err)
	}
	if len(dirSvcs) != 3 {
		t.Fatalf("expected 3 services read from dir, got %d", len(dirSvcs))
	}

	// 5. Test MergeServices
	merged := model.MergeServices([]model.NodeServiceInfo{
		{Namespace: "production", Name: "cart-service", ID: "cart-1", Labels: map[string]string{"v": "1"}},
		{Namespace: "default", Name: "legacy", ID: "leg-1"},
	}, dirSvcs)

	if len(merged) != 4 {
		t.Fatalf("expected 4 merged services, got %d", len(merged))
	}
}

func TestHealthCheckConfig(t *testing.T) {
	cfg := &model.HealthCheckConfig{
		Type:               "http",
		Address:            "127.0.0.1",
		Port:               9090,
		Path:               "status",
		Interval:           "10s",
		Timeout:            "3s",
		HealthyThreshold:   3,
		UnhealthyThreshold: 4,
	}

	if cfg.GetProbeType() != "HTTP" {
		t.Errorf("expected probe type HTTP, got %s", cfg.GetProbeType())
	}
	if cfg.GetInterval() != 10*1e9 {
		t.Errorf("expected interval 10s, got %v", cfg.GetInterval())
	}
	if cfg.GetTimeout() != 3*1e9 {
		t.Errorf("expected timeout 3s, got %v", cfg.GetTimeout())
	}
	if cfg.GetHealthyThreshold() != 3 {
		t.Errorf("expected healthy threshold 3, got %d", cfg.GetHealthyThreshold())
	}
	if cfg.GetUnhealthyThreshold() != 4 {
		t.Errorf("expected unhealthy threshold 4, got %d", cfg.GetUnhealthyThreshold())
	}
	if cfg.GetTargetAddress() != "127.0.0.1:9090" {
		t.Errorf("expected target address 127.0.0.1:9090, got %s", cfg.GetTargetAddress())
	}

	// Equal test
	cfg2 := &model.HealthCheckConfig{
		Type:               "HTTP",
		Address:            "127.0.0.1",
		Port:               9090,
		Path:               "status",
		Interval:           "10s",
		Timeout:            "3s",
		HealthyThreshold:   3,
		UnhealthyThreshold: 4,
	}
	if !cfg.Equal(cfg2) {
		t.Errorf("expected cfg and cfg2 to be equal")
	}
}

