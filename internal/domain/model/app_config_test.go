package model_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func TestDefaultConfig(t *testing.T) {
	cfg := model.DefaultConfig()
	if cfg.Listeners.InternalAddr != "127.0.0.1:15001" {
		t.Fatalf("unexpected internal addr: %s", cfg.Listeners.InternalAddr)
	}
	if cfg.Listeners.ExternalAddr != "0.0.0.0:15008" {
		t.Fatalf("unexpected external addr: %s", cfg.Listeners.ExternalAddr)
	}
	if len(cfg.Interception.Subnets) == 0 {
		t.Fatalf("expected default subnets to not be empty")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
}

func TestLoadConfigFileAndEnv(t *testing.T) {
	tmpDir := t.TempDir()

	servicesFile := filepath.Join(tmpDir, "services.json")
	servicesJSON := `[
		{
			"Namespace": "default",
			"Name": "order-service",
			"ID": "order-1",
			"Labels": {"app": "order"}
		}
	]`
	if err := os.WriteFile(servicesFile, []byte(servicesJSON), 0644); err != nil {
		t.Fatalf("failed to write services file: %v", err)
	}

	configFile := filepath.Join(tmpDir, "config.json")
	configJSON := `{
		"spire": {
			"disabled": true
		},
		"listeners": {
			"internal_addr": "127.0.0.1:15001",
			"external_addr": "127.0.0.1:15008"
		},
		"control_plane": {
			"address": "http://127.0.0.1:9091",
			"node_id": "test-node",
			"target": "test-cluster"
		},
		"interception": {
			"type": "noop",
			"subnets": ["10.0.0.0/16", "172.16.0.0/12"]
		},
		"services_file": ` + `"` + filepath.ToSlash(servicesFile) + `"` + `
	}`
	if err := os.WriteFile(configFile, []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if !cfg.Spire.Disabled {
		t.Errorf("expected Spire.Disabled to be true")
	}
	if cfg.ControlPlane.NodeID != "test-node" {
		t.Errorf("expected NodeID test-node, got %s", cfg.ControlPlane.NodeID)
	}
	if len(cfg.Interception.Subnets) != 2 {
		t.Errorf("expected 2 subnets, got %d", len(cfg.Interception.Subnets))
	}
	if len(cfg.Services) != 1 || cfg.Services[0].Name != "order-service" {
		t.Errorf("expected loaded service 'order-service', got %v", cfg.Services)
	}

	// Test environment variable override
	t.Setenv("NODE_ID", "env-override-node")
	t.Setenv("INTERCEPTION_SUBNETS", "192.168.1.0/24")

	cfgWithEnv, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load config with env: %v", err)
	}
	if cfgWithEnv.ControlPlane.NodeID != "env-override-node" {
		t.Errorf("expected NodeID env-override-node, got %s", cfgWithEnv.ControlPlane.NodeID)
	}
	if len(cfgWithEnv.Interception.Subnets) != 1 || cfgWithEnv.Interception.Subnets[0] != "192.168.1.0/24" {
		t.Errorf("expected overridden subnets, got %v", cfgWithEnv.Interception.Subnets)
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := model.DefaultConfig()

	// Invalid internal address
	cfg.Listeners.InternalAddr = "not-a-port"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected validation error for invalid internal_addr")
	}

	// Invalid CIDR
	cfg = model.DefaultConfig()
	cfg.Interception.Subnets = []string{"999.999.999.999/99"}
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected validation error for invalid CIDR")
	}
}
