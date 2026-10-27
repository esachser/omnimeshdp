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
	if cfg.Interception.Type != "wfp" {
		t.Fatalf("expected default interception type 'wfp', got %q", cfg.Interception.Type)
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
			"type": "noop"
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
	if cfg.Interception.Type != "noop" {
		t.Errorf("expected interception type 'noop', got %s", cfg.Interception.Type)
	}
	if len(cfg.Services) != 1 || cfg.Services[0].Name != "order-service" {
		t.Errorf("expected loaded service 'order-service', got %v", cfg.Services)
	}

	// Test environment variable override
	t.Setenv("NODE_ID", "env-override-node")
	t.Setenv("INTERCEPTION_TYPE", "windivert")

	cfgWithEnv, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load config with env: %v", err)
	}
	if cfgWithEnv.ControlPlane.NodeID != "env-override-node" {
		t.Errorf("expected NodeID env-override-node, got %s", cfgWithEnv.ControlPlane.NodeID)
	}
	if cfgWithEnv.Interception.Type != "windivert" {
		t.Errorf("expected overridden interception type 'windivert', got %s", cfgWithEnv.Interception.Type)
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := model.DefaultConfig()

	// Invalid internal address
	cfg.Listeners.InternalAddr = "not-a-port"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected validation error for invalid internal_addr")
	}

	// Invalid external address
	cfg = model.DefaultConfig()
	cfg.Listeners.ExternalAddr = "not-a-port"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected validation error for invalid external_addr")
	}
}

func TestConfigDirFiles(t *testing.T) {
	configFiles := []string{
		"../../../config/config.test.json",
		"../../../config/config.windows.json",
		"../../../config/config.linux.json",
	}

	for _, relPath := range configFiles {
		absPath, err := filepath.Abs(relPath)
		if err != nil {
			t.Fatalf("failed to resolve path %s: %v", relPath, err)
		}
		cfg, err := model.LoadConfig(absPath)
		if err != nil {
			t.Fatalf("expected %s to load without error, got: %v", filepath.Base(relPath), err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected %s to be valid, got: %v", filepath.Base(relPath), err)
		}
	}
}
