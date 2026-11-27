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
	if cfg.Routing.DefaultMaxRetries != model.DefaultMaxRetries {
		t.Fatalf("expected default max retries %d, got %d", model.DefaultMaxRetries, cfg.Routing.DefaultMaxRetries)
	}
	if cfg.Routing.DefaultBackoffBase != "0ms" {
		t.Fatalf("expected default backoff base '0ms', got %q", cfg.Routing.DefaultBackoffBase)
	}
	if cfg.Routing.DefaultBackoffMax != "500ms" {
		t.Fatalf("expected default backoff max '500ms', got %q", cfg.Routing.DefaultBackoffMax)
	}
	if cfg.Routing.ConnectTimeout != "5s" {
		t.Fatalf("expected default connect timeout '5s', got %q", cfg.Routing.ConnectTimeout)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
	if cfg.Authorization.Mode != "strict" || cfg.Authorization.NamespaceDefaultIsolation != "strict" || !cfg.Authorization.EnforceL7 {
		t.Fatalf("unexpected default authorization config: %+v", cfg.Authorization)
	}
	if !cfg.HTTP.Enabled || !cfg.HTTP.Outbound.Enabled || !cfg.HTTP.Inbound.Enabled {
		t.Fatalf("expected HTTP L7 outbound and inbound to be enabled by default")
	}
	if cfg.HTTP.SniffTimeout != "100ms" || cfg.HTTP.MaxSniffBytes != 4096 || cfg.HTTP.MaxHeaderBytes != 65536 {
		t.Fatalf("unexpected default HTTP proxy limits: %+v", cfg.HTTP)
	}
	if cfg.HTTP.Tracing.TraceparentMode != "preserve" || cfg.HTTP.Tracing.RequestIDHeader != "x-request-id" {
		t.Fatalf("unexpected default HTTP tracing config: %+v", cfg.HTTP.Tracing)
	}
	if cfg.HTTP.MeshHeaders.StripPrefixOnInbound != "x-omnimesh-" {
		t.Fatalf("unexpected default inbound strip prefix: %q", cfg.HTTP.MeshHeaders.StripPrefixOnInbound)
	}
}

func TestHTTPConfigFileEnvAndValidation(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")
	configJSON := `{
		"spire": {"disabled": true},
		"http": {
			"enabled": true,
			"outbound": {"enabled": true},
			"inbound": {"enabled": false},
			"sniff_timeout": "200ms",
			"max_sniff_bytes": 2048,
			"max_header_bytes": 32768,
			"idle_timeout": "30s",
			"fail_open": true,
			"tracing": {
				"traceparent_mode": "new_span",
				"echo_response_headers": true
			},
			"mesh_headers": {
				"allow_unverified_identity": false
			},
			"rules": [
				{
					"name": "add-env",
					"phase": "request",
					"direction": "outbound",
					"action": "set",
					"header": "x-env",
					"value": "staging"
				}
			]
		}
	}`
	if err := os.WriteFile(configFile, []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load HTTP config: %v", err)
	}
	if cfg.HTTP.Inbound.Enabled || !cfg.HTTP.FailOpen || cfg.HTTP.MaxSniffBytes != 2048 {
		t.Fatalf("unexpected HTTP config parsed from JSON: %+v", cfg.HTTP)
	}
	if cfg.HTTP.Tracing.TraceparentMode != "new_span" || !cfg.HTTP.Tracing.EchoResponseHeaders {
		t.Fatalf("unexpected HTTP tracing config: %+v", cfg.HTTP.Tracing)
	}
	if cfg.HTTP.MeshHeaders.ShouldAllowUnverifiedIdentity(cfg.Spire.Disabled) {
		t.Fatalf("explicit allow_unverified_identity=false should override spire.disabled=true")
	}

	t.Setenv("HTTP_INBOUND_ENABLED", "true")
	t.Setenv("HTTP_SNIFF_TIMEOUT", "150ms")
	t.Setenv("HTTP_TRACING_MODE", "preserve")
	t.Setenv("HTTP_TRACING_ECHO_RESPONSE", "false")
	t.Setenv("HTTP_MESH_HEADERS_ENABLED", "false")

	cfgEnv, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load HTTP config with env overrides: %v", err)
	}
	if !cfgEnv.HTTP.Inbound.Enabled || cfgEnv.HTTP.SniffTimeout != "150ms" ||
		cfgEnv.HTTP.Tracing.TraceparentMode != "preserve" || cfgEnv.HTTP.Tracing.EchoResponseHeaders ||
		cfgEnv.HTTP.MeshHeaders.Enabled {
		t.Fatalf("unexpected HTTP config after env overrides: %+v", cfgEnv.HTTP)
	}

	// Protocol normalization and validation failures
	cases := []struct {
		raw  string
		want model.HTTPProtocol
	}{
		{"", model.ProtocolAuto},
		{"auto", model.ProtocolAuto},
		{"TCP", model.ProtocolTCP},
		{"http", model.ProtocolHTTP},
		{"http/1.1", model.ProtocolHTTP1},
		{"HTTP2", model.ProtocolHTTP2},
		{"h2c", model.ProtocolHTTP2},
		{"grpc", model.ProtocolHTTP2},
	}
	for _, tc := range cases {
		if got := model.NormalizeProtocol(tc.raw); got != tc.want {
			t.Errorf("NormalizeProtocol(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	bad := model.DefaultConfig()
	bad.HTTP.SniffTimeout = "0s"
	if err := bad.Validate(); err == nil {
		t.Errorf("expected validation error for 0s sniff_timeout")
	}

	bad = model.DefaultConfig()
	bad.HTTP.SniffTimeout = "10s"
	if err := bad.Validate(); err == nil {
		t.Errorf("expected validation error for >5s sniff_timeout")
	}

	bad = model.DefaultConfig()
	bad.HTTP.Tracing.TraceparentMode = "invalid"
	if err := bad.Validate(); err == nil {
		t.Errorf("expected validation error for invalid traceparent_mode")
	}

	bad = model.DefaultConfig()
	bad.HTTP.Rules = []model.HeaderRule{{Name: "bad", Phase: "request", Action: "set", Header: "Content-Length", Value: "10"}}
	if err := bad.Validate(); err == nil {
		t.Errorf("expected validation error for forbidden header Content-Length")
	}

	bad = model.DefaultConfig()
	bad.HTTP.Rules = []model.HeaderRule{{Name: "crlf", Phase: "request", Action: "set", Header: "x-test", Value: "a\r\nb"}}
	if err := bad.Validate(); err == nil {
		t.Errorf("expected validation error for CR/LF in rule value")
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

	// Invalid routing max retries
	cfg = model.DefaultConfig()
	cfg.Routing.DefaultMaxRetries = -1
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected validation error for negative default_max_retries")
	}

	// Invalid routing backoff base
	cfg = model.DefaultConfig()
	cfg.Routing.DefaultBackoffBase = "-5ms"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected validation error for negative default_backoff_base")
	}

	// Backoff max < backoff base
	cfg = model.DefaultConfig()
	cfg.Routing.DefaultBackoffBase = "200ms"
	cfg.Routing.DefaultBackoffMax = "100ms"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected validation error when default_backoff_max < default_backoff_base")
	}

	// Connect timeout <= 0
	cfg = model.DefaultConfig()
	cfg.Routing.ConnectTimeout = "0s"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected validation error for zero connect_timeout")
	}
}

func TestRoutingConfigFileAndEnvOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")
	configJSON := `{
		"spire": {"disabled": true},
		"routing": {
			"default_max_retries": 5,
			"default_backoff_base": "25ms",
			"default_backoff_max": "250ms",
			"connect_timeout": "2s",
			"retry_on_connect_failure": true
		}
	}`
	if err := os.WriteFile(configFile, []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	if cfg.Routing.DefaultMaxRetries != 5 || cfg.Routing.DefaultBackoffBase != "25ms" ||
		cfg.Routing.DefaultBackoffMax != "250ms" || cfg.Routing.ConnectTimeout != "2s" ||
		!cfg.Routing.RetryOnConnectFailure {
		t.Fatalf("unexpected routing config from file: %+v", cfg.Routing)
	}

	t.Setenv("ROUTING_DEFAULT_MAX_RETRIES", "2")
	t.Setenv("ROUTING_DEFAULT_BACKOFF_BASE", "10ms")
	t.Setenv("ROUTING_DEFAULT_BACKOFF_MAX", "100ms")
	t.Setenv("ROUTING_CONNECT_TIMEOUT", "3s")
	t.Setenv("ROUTING_RETRY_ON_CONNECT_FAILURE", "false")

	cfgEnv, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load config with routing env overrides: %v", err)
	}
	if cfgEnv.Routing.DefaultMaxRetries != 2 || cfgEnv.Routing.DefaultBackoffBase != "10ms" ||
		cfgEnv.Routing.DefaultBackoffMax != "100ms" || cfgEnv.Routing.ConnectTimeout != "3s" ||
		cfgEnv.Routing.RetryOnConnectFailure {
		t.Fatalf("unexpected routing config after env overrides: %+v", cfgEnv.Routing)
	}

	t.Setenv("ROUTING_DEFAULT_MAX_RETRIES", "not-an-int")
	if _, err := model.LoadConfig(configFile); err == nil {
		t.Fatalf("expected error for invalid ROUTING_DEFAULT_MAX_RETRIES")
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

func TestAuthorizationConfigFileAndEnvOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")
	configJSON := `{
		"spire": {"disabled": true},
		"authorization": {
			"mode": "dry_run",
			"namespace_default_isolation": "open",
			"allow_unverified_identity": false,
			"enforce_l7": true,
			"trust_domain": "omnimesh.local",
			"audit_log_allows": true,
			"local_policies": [
				{
					"name": "local-allow",
					"namespace": "prod",
					"action": "allow",
					"source": {"namespace": "prod", "name": "web"},
					"destination": {"namespace": "prod", "name": "api"},
					"ports": [8080]
				}
			]
		}
	}`
	if err := os.WriteFile(configFile, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg.Authorization.Mode != "dry_run" || cfg.Authorization.NamespaceDefaultIsolation != "open" ||
		cfg.Authorization.ShouldAllowUnverifiedIdentity(cfg.Spire.Disabled) ||
		!cfg.Authorization.AuditLogAllows || len(cfg.Authorization.LocalPolicies) != 1 {
		t.Fatalf("unexpected Authorization config parsed from file: %+v", cfg.Authorization)
	}

	t.Setenv("AUTHZ_MODE", "permissive")
	t.Setenv("AUTHZ_NAMESPACE_DEFAULT_ISOLATION", "strict")
	t.Setenv("AUTHZ_ALLOW_UNVERIFIED_IDENTITY", "true")
	t.Setenv("AUTHZ_ENFORCE_L7", "false")
	t.Setenv("AUTHZ_TRUST_DOMAIN", "corp.mesh")
	t.Setenv("AUTHZ_AUDIT_LOG_ALLOWS", "false")

	cfgEnv, err := model.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig with env overrides error: %v", err)
	}
	if cfgEnv.Authorization.Mode != "permissive" ||
		cfgEnv.Authorization.NamespaceDefaultIsolation != "strict" ||
		!cfgEnv.Authorization.ShouldAllowUnverifiedIdentity(false) ||
		cfgEnv.Authorization.EnforceL7 ||
		cfgEnv.Authorization.TrustDomain != "corp.mesh" ||
		cfgEnv.Authorization.AuditLogAllows {
		t.Fatalf("unexpected Authorization config after env overrides: %+v", cfgEnv.Authorization)
	}

	t.Setenv("AUTHZ_MODE", "invalid-mode")
	if _, err := model.LoadConfig(configFile); err == nil {
		t.Fatalf("expected validation error for invalid AUTHZ_MODE")
	}
}
